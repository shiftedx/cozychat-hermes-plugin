"""The shared state: one directory per computer, and two processes that both reach it.

Every test here uses TWO handles on the same directory with their own SQLite connections, which is
what two Hermes processes are. The old suites all ran one object and could not have caught the fault
this slice exists to fix.
"""

import json
import os
import sqlite3
import stat
import threading
import time

import pytest

from cozychat import activities as live
from cozychat import state as shared
from cozychat.approvals import ANSWERED, SETTLED, UNKNOWN, ApprovalDesk
from cozychat.devices import DeviceStore
from cozychat.feed import LiveFeed


class Request:
    """The host's transport request, as much of it as the desk reads."""

    def __init__(self, request_id="req-1", timeout=30.0, choices=("once", "deny")):
        self.request_id = request_id
        self.timeout_seconds = timeout
        self.allowed_choices = list(choices)
        self.pattern_key = "delete in root path"
        self.description = "rm -rf /"
        self.surface = "cli"


# -- where it lives -------------------------------------------------------


def test_the_root_is_the_hermes_home_with_the_profile_stripped(tmp_path):
    # This is the whole reason the directory is not per plugin: `hermes serve` runs `-p default`
    # while the hooks run in a named profile's gateway, so a per-profile path is two paths.
    root = tmp_path / "hermes"
    assert shared.state_root(root / "profiles" / "cozychatlive") == root / "cozychat"
    assert shared.state_root(root) == root / "cozychat"


def test_a_second_hermes_home_is_a_second_directory(tmp_path):
    assert shared.state_root(tmp_path / "a") != shared.state_root(tmp_path / "b")


def test_the_environment_answers_when_hermes_itself_cannot_be_imported(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "root" / "profiles" / "studio"))
    assert shared.state_root() == tmp_path / "root" / "cozychat"


# -- the feed across processes --------------------------------------------


def test_frames_written_through_one_handle_are_read_through_another(tmp_path):
    gateway = LiveFeed(shared.SharedState(tmp_path / "cozychat"))
    serve = LiveFeed(shared.SharedState(tmp_path / "cozychat"))

    published = gateway.publish("message.delta", source="room", room_id="R1",
                                payload={"text": "hello"})
    frames = serve.since(0)
    assert [frame["seq"] for frame in frames] == [published["seq"]]
    assert frames[0]["payload"]["text"] == "hello" and frames[0]["room_id"] == "R1"
    assert serve.since(published["seq"]) == []


def test_the_seq_keeps_rising_for_a_reader_that_reconnects(tmp_path):
    gateway = LiveFeed(shared.SharedState(tmp_path / "cozychat"))
    serve = LiveFeed(shared.SharedState(tmp_path / "cozychat"))
    gateway.publish("stream.started", source="run")
    cursor = serve.since(0)[-1]["seq"]
    gateway.publish("stream.ended", source="run")
    assert [frame["kind"] for frame in serve.since(cursor)] == ["stream.ended"]


# -- the approval desk across processes -----------------------------------


def test_the_route_answers_an_approval_the_other_process_is_waiting_on(tmp_path):
    gateway = ApprovalDesk(shared.SharedState(tmp_path / "cozychat"))
    serve = ApprovalDesk(shared.SharedState(tmp_path / "cozychat"))
    gateway.open(Request())

    # What `GET /approvals` answered 2026-09-15: an empty list while a turn was genuinely blocked.
    assert [row["request_id"] for row in serve.listing()] == ["req-1"]

    answer = []
    waiter = threading.Thread(target=lambda: answer.append(gateway.wait("req-1", 10.0)))
    waiter.start()
    deadline = time.monotonic() + 5.0
    while serve.answer("req-1", "once") == UNKNOWN and time.monotonic() < deadline:
        time.sleep(0.01)
    waiter.join(timeout=5.0)
    assert answer == ["once"]
    # And the row is gone, so the same tap cannot authorize a second command.
    assert serve.answer("req-1", "once") == UNKNOWN


def test_a_decision_after_the_waiter_gave_up_reaches_nobody(tmp_path):
    gateway = ApprovalDesk(shared.SharedState(tmp_path / "cozychat"))
    serve = ApprovalDesk(shared.SharedState(tmp_path / "cozychat"))
    gateway.open(Request(timeout=0.0))
    assert gateway.wait("req-1", 0.0) is None
    assert serve.answer("req-1", "once") == UNKNOWN


def test_an_expired_request_the_waiter_never_reached_is_settled_not_answered(tmp_path):
    serve = ApprovalDesk(shared.SharedState(tmp_path / "cozychat"))
    ApprovalDesk(shared.SharedState(tmp_path / "cozychat")).open(
        Request(timeout=0.0), now=time.time() - 60)
    assert serve.answer("req-1", "once") == SETTLED


def test_the_listing_hides_what_has_already_been_answered(tmp_path):
    gateway = ApprovalDesk(shared.SharedState(tmp_path / "cozychat"))
    serve = ApprovalDesk(shared.SharedState(tmp_path / "cozychat"))
    gateway.open(Request())
    assert serve.answer("req-1", "once") == ANSWERED
    assert serve.listing() == []


# -- the cards across processes -------------------------------------------


class FakeRelay:
    def __init__(self):
        self.forgotten = []

    def register_live_activity(self, token, environment, device_id, profile):
        return "push-" + token[:2]

    def forget(self, push_id):
        self.forgotten.append(push_id)


class FakeOutbox:
    def __init__(self):
        self.queued = []

    def enqueue_live_activity(self, activity_id, push_id, body, *, device_id="", profile="",
                              consent_version=0, terminal=False, now=None):
        self.queued.append((activity_id, push_id, terminal))


def test_a_card_registered_by_the_route_is_driven_by_the_hooks(tmp_path):
    allows = lambda device_id, profile: device_id == "phone-1" and profile == "default"
    route = live.LiveActivities(shared.SharedState(tmp_path / "cozychat"))
    route.configure(outbox=FakeOutbox(), relay=FakeRelay(), allows_device=allows)
    assert route.register("A1", "aa" * 16, "development", "session-1", "phone-1", "default", 1)

    # A different process's registry, which never saw the POST. Before this slice it pushed nothing.
    hooks = live.LiveActivities(shared.SharedState(tmp_path / "cozychat"))
    outbox = FakeOutbox()
    hooks.configure(outbox=outbox, relay=FakeRelay())
    assert hooks.update("session-1", "thinking", "Thinking") == 1
    assert outbox.queued == [("A1", "push-aa", False)]
    assert hooks.finish("session-1", True) == 1
    assert outbox.queued[-1] == ("A1", "push-aa", True)


def test_forgetting_a_card_in_one_process_stops_the_other_pushing_to_it(tmp_path):
    allows = lambda device_id, profile: device_id == "phone-1" and profile == "default"
    route = live.LiveActivities(shared.SharedState(tmp_path / "cozychat"))
    route.configure(outbox=FakeOutbox(), relay=FakeRelay(), allows_device=allows)
    route.register("A1", "aa" * 16, "development", "session-1", "phone-1", "default", 1)

    hooks = live.LiveActivities(shared.SharedState(tmp_path / "cozychat"))
    outbox = FakeOutbox()
    hooks.configure(outbox=outbox, relay=FakeRelay())
    assert route.forget("A1") is True
    assert hooks.update("session-1", "thinking", "Thinking") == 0
    assert outbox.queued == []


# -- migration ------------------------------------------------------------


def test_the_old_per_plugin_files_move_into_the_shared_directory(tmp_path):
    plugin_dir, root = tmp_path / "plugins" / "cozychat", tmp_path / "cozychat"
    (plugin_dir / "keys").mkdir(parents=True)
    (plugin_dir / "devices.json").write_text('[{"device_id": "phone-1"}]', "utf-8")
    (plugin_dir / "keys" / "phone-1").write_bytes(b"key-material")
    sqlite3.connect(plugin_dir / "outbox.sqlite").close()

    assert set(shared.migrate_plugin_dir(plugin_dir, root)) == {
        "devices.json", "keys", "outbox.sqlite"}
    assert [d["device_id"] for d in DeviceStore(root).list()] == ["phone-1"]
    assert DeviceStore(root).key("phone-1") == b"key-material"
    assert (root / "outbox.sqlite").exists()
    assert not (plugin_dir / "devices.json").exists()
    # And the shared directory is the private one it has to be.
    assert stat.S_IMODE(root.stat().st_mode) == 0o700


def test_migration_never_overwrites_what_the_shared_directory_already_holds(tmp_path):
    plugin_dir, root = tmp_path / "plugins" / "cozychat", tmp_path / "cozychat"
    plugin_dir.mkdir(parents=True)
    root.mkdir(parents=True)
    (plugin_dir / "devices.json").write_text('[{"device_id": "stale"}]', "utf-8")
    (root / "devices.json").write_text('[{"device_id": "current"}]', "utf-8")

    # The second profile to load the plugin must not hand its own stale copy to the first one.
    assert shared.migrate_plugin_dir(plugin_dir, root) == []
    assert [d["device_id"] for d in DeviceStore(root).list()] == ["current"]


def test_migration_is_a_no_op_the_second_time(tmp_path):
    plugin_dir, root = tmp_path / "plugins" / "cozychat", tmp_path / "cozychat"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "devices.json").write_text("[]", "utf-8")
    assert shared.migrate_plugin_dir(plugin_dir, root) == ["devices.json"]
    assert shared.migrate_plugin_dir(plugin_dir, root) == []


def test_the_old_registration_file_becomes_rows_and_is_removed(tmp_path):
    store = shared.SharedState(tmp_path / "cozychat")
    path = tmp_path / "live-activities.json"
    path.write_text(json.dumps([
        {"activity_id": "A1", "push_id": "push-1", "environment": "development",
         "session_id": "session-1", "created_at": 1.0},
        {"activity_id": "broken"},
    ]), "utf-8")

    assert live.migrate_registrations(path, store) == 1
    assert not path.exists()
    registry = live.LiveActivities(store)
    assert registry.listing() == [{"activity_id": "A1", "session_id": "session-1"}]


def test_migrating_a_registration_file_that_was_never_there_is_fine(tmp_path):
    store = shared.SharedState(tmp_path / "cozychat")
    assert live.migrate_registrations(tmp_path / "nothing.json", store) == 0


# -- what /info can say ---------------------------------------------------


def test_the_writer_is_claimed_by_a_frame_and_not_by_loading(tmp_path):
    # Measured 2026-09-15: claiming it at load time made `hermes serve` — the last process to
    # start — report itself as the writer of a feed it had never written to.
    store = shared.SharedState(tmp_path / "cozychat")
    assert store.writer_pid() is None
    assert store.attached() is False
    LiveFeed(store).publish("stream.started", source="run")
    assert store.writer_pid() == os.getpid()
    assert store.attached() is True           # this process writes the frames, idle or not


def test_attached_is_true_in_the_other_process_only_while_the_feed_is_fresh(tmp_path):
    # The dashboard process's view: it never writes a frame, so all it can go on is whether one
    # arrived lately. `hermes serve` answering `/info` is exactly this.
    store = shared.SharedState(tmp_path / "cozychat")
    store.note_writer(os.getpid() + 1)        # the hooks are somebody else's process
    assert store.attached() is False
    # A frame from that other process: written straight in, because publishing through this one
    # would make this process the writer and prove the wrong thing.
    with store.write() as db:
        db.execute("INSERT INTO frames (at, body) VALUES (?, '{}')", (time.time(),))
    assert store.attached() is True
    # This is the fault the old `attached` could not report: a ring existed, and nothing fed it.
    assert store.attached(now=time.time() + shared.FRESH_SECONDS + 1) is False


def test_info_reports_the_state_version_and_both_pids(plugin_app):
    client, package, _ = plugin_app
    package.feed.publish("stream.started", source="run")
    body = client.get("/api/plugins/cozychat/info").json()
    assert body["state"] == "shared-v1"
    assert body["serve_pid"] == os.getpid()
    assert body["attached"] is True and body["seq"] == 1


def test_info_reports_no_state_version_for_a_plugin_that_predates_this(plugin_app):
    client, package, _ = plugin_app
    del package.STATE_VERSION
    assert client.get("/api/plugins/cozychat/info").json()["state"] is None


@pytest.mark.parametrize("capacity", [3])
def test_the_frames_table_is_bounded(tmp_path, capacity):
    feed = LiveFeed(shared.SharedState(tmp_path / "cozychat", capacity=capacity, prune_every=1))
    for index in range(10):
        feed.publish("message.delta", source="room", payload={"text": str(index)})
    assert [frame["payload"]["text"] for frame in feed.since(0)] == ["7", "8", "9"]
