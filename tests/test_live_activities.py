"""The Lock Screen card: its registration routes, its cadence, and the relay's own schema.

EVERY BODY THIS SUITE PRODUCES IS VALIDATED against `notify-schema.json`, a copy of the relay's
`NotifyRequestSchema`. The fake relay does it on the way past, so a test that sends a card update
cannot pass while sending something the relay would reject: there is no separate "schema test" to
forget to update.
"""

from __future__ import annotations

import json
import stat
import time
from pathlib import Path

import pytest

from cozychat import activities as live
from cozychat.push import LIVE_COALESCE_SECONDS, Outbox

SCHEMA = json.loads((Path(__file__).parent / "notify-schema.json").read_text("utf-8"))


class FakeRelay:
    """Records what the plugin sent, and refuses anything the real relay would refuse."""

    def __init__(self, *, push_ids=("push-1", "push-2"), status=202) -> None:
        self.push_ids = list(push_ids)
        self.status = status
        self.registered: list = []
        self.notified: list = []
        self.forgotten: list = []

    def register_live_activity(self, token, environment, device_id, profile):
        self.registered.append((token, environment, device_id, profile))
        return self.push_ids.pop(0) if self.push_ids else None

    def notify_live_activity(self, push_id, body):
        validate(SCHEMA, {"pushId": push_id, "liveActivity": body})
        self.notified.append((push_id, body))
        return self.status, None

    def forget(self, push_id):
        self.forgotten.append(push_id)


class CardOutbox(Outbox):
    """An explicit test-only owner for card tests that do not exercise consent routing."""
    def __init__(self, path):
        super().__init__(path)
        self.live_authority = lambda *_: True

    def enqueue_live_activity(self, activity_id, push_id, body, **kwargs):
        if not kwargs.get("device_id") and not kwargs.get("profile"):
            kwargs.update(device_id="test-phone", profile="default", consent_version=1)
        return super().enqueue_live_activity(activity_id, push_id, body, **kwargs)


TEST_DEVICE_ID = "test-phone"
TEST_PROFILE = "default"


def allows_test_card(device_id, profile):
    return device_id == TEST_DEVICE_ID and profile == TEST_PROFILE


def configure_cards(registry, outbox, relay):
    registry.configure(outbox=outbox, relay=relay, allows_device=allows_test_card)


def register_card(registry, activity_id, token, environment, session_id):
    return registry.register(activity_id, token, environment, session_id,
                             TEST_DEVICE_ID, TEST_PROFILE, 1)


def validate(schema, instance) -> None:
    """The relay's own validator when it is installed, which it is in the Hermes venv."""
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(instance, schema)


@pytest.fixture
def cards(tmp_path):
    """A configured registry, its outbox, and the relay behind both."""
    relay = FakeRelay()
    outbox = CardOutbox(tmp_path / "outbox.sqlite")
    registry = live.LiveActivities()
    configure_cards(registry, outbox, relay)
    register_card(registry, "A1", "aa" * 16, "development", "session-1")
    yield registry, outbox, relay
    outbox.close()


# -- storage -------------------------------------------------------------


def test_a_registration_keeps_the_push_id_and_never_the_token(cards, shared_state):
    _, _, relay = cards
    with shared_state.read() as db:
        rows = db.execute("SELECT push_id FROM activities WHERE activity_id = 'A1'").fetchall()
    assert relay.registered == [("aa" * 16, "development", TEST_DEVICE_ID, TEST_PROFILE)]
    assert [row[0] for row in rows] == ["push-1"]
    # The ActivityKit token stops at the relay. Nothing on this computer is addressable with it.
    assert "aa" * 16 not in shared_state.path.read_bytes().decode("latin-1")


def test_the_shared_state_file_and_its_directory_are_private(cards, shared_state):
    assert stat.S_IMODE(shared_state.path.stat().st_mode) == 0o600
    # 0700, not 0600: a directory with no execute bit cannot be entered, so the plugin could not
    # reach its own state. Same privacy, and traversable.
    assert stat.S_IMODE(shared_state.root.stat().st_mode) == 0o700


def test_re_registering_one_card_replaces_it_and_releases_the_old_relay_row(cards):
    registry, _, relay = cards
    assert register_card(registry, "A1", "bb" * 16, "development", "session-1")
    assert relay.forgotten == ["push-1"]
    assert [row["activity_id"] for row in registry.listing()] == ["A1"]


def test_the_store_is_bounded(cards, tmp_path):
    registry, outbox, relay = cards
    relay.push_ids = [f"push-{n}" for n in range(live.MAX_REGISTRATIONS + 4)]
    for n in range(live.MAX_REGISTRATIONS + 2):
        register_card(registry, f"B{n}", "cc" * 16, "production", "session-2")
    assert len(registry.listing()) == live.MAX_REGISTRATIONS


def test_forgetting_a_card_releases_its_relay_registration(cards):
    registry, _, relay = cards
    assert registry.forget("A1") is True
    assert relay.forgotten == ["push-1"]
    assert registry.forget("A1") is False


def test_registrations_survive_a_restart(tmp_path):
    relay = FakeRelay()
    outbox = CardOutbox(tmp_path / "outbox.sqlite")
    first = live.LiveActivities()
    configure_cards(first, outbox, relay)
    register_card(first, "A1", "aa" * 16, "development", "session-1")

    second = live.LiveActivities()
    configure_cards(second, outbox, relay)
    assert second.update("session-1", "thinking", "Thinking", now=100.0) == 1
    outbox.drain(relay, _NoDevices(), now=100.0)
    assert relay.notified[0][0] == "push-1"
    outbox.close()


class _NoDevices:
    def list(self):
        return [{"device_id": "test-phone", "profile": "default", "consent_version": 1}]


# -- cadence -------------------------------------------------------------


def test_updates_are_coalesced_to_one_per_card_per_window(cards):
    registry, outbox, relay = cards
    registry.update("session-1", "thinking", "Thinking", now=100.0)
    outbox.drain(relay, _NoDevices(), now=100.0)
    registry.update("session-1", "usingTools", "Using tools", tool_delta=1, now=100.5)
    registry.update("session-1", "writing", "Writing the reply", now=101.0)
    outbox.drain(relay, _NoDevices(), now=101.0)
    assert [body["contentState"]["phase"] for _, body in relay.notified] == ["thinking"]

    outbox.drain(relay, _NoDevices(), now=100.0 + LIVE_COALESCE_SECONDS)
    # One update for the two that were held, and it is the NEWEST state, not the oldest.
    assert [body["contentState"]["phase"] for _, body in relay.notified] == ["thinking", "writing"]
    assert relay.notified[-1][1]["contentState"]["toolCallCount"] == 1


def test_the_terminal_update_is_never_held_back(cards):
    registry, outbox, relay = cards
    registry.update("session-1", "thinking", "Thinking", now=100.0)
    outbox.drain(relay, _NoDevices(), now=100.0)
    registry.update("session-1", "writing", "Writing the reply", now=100.2)
    registry.finish("session-1", succeeded=True, now=100.3)
    outbox.drain(relay, _NoDevices(), now=100.3)

    last = relay.notified[-1][1]
    assert last["event"] == "end"
    assert last["contentState"]["phase"] == "completed"
    assert last["dismissalDate"] == int(100.3) + live.DISMISS_AFTER_SECONDS
    assert "staleDate" not in last


def test_a_failed_run_ends_the_card_as_failed(cards):
    registry, outbox, relay = cards
    registry.finish("session-1", succeeded=False, now=100.0)
    outbox.drain(relay, _NoDevices(), now=100.0)
    assert relay.notified[-1][1]["contentState"]["phase"] == "failed"


@pytest.mark.parametrize("first_status", [202, 0, 429, 500, 400])
def test_a_terminal_update_queued_during_send_survives(cards, first_status):
    registry, outbox, relay = cards
    original_notify = relay.notify_live_activity

    def finish_during_send(push_id, body):
        if not relay.notified:
            registry.finish("session-1", succeeded=True, now=100.1)
            original_notify(push_id, body)
            return first_status, 60.0 if first_status == 429 else None
        return original_notify(push_id, body)

    relay.notify_live_activity = finish_during_send
    registry.update("session-1", "thinking", "Thinking", now=100.0)
    assert outbox.drain(relay, _NoDevices(), now=100.0) == (1 if first_status == 202 else 0)
    assert outbox.drain(relay, _NoDevices(), now=100.1) == 1
    assert [body["event"] for _, body in relay.notified] == ["update", "end"]


def test_a_relay_refusal_is_retried_with_backoff(cards):
    registry, outbox, relay = cards
    relay.status = 500
    registry.update("session-1", "thinking", "Thinking", now=100.0)
    outbox.drain(relay, _NoDevices(), now=100.0)
    assert len(relay.notified) == 1
    relay.status = 202
    outbox.drain(relay, _NoDevices(), now=100.5)
    assert len(relay.notified) == 1, "a deferred card update is not retried inside its backoff"
    outbox.drain(relay, _NoDevices(), now=102.0)
    assert len(relay.notified) == 2


def test_only_the_cards_watching_that_session_are_updated(cards):
    registry, outbox, relay = cards
    register_card(registry, "A2", "dd" * 16, "production", "session-9")
    registry.update("session-9", "thinking", "Thinking", now=100.0)
    outbox.drain(relay, _NoDevices(), now=100.0)
    assert [push_id for push_id, _ in relay.notified] == ["push-2"]


def test_the_sequence_only_goes_up(cards):
    registry, outbox, relay = cards
    for tick in range(3):
        registry.update("session-1", "thinking", "Thinking", now=100.0 + tick * 3)
        outbox.drain(relay, _NoDevices(), now=100.0 + tick * 3)
    assert [body["contentState"]["eventSequence"] for _, body in relay.notified] == [1, 2, 3]


def test_a_long_status_is_cut_to_the_relays_ceiling(cards):
    registry, outbox, relay = cards
    registry.update("session-1", "thinking", "x" * 400, now=100.0)
    outbox.drain(relay, _NoDevices(), now=100.0)
    assert len(relay.notified[-1][1]["contentState"]["shortStatus"]) == live.SHORT_STATUS_MAX


def test_an_unconfigured_registry_does_nothing(tmp_path):
    assert live.LiveActivities().update("session-1", "thinking", "Thinking") == 0


def test_registration_without_an_explicit_consent_authority_makes_no_relay_call(tmp_path):
    relay = FakeRelay()
    registry = live.LiveActivities()
    registry.configure(outbox=CardOutbox(tmp_path / "outbox.sqlite"), relay=relay)
    assert not registry.register("A1", "aa" * 16, "development", "session-1",
                                 TEST_DEVICE_ID, TEST_PROFILE, 1)
    assert relay.registered == []


@pytest.mark.parametrize(("device_id", "profile", "version"), [
    ("", TEST_PROFILE, 1), (TEST_DEVICE_ID, "", 1), (TEST_DEVICE_ID, TEST_PROFILE, 0),
])
def test_registration_requires_complete_versioned_consent(tmp_path, device_id, profile, version):
    relay = FakeRelay()
    registry = live.LiveActivities()
    registry.configure(outbox=CardOutbox(tmp_path / "outbox.sqlite"), relay=relay,
                       allows_device=allows_test_card)
    assert not registry.register("A1", "aa" * 16, "development", "session-1",
                                 device_id, profile, version)
    assert relay.registered == []


# -- the hooks -----------------------------------------------------------


@pytest.fixture
def emitter(cards, tmp_path):
    from cozychat.devices import DeviceStore
    from cozychat.events import Emitter

    registry, outbox, relay = cards
    return Emitter(DeviceStore(tmp_path), outbox, {"profile_name": "luna"},
                   activities=registry), outbox, relay


def drained(outbox, relay, tick=0.0):
    """Drain from the hooks' own clock: a hook stamps `now` itself, so a scripted one would leave
    every row it queued in the future and nothing would ever be due."""
    outbox.drain(relay, _NoDevices(), now=time.time() + tick)
    return [body["contentState"] for _, body in relay.notified]


def test_the_hooks_walk_the_card_through_a_turn(emitter):
    hooks, outbox, relay = emitter
    hooks.stream_start(session_id="session-1")
    states = drained(outbox, relay)
    assert states[-1]["phase"] == "thinking"

    hooks.tool_started(tool_name="terminal", tool_call_id="t1", session_id="session-1")
    states = drained(outbox, relay, 3.0)
    assert (states[-1]["phase"], states[-1]["toolCallCount"]) == ("usingTools", 1)

    hooks.stream_delta(session_id="session-1", delta="hello")
    states = drained(outbox, relay, 6.0)
    assert states[-1]["phase"] == "writing"

    hooks.session_end(session_id="session-1", completed=True)
    states = drained(outbox, relay, 6.1)
    assert states[-1]["phase"] == "completed"


def test_an_approval_blocks_the_card_on_the_id_the_phone_answers(emitter):
    hooks, outbox, relay = emitter
    hooks.approval_pending(pattern_key="terminal:rm", tool_call_id="t1", session_id="session-1",
                           request_id="req-9")
    state = drained(outbox, relay)[-1]
    assert (state["phase"], state["approvalID"]) == ("waitingOnApproval", "req-9")


def test_reasoning_deltas_do_not_claim_the_reply_is_being_written(emitter):
    hooks, outbox, relay = emitter
    hooks.stream_delta(session_id="session-1", delta="thinking out loud", kind="reasoning")
    assert drained(outbox, relay) == []


def test_the_card_retires_even_when_replies_are_muted(cards, tmp_path):
    from cozychat.devices import DeviceStore
    from cozychat.events import Emitter

    registry, outbox, relay = cards
    hooks = Emitter(DeviceStore(tmp_path), outbox, {"push_replies": False}, activities=registry)
    hooks.session_end(session_id="session-1", completed=True)
    assert drained(outbox, relay)[-1]["phase"] == "completed"


# -- the routes ----------------------------------------------------------


@pytest.fixture
def routes(plugin_app, tmp_path):
    client, package, _ = plugin_app
    relay = FakeRelay()
    outbox = CardOutbox(tmp_path / "outbox.sqlite")
    registry = live.LiveActivities()
    registry.configure(outbox=outbox, relay=relay,
                       allows_device=lambda device_id, profile:
                       device_id == "phone-1" and profile == "default")
    package.live_activities = lambda: registry
    yield client, registry, relay
    outbox.close()


BODY = {"activity_id": "A1", "token": "aa" * 16, "environment": "development",
        "session_id": "session-1", "device_id": "phone-1", "profile": "default",
        "consent_version": 1}


def test_the_route_registers_a_card(routes):
    client, registry, relay = routes
    response = client.post("/api/plugins/cozychat/live-activities", json=BODY)
    assert response.status_code == 200
    assert response.json() == {"ok": True, "activity_id": "A1"}
    assert registry.listing() == [{"activity_id": "A1", "session_id": "session-1"}]


@pytest.mark.parametrize("field, value", [
    ("activity_id", ""), ("token", ""), ("session_id", ""),
    ("environment", "staging"), ("token", "a" * 600), ("activity_id", "A" * 200),
])
def test_the_route_refuses_a_malformed_registration(routes, field, value):
    client, registry, _ = routes
    response = client.post("/api/plugins/cozychat/live-activities", json={**BODY, field: value})
    assert response.status_code == 400
    assert registry.listing() == []


def test_a_relay_that_refuses_the_token_is_a_bad_gateway(routes):
    client, _, relay = routes
    relay.push_ids = []
    assert client.post("/api/plugins/cozychat/live-activities", json=BODY).status_code == 502


def test_the_route_forgets_a_card(routes):
    client, registry, relay = routes
    client.post("/api/plugins/cozychat/live-activities", json=BODY)
    response = client.delete("/api/plugins/cozychat/live-activities/A1")
    assert response.json() == {"ok": True, "removed": True}
    assert relay.forgotten == ["push-1"]
    assert client.delete(
        "/api/plugins/cozychat/live-activities/A1").json() == {"ok": True, "removed": False}


def test_the_routes_refuse_when_the_plugin_drives_no_cards(plugin_app):
    client, package, _ = plugin_app
    package.live_activities = live.LiveActivities
    assert client.post("/api/plugins/cozychat/live-activities", json=BODY).status_code == 503
    assert client.delete("/api/plugins/cozychat/live-activities/A1").status_code == 503
