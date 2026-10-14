import io
import json
import threading
import time
import urllib.request

import pytest

from cozychat.activities import LiveActivities
from cozychat.devices import DeviceStore
from cozychat.push import Outbox, Relay
from cozychat.relay import cli, services
from cozychat.relay.control import PhoneManagement
from cozychat.relay.pairing import PairingStore
from cozychat.relay.push_devices import PushDevices
from cozychat.relay.runtime import Tunnel

PHONE = bytes.fromhex("11" * 32)
OTHER = bytes.fromhex("22" * 32)
PROFILE = "default"


@pytest.fixture
def push_setup(monkeypatch, shared_state):
    calls = []

    class Response:
        status = 202
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self): return b'{"pushId":"activity-push"}'

    def open_request(request, **kwargs):
        calls.append((request.method, request.full_url, request.data))
        return Response()

    monkeypatch.setattr(urllib.request, "urlopen", open_request)
    devices = DeviceStore(shared_state.root)
    relay = Relay("https://push.cozylabs.ai")
    policy = PushDevices(devices, relay)
    relay._allows = policy.allows
    relay._allows_registration = lambda device_id, profile: devices.consented(device_id, profile)
    outbox = Outbox(shared_state.root / "outbox.sqlite")
    outbox.live_authority = policy.allows_live_activity
    cards = LiveActivities(state=shared_state)
    cards.configure(outbox=outbox, relay=relay,
                    allows_device=lambda device_id, profile: devices.consented(device_id, profile),
                    retire_push=policy.retire_registration)
    yield policy, relay, outbox, cards, calls
    outbox.close()


def add(policy, key=PHONE, push_id="phone-push"):
    return policy.handle(key, {"op": "device.add", "device": {
        "push_id": push_id, "key_hex": b"test-push-key".hex(), "profile": PROFILE,
        "consent_version": 1}})


def test_default_pairing_and_every_push_lane_make_zero_http_requests(push_setup, tmp_path):
    policy, relay, outbox, cards, calls = push_setup
    tunnel = Tunnel(PairingStore(tmp_path / "relay"), home=tmp_path,
                    config={"relay_url": relay.base}, plugin_version="0.6.0",
                    state_version="shared-v1", push_devices=policy)
    tunnel.store.open_window()
    features = tunnel.capabilities([], PHONE)["features"]["push"]
    assert features == {"available": True, "paired": False}
    outbox.enqueue(PHONE.hex(), "message", "turn", {"kind": "message", "preview": "reply"},
                   profile=PROFILE, consent_version=1, now=1)
    outbox.enqueue_live_activity("card", "stale-push", {"event": "update"}, now=1)
    outbox.drain(relay, policy.store, now=100)
    assert not cards.register("card", "token", "development", "session", PHONE.hex(), PROFILE, 1)
    assert relay.register_live_activity("token", "development") is None
    relay.notify("stale-push", "sealed", "message", "turn")
    relay.notify_live_activity("stale-push", {})
    assert calls == []


def test_upgrade_quarantines_legacy_devices_cards_and_outbox_without_relay_calls(
        monkeypatch, shared_state):
    calls = []
    monkeypatch.setattr(urllib.request, "urlopen", lambda *args, **kwargs: calls.append(args))
    store = DeviceStore(shared_state.root)
    store.add({"device_id": PHONE.hex(), "push_id": "legacy-push", "key_hex": "11"})
    outbox = Outbox(shared_state.root / "outbox.sqlite")
    outbox.enqueue(PHONE.hex(), "message", "turn", {"kind": "message"}, now=1)
    outbox.enqueue_live_activity("legacy-card", "legacy-card-push", {"event": "update"}, now=1)
    outbox.close()
    with shared_state.write() as db:
        db.execute("INSERT INTO activities (activity_id, push_id, environment, session_id, created_at)"
                   " VALUES ('legacy-card', 'legacy-card-push', 'production', 's', 1)")

    policy = PushDevices(store, Relay("https://push.cozylabs.ai"), shared_state)

    assert store.list() == []
    with shared_state.read() as db:
        assert db.execute("SELECT * FROM activities").fetchall() == []
    assert calls == []
    policy.retry_retirements(now=999)
    assert calls == []


def test_profile_authority_isolated_for_one_phone(push_setup):
    policy, relay, outbox, _, calls = push_setup
    add(policy, push_id="default-push")
    policy.handle(PHONE, {"op": "device.add", "device": {
        "push_id": "luna-push", "key_hex": "22", "profile": "luna", "consent_version": 1}})
    from cozychat.events import Emitter
    emitter = Emitter(policy.store, outbox, {"profile_name": "luna"})
    assert emitter.cron_send("job", "done") == 1
    assert outbox.drain(relay, policy.store, now=time.time() + 1) == 1
    assert json.loads(calls[-1][2])["pushId"] == "luna-push"


def test_live_queue_rejects_missing_or_forged_profile_authority(push_setup):
    policy, relay, outbox, cards, calls = push_setup
    add(policy, push_id="default-push")
    policy.handle(PHONE, {"op": "device.add", "device": {
        "push_id": "luna-push", "key_hex": "22", "profile": "luna", "consent_version": 1}})
    assert cards.register("card", "token", "development", "session", PHONE.hex(), PROFILE, 1)
    calls.clear()
    outbox.enqueue_live_activity("missing-owner", "default-push", {"event": "update"},
                                 consent_version=1, now=1)
    # The phone consented for luna, but this card belongs to default. Its copied push id is not
    # authority to deliver a default card through luna's profile.
    outbox.enqueue_live_activity("card", "default-push", {"event": "update"},
                                 device_id=PHONE.hex(), profile="luna", consent_version=1, now=1)
    assert outbox.drain(relay, policy.store, now=100) == 0
    assert calls == []


def test_failed_deregistration_is_retained_and_retried(push_setup):
    policy, relay, _, _, calls = push_setup
    add(policy)
    attempts = [0]

    def fail_once(request, **kwargs):
        calls.append((request.method, request.full_url, request.data))
        attempts[0] += 1
        if attempts[0] == 1:
            raise OSError("offline")
        class Response:
            status = 204
            def __enter__(self): return self
            def __exit__(self, *args): pass
        return Response()

    relay._opener = fail_once
    result = policy.handle(PHONE, {"op": "device.remove", "profile": PROFILE})
    assert result == {"removed": True, "enabled": False, "pending_cleanup": True}
    assert policy.store.list() == []
    assert policy.retry_retirements(now=time.time() + 2) == 1
    assert policy.pending_retirements() == 0
    assert [call[0] for call in calls].count("DELETE") == 2


def test_legacy_card_removal_is_local_and_makes_no_relay_call(shared_state):
    class RelayProbe:
        def __init__(self): self.forgotten = []
        def forget(self, push_id): self.forgotten.append(push_id)

    cards = LiveActivities(state=shared_state)
    cards.configure(outbox=Outbox(shared_state.root / "outbox.sqlite"), relay=RelayProbe())
    with shared_state.write() as db:
        db.execute("INSERT INTO activities (activity_id, push_id, environment, session_id, created_at)"
                   " VALUES ('legacy', 'legacy-push', 'production', 's', 1)")
    assert cards.forget("legacy")
    assert cards._relay.forgotten == []


def test_opt_in_sends_and_opt_out_deregisters_and_stops_stale_rows(push_setup):
    policy, relay, outbox, cards, calls = push_setup
    add(policy)
    assert policy.paired(PHONE) and not policy.paired(OTHER)
    outbox.enqueue(PHONE.hex(), "message", "turn", {"kind": "message", "preview": "reply"},
                   profile=PROFILE, consent_version=1, now=1)
    assert outbox.drain(relay, policy.store, now=100) == 1
    assert calls[0][:2] == ("POST", "https://push.cozylabs.ai/notify")
    assert b"reply" not in calls[0][2]
    assert cards.register("card", "token", "development", "session", PHONE.hex(), PROFILE, 1)
    outbox.enqueue_live_activity("card", "activity-push", {"event": "update"},
                                 device_id=PHONE.hex(), profile=PROFILE, consent_version=1, now=1)
    assert policy.handle(PHONE, {"op": "device.remove", "profile": PROFILE})["enabled"] is False
    assert {url for method, url, _ in calls if method == "DELETE"} == {
        "https://push.cozylabs.ai/register/phone-push",
        "https://push.cozylabs.ai/register/activity-push"}
    before = len(calls)
    assert outbox.drain(relay, policy.store, now=101) == 0
    relay.notify_live_activity("activity-push", {})
    assert not cards.register("new", "token", "development", "session", PHONE.hex())
    assert len(calls) == before and not policy.paired(PHONE)


def test_opt_out_leaves_the_other_phone_enabled(push_setup):
    policy, relay, outbox, _, calls = push_setup
    add(policy)
    add(policy, OTHER, "other-push")
    policy.handle(PHONE, {"op": "device.remove", "profile": PROFILE})
    outbox.enqueue(OTHER.hex(), "message", "other", {"kind": "message"},
                   profile=PROFILE, consent_version=1, now=1)
    assert outbox.drain(relay, policy.store, now=100) == 1
    assert json.loads(calls[-1][2])["pushId"] == "other-push"


def test_a_phone_cannot_change_another_phones_consent(push_setup):
    policy, _, _, _, calls = push_setup
    with pytest.raises(ValueError):
        policy.handle(PHONE, {"op": "device.add", "device": {
            "device_id": OTHER.hex(), "push_id": "other", "key_hex": "11"}})
    with pytest.raises(ValueError):
        policy.handle(PHONE, {"op": "device.remove", "device_id": OTHER.hex()})
    assert policy.store.list() == [] and calls == []


def test_control_requires_host_approval_before_accepting_push_keys(push_setup):
    policy, _, _, _, calls = push_setup
    context = services.SessionContext(approved=False, capabilities=lambda: {}, api=lambda: None,
                                     phone_key=PHONE, push_handler=policy.handle)
    request = json.dumps({"id": 1, "op": "device.add", "device": {
        "push_id": "phone-push", "key_hex": "11", "profile": PROFILE, "consent_version": 1}}).encode()
    assert services._answer(request, context)["error"] == "not_approved"
    context.approved = True
    assert services._answer(request, context)["enabled"] is True
    assert calls == []  # Registration belongs to the phone; no token goes through control.


def test_no_push_is_a_compatibility_alias_and_cli_has_explicit_commands():
    import argparse
    parser = argparse.ArgumentParser()
    cli.setup(parser)
    assert parser.parse_args(["pair", "--no-push"]).no_push is True
    args = parser.parse_args(["push", "disable", PHONE.hex()])
    assert args.action == "disable" and args.phone == PHONE.hex()


def test_cli_enable_disable_uses_the_same_pairing_scope(push_setup, tmp_path, monkeypatch):
    policy, relay, _, _, calls = push_setup
    tunnel = Tunnel(PairingStore(tmp_path / "relay"), home=tmp_path,
                    config={"relay_url": relay.base}, plugin_version="0.6.0",
                    state_version="shared-v1", push_devices=policy)
    monkeypatch.setattr(tunnel.store, "is_approved", lambda key: key == PHONE)
    assert cli.set_push(tunnel, "enable", PHONE.hex(), payload={
        "push_id": "phone-push", "key_hex": "11", "profile": PROFILE, "consent_version": 1}, out=io.StringIO()) == 0
    assert cli.set_push(tunnel, "disable", PHONE.hex(), out=io.StringIO()) == 0
    assert calls[0][:2] == ("DELETE", "https://push.cozylabs.ai/register/phone-push")


def test_register_wires_default_http_guards(monkeypatch, shared_state):
    import cozychat
    from test_register import RecordingContext

    calls, drains = [], []
    monkeypatch.setattr(urllib.request, "urlopen", lambda *args, **kwargs: calls.append(args))
    monkeypatch.setattr(cozychat, "_start_drain", lambda relay, store, outbox, path, **kw:
                        drains.append((relay, store, outbox)) or outbox.close)
    ctx = RecordingContext()
    cozychat.register(ctx)
    try:
        relay, store, outbox = drains[0]
        assert store.list() == []
        assert relay.register_live_activity("token", "development") is None
        relay.notify("stale", "sealed", "message", "turn")
        relay.notify_live_activity("stale", {})
        outbox.drain(relay, store)
        assert calls == []
    finally:
        for unload in ctx.unloads:
            unload()


def test_push_opt_in_and_opt_out_through_real_encrypted_control(push_setup, tmp_path):
    import asyncio
    from cozychat.relay import pairing
    from tunnel_phone import Phone, loopback_binds
    from test_tunnel_pairing import wait_for

    policy, relay, _, _, calls = push_setup
    tunnel = Tunnel(PairingStore(tmp_path / "relay"), home=tmp_path,
                    config={"relay_url": relay.base, "lan_port": 0}, plugin_version="0.6.0",
                    state_version="shared-v1", push_devices=policy, interfaces=loopback_binds)
    window = tunnel.store.open_window()

    async def scenario():
        listener = tunnel.make_listener(decision_poll_seconds=0.01)
        await listener.start()
        phone = Phone(pairing.pairing_link(tunnel.store.host_public(), window, listener.hints()))
        try:
            await phone.connect()
            refused = await phone.request("device.add", device={"push_id": "phone-push", "key_hex": "11", "profile": PROFILE, "consent_version": 1})
            assert refused["error"] == "not_approved"
            await wait_for(lambda: tunnel.store.attempt() is not None)
            tunnel.store.decide(tunnel.store.attempt().id, approve=True)
            await phone.next_control()
            before = await phone.request("info")
            assert before["capabilities"]["features"]["push"] == {"available": True, "paired": False}
            assert calls == []
            enabled = await phone.request("device.add", device={"push_id": "phone-push", "key_hex": "11", "profile": PROFILE, "consent_version": 1})
            assert enabled["enabled"] is True
            assert (await phone.request("info"))["capabilities"]["features"]["push"]["paired"] is True
            assert (await phone.request("device.remove", profile=PROFILE))["removed"] is True
            assert (await phone.request("info"))["capabilities"]["features"]["push"]["paired"] is False
            assert calls[0][:2] == ("DELETE", "https://push.cozylabs.ai/register/phone-push")
        finally:
            await phone.close()
            await listener.stop()

    asyncio.run(asyncio.wait_for(scenario(), 15))


def test_tombstone_delete_targets_the_relay_the_registration_used(push_setup):
    policy, relay, _, _, calls = push_setup
    policy.handle(PHONE, {"op": "device.add", "device": {
        "push_id": "private-push", "key_hex": b"k".hex(), "profile": PROFILE, "consent_version": 1,
        "relay_url": "https://private-relay.example/v1"}})
    assert policy.store.list()[0]["relay_url"] == "https://private-relay.example/v1"
    policy.handle(PHONE, {"op": "device.remove", "profile": PROFILE})
    assert [c[1] for c in calls if c[0] == "DELETE"] == ["https://private-relay.example/v1/register/private-push"]


def test_a_rotated_registration_is_deleted_at_its_own_relay(push_setup):
    policy, _, _, _, calls = push_setup
    policy.handle(PHONE, {"op": "device.add", "device": {
        "push_id": "old", "key_hex": b"k".hex(), "profile": PROFILE, "consent_version": 1,
        "relay_url": "https://old-relay.example"}})
    add(policy, push_id="new")
    assert [c[1] for c in calls if c[0] == "DELETE"] == ["https://old-relay.example/register/old"]


def test_unsafe_or_missing_relay_urls_fall_back_to_the_current_relay(push_setup):
    policy, _, _, _, calls = push_setup
    policy.handle(PHONE, {"op": "device.add", "device": {
        "push_id": "odd", "key_hex": b"k".hex(), "profile": PROFILE, "consent_version": 1,
        "relay_url": "http://public-host.example"}})
    assert "relay_url" not in policy.store.list()[0]
    policy.handle(PHONE, {"op": "device.remove", "profile": PROFILE})
    assert [c[1] for c in calls if c[0] == "DELETE"] == ["https://push.cozylabs.ai/register/odd"]


def test_exported_tombstones_survive_and_are_retried_at_their_relay(push_setup, tmp_path, monkeypatch):
    from cozychat.relay import push_devices
    policy, relay, _, _, calls = push_setup
    policy.handle(PHONE, {"op": "device.add", "device": {
        "push_id": "stuck", "key_hex": b"k".hex(), "profile": PROFILE, "consent_version": 1,
        "relay_url": "https://private-relay.example"}})

    def down(request, **kwargs):
        calls.append((request.method, request.full_url, None))
        raise OSError("relay unreachable")

    relay._opener = down
    monkeypatch.setattr(urllib.request, "urlopen", down)  # the stdlib client used by retries
    assert policy.handle(PHONE, {"op": "device.remove", "profile": PROFILE})["pending_cleanup"] is True
    leftover = tmp_path / "leftover.json"
    assert push_devices.export_tombstones(policy.state.root, leftover) == 1
    assert oct(leftover.stat().st_mode & 0o777) == "0o600"
    assert push_devices.retry_exported_tombstones(leftover) == 1  # still down: kept
    assert leftover.exists()

    class Up:
        status = 204
        def __enter__(self): return self
        def __exit__(self, *args): pass

    monkeypatch.setattr(urllib.request, "urlopen", lambda request, **kw: (calls.append(
        (request.method, request.full_url, None)), Up())[1])
    assert push_devices.retry_exported_tombstones(leftover) == 0
    assert not leftover.exists()
    assert calls[-1][1] == "https://private-relay.example/register/stuck"


class BlockingRelay:
    base = "https://push.cozylabs.ai"

    def __init__(self):
        self.entered, self.release, self.forgotten = threading.Event(), threading.Event(), []

    def forget(self, push_id, relay_url=None):
        self.entered.set()
        assert self.release.wait(20)
        self.forgotten.append(push_id)
        return 204


def test_revoke_makes_no_relay_call_under_the_pairing_lock(shared_state, tmp_path):
    relay = BlockingRelay()
    devices = DeviceStore(shared_state.root)
    policy = PushDevices(devices, relay)
    store = PairingStore(tmp_path / "relay")
    for key, name in ((PHONE, "A"), (OTHER, "B")):
        window = store.open_window()
        attempt = store.begin_attempt(window.id, key, name, "123456")
        assert store.decide(attempt, True) and store.settle(attempt) == "approved"
    policy.handle(PHONE, {"op": "device.add", "device": {
        "push_id": "phone-push", "key_hex": b"k".hex(), "profile": PROFILE, "consent_version": 1}})
    # The add made no tombstone; the revoke below makes one and must not deliver it inline.
    management = PhoneManagement(
        store, devices=devices, retire_push=lambda key: policy.retire_phone(key, deliver=False),
        push_cleanup_pending=lambda key: bool(policy.pending_retirements(key.hex())),
        deliver_retirements=policy.retry_retirements)

    started = time.monotonic()
    result = management.revoke(PHONE.hex())
    assert time.monotonic() - started < 2
    assert result["removed"] is True and result["pending_cleanup"] is True
    assert relay.entered.wait(5)  # delivery runs, off the lock and off the caller

    outcome = {}
    other = threading.Thread(target=lambda: outcome.update(
        phones=management.answer({"op": "phones.list"}, OTHER)), daemon=True)
    other.start()
    other.join(2)
    assert not other.is_alive(), "another phone's call waited on relay HTTP"
    assert outcome["phones"]["phones"] == [{"name": "B", "is_this_phone": True}]

    relay.release.set()
    management.delivery_thread.join(10)
    assert relay.forgotten == ["phone-push"]
    assert policy.pending_retirements() == 0
