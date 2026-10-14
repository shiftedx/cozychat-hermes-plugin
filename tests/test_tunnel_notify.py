"""Local notifications over the production listener, Noise session and mux."""

import asyncio
import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest

from cozychat.events import Emitter
from cozychat.devices import DeviceStore
from cozychat.feed import LiveFeed
from cozychat.local_push import NotifySubscriptions, push_proof
from cozychat.push import Outbox
from cozychat.relay import noise, pairing, services
from cozychat.relay.host import Listener, ListenerConfig
from cozychat.relay.mux import INITIAL_WINDOW, SessionClose, StreamClose
from cozychat.relay.services import ApiTarget
from cozychat.state import SharedState
from tunnel_phone import Phone, loopback_binds


def run(coro, timeout=15):
    return asyncio.run(asyncio.wait_for(coro, timeout))


async def until(predicate, timeout=3):
    deadline = asyncio.get_running_loop().time() + timeout
    while not predicate():
        assert asyncio.get_running_loop().time() < deadline
        await asyncio.sleep(0.01)


class EmptyStore:
    def list(self):
        return []


class RecordingOutbox:
    def __init__(self):
        self.rows = []

    def enqueue(self, device_id, category, collapse_id, payload, *, level=None, now=None, **kwargs):
        self.rows.append((device_id, category, collapse_id, payload, level))


class Lines:
    def __init__(self, stream):
        self.stream = stream
        self.buffer = b""

    async def next(self, timeout=2):
        async def read():
            while b"\n" not in self.buffer:
                chunk = await self.stream.read()
                if not chunk:
                    raise EOFError
                self.buffer += chunk
            line, _, self.buffer = self.buffer.partition(b"\n")
            return json.loads(line)

        return await asyncio.wait_for(read(), timeout)


async def ack(stream, identifier):
    await stream.write(json.dumps({"op": "ack", "id": identifier}).encode() + b"\n")


def preapprove(store, private):
    """Approve through PairingStore's public state transitions, without editing its files."""
    window = store.open_window({"push": False})
    attempt = store.begin_attempt(window.id, noise.public_key(private), "Test phone", "000000")
    assert attempt is not None and store.decide(attempt, True)
    assert store.settle(attempt) == "approved"
    return window


async def connected(tmp_path, **config_overrides):
    state = SharedState(tmp_path / "shared")
    feed = LiveFeed(state)
    store = pairing.PairingStore(tmp_path / "relay")
    private = noise.generate_private_key()
    window = preapprove(store, private)
    config = ListenerConfig(port=0, interfaces=loopback_binds, advertise_mdns=False,
                            allowlist_poll_seconds=0.05, **config_overrides)
    capabilities = lambda hints: services.capability_document(
        plugin_version="0.6.0", state_version="shared-v1", lan_addresses=hints,
        push_available=False, push_paired=False, notify_available=True,
        api_profiles=("default", "luna"))
    listener = Listener(store, config, capabilities=capabilities,
                        api=lambda: ApiTarget(1, None, profiles=("default", "luna")), feed=feed)
    await listener.start()
    phone = Phone(pairing.pairing_link(store.host_public(), window, listener.hints()),
                  static_private=private)
    phone.approved = True
    await phone.connect()
    return state, feed, store, listener, phone


def emitter(feed, profile="luna", outbox=None, store=None, **config):
    settings = {"profile_name": profile, **config}
    return Emitter(store or EmptyStore(), outbox or RecordingOutbox(), settings, feed=feed)


def test_emitter_publishes_one_redacted_envelope_before_device_fanout(tmp_path):
    feed = LiveFeed(SharedState(tmp_path / "state"))
    outbox = RecordingOutbox()
    devices = type("Devices", (), {"list": lambda self: [
        {"device_id": "a", "filters": {}, "profile": "luna", "consent_version": 1},
        {"device_id": "b", "filters": {}, "profile": "luna", "consent_version": 1}]})()
    subject = emitter(feed, outbox=outbox, store=devices)
    subject.stream_delta(session_id="s1", delta="Home Wi-Fi reply", command="secret")
    subject.session_end(session_id="s1", platform="api_server", turn_id="t1")
    notifications = [frame for frame in feed.since(0) if frame["kind"] == "notify"]
    assert len(notifications) == 1 and len(outbox.rows) == 2
    envelope = notifications[0]["payload"]
    assert set(envelope) == {"v", "id", "category", "collapseId", "payload", "profile", "at"}
    assert envelope["v"] == 1 and envelope["category"] == "message"
    assert envelope["payload"] == {"kind": "message", "threadId": "bot:luna",
                                    "agentName": "luna", "preview": "Home Wi-Fi reply"}
    assert envelope["profile"] == "luna" and isinstance(envelope["at"], float)
    assert str(uuid.UUID(envelope["id"])) == envelope["id"]
    assert "secret" not in json.dumps(envelope)


def test_real_listener_delivers_without_apns_registration_and_does_not_replay_history(tmp_path):
    async def scenario():
        state, feed, _, listener, phone = await connected(tmp_path,
                                                          notify_heartbeat_seconds=10)
        subject = emitter(feed)
        subject.stream_delta(session_id="old", delta="offline reply")
        subject.session_end(session_id="old", platform="api_server", turn_id="old-turn")
        stream = await phone.mux.open("notify")
        lines = Lines(stream)
        try:
            assert await lines.next() == {"v": 1, "subscribed": True}
            with pytest.raises(asyncio.TimeoutError):
                await lines.next(timeout=0.15)
            feed.publish("message.delta", source="session", payload={"text": "ignored"})
            subject.stream_delta(session_id="live", delta="Home Wi-Fi reply")
            subject.session_end(session_id="live", platform="api_server", turn_id="live-turn")
            envelope = await lines.next()
            assert envelope["payload"]["preview"] == "Home Wi-Fi reply"
            assert envelope["profile"] == "luna"
            await ack(stream, envelope["id"])
            assert phone.payload["services"]["notify"] == {"version": 1}
            assert phone.payload["features"]["local_push"] == {"available": True}
            assert phone.payload["features"]["push"] == {"available": False, "paired": False}
        finally:
            await phone.close()
            await listener.stop()
            state.close()

    run(scenario())


def test_subscription_filters_and_profile_are_enforced(tmp_path):
    async def scenario():
        state, feed, _, listener, phone = await connected(tmp_path,
                                                          notify_heartbeat_seconds=10)
        stream = await phone.mux.open("notify", {
            "profile": "luna", "replies": False, "approvals": True,
            "rooms": False, "subagents": False})
        lines = Lines(stream)
        try:
            assert (await lines.next())["subscribed"] is True
            now = 1234.0
            for source, profile in (("replies", "luna"), ("approvals", "default"),
                                    ("rooms", "luna"), ("subagents", "luna")):
                feed.publish("notify", source="notify:" + source,
                             payload={"v": 1, "id": str(uuid.uuid4()), "category": "message",
                                      "collapseId": source, "payload": {"kind": "message"},
                                      "profile": profile, "at": now})
            wanted = {"v": 1, "id": str(uuid.uuid4()), "category": "approval.pending",
                      "collapseId": "approval", "payload": {"kind": "approval_pending"},
                      "profile": "luna", "at": now}
            feed.publish("notify", source="notify:approvals", payload=wanted)
            assert await lines.next() == wanted
            with pytest.raises(asyncio.TimeoutError):
                await lines.next(timeout=0.15)
        finally:
            await phone.close()
            await listener.stop()
            state.close()

    run(scenario())


def test_invalid_oversized_and_duplicate_subscriptions_are_refused(tmp_path):
    async def scenario():
        state, _, _, listener, phone = await connected(tmp_path,
                                                       notify_heartbeat_seconds=10)
        try:
            for args in ({"unknown": True}, {"replies": "yes"}, {"profile": "missing"},
                         {"profile": "x" * services.MAX_NOTIFY_LINE}):
                stream = await phone.mux.open("notify", args)
                await until(lambda: stream.closed)
                assert stream.close_code == StreamClose.POLICY
            first = await phone.mux.open("notify")
            assert (await Lines(first).next())["subscribed"] is True
            duplicate = await phone.mux.open("notify")
            await until(lambda: duplicate.closed)
            assert duplicate.close_code == StreamClose.POLICY
        finally:
            await phone.close()
            await listener.stop()
            state.close()

    run(scenario())


def test_heartbeat_ack_keeps_stream_alive_and_a_missing_ack_closes_it(tmp_path):
    async def scenario():
        state, _, _, listener, phone = await connected(
            tmp_path, notify_heartbeat_seconds=0.08, notify_ack_timeout_seconds=0.2)
        stream = await phone.mux.open("notify")
        lines = Lines(stream)
        try:
            assert (await lines.next())["subscribed"] is True
            first = await lines.next()
            assert set(first) == {"v", "heartbeat"}
            await ack(stream, first["heartbeat"])
            second = await lines.next()
            assert second["heartbeat"] != first["heartbeat"]
            await until(lambda: stream.closed, timeout=1)
            assert stream.close_code == StreamClose.NORMAL
        finally:
            await phone.close()
            await listener.stop()
            state.close()

    run(scenario())


@pytest.mark.parametrize("receipt", [b'{}\n', b"x" * (services.MAX_NOTIFY_LINE + 1)])
def test_invalid_and_oversized_receipts_close_the_stream(tmp_path, receipt):
    async def scenario():
        state, _, _, listener, phone = await connected(tmp_path,
                                                       notify_heartbeat_seconds=10)
        stream = await phone.mux.open("notify")
        try:
            assert (await Lines(stream).next())["subscribed"] is True
            await stream.write(receipt)
            await until(lambda: stream.closed)
            assert stream.close_code == StreamClose.POLICY
        finally:
            await phone.close()
            await listener.stop()
            state.close()

    run(scenario())


def test_slow_reader_is_credit_bounded_and_closing_cancels_the_service(tmp_path):
    async def scenario():
        state, feed, _, listener, phone = await connected(tmp_path,
                                                          notify_heartbeat_seconds=10)
        stream = await phone.mux.open("notify")
        lines = Lines(stream)
        assert (await lines.next())["subscribed"] is True
        host_mux = next(iter(listener._sessions))
        host_stream = next(value for value in host_mux._streams.values()
                           if value.service == "notify")
        try:
            for index in range(100):
                feed.publish("notify", source="notify:replies", payload={
                    "v": 1, "id": str(uuid.uuid4()), "category": "message",
                    "collapseId": str(index),
                    "payload": {"kind": "message", "preview": "x" * 7000},
                    "profile": "luna", "at": 1.0})
            await until(lambda: host_stream.bytes_sent == INITIAL_WINDOW)
            assert host_stream.send_credit == 0
            await stream.close()
            await until(lambda: host_stream.closed and host_stream.id not in host_mux._stream_tasks)
        finally:
            await phone.close()
            await listener.stop()
            state.close()

    run(scenario())


def test_revocation_closes_the_notify_session(tmp_path):
    async def scenario():
        state, _, store, listener, phone = await connected(tmp_path,
                                                           notify_heartbeat_seconds=10)
        stream = await phone.mux.open("notify")
        try:
            assert (await Lines(stream).next())["subscribed"] is True
            assert store.remove_phone(phone.static_public)
            await asyncio.wait_for(phone.mux.done.wait(), 2)
            assert phone.mux.remote_close_code == SessionClose.REVOKED
            assert stream.closed
        finally:
            await phone.close()
            await listener.stop()
            state.close()

    run(scenario())


def test_unapproved_session_cannot_subscribe(tmp_path):
    async def scenario():
        state = SharedState(tmp_path / "shared")
        feed = LiveFeed(state)
        store = pairing.PairingStore(tmp_path / "relay")
        window = store.open_window()
        listener = Listener(store, ListenerConfig(port=0, interfaces=loopback_binds,
                                                   advertise_mdns=False),
                            capabilities=lambda hints: {}, api=lambda: ApiTarget(1, None),
                            feed=feed)
        await listener.start()
        phone = Phone(pairing.pairing_link(store.host_public(), window, listener.hints()))
        await phone.handshake()
        stream = await phone.mux.open("notify")
        phone._tasks.append(asyncio.ensure_future(phone.mux.run()))
        try:
            await until(lambda: stream.closed)
            assert stream.close_code == StreamClose.POLICY
        finally:
            await phone.close()
            await listener.stop()
            state.close()

    run(scenario())


@pytest.mark.parametrize("subscribed,opted_in", [(True, True), (False, True),
                                                (True, False), (False, False)])
def test_notification_dispatch_prefers_this_phones_subscription(tmp_path, subscribed, opted_in):
    async def scenario():
        state, feed, _, listener, phone = await connected(tmp_path, notify_heartbeat_seconds=10)
        devices = DeviceStore(state.root)
        key = b"this-phone-push-key"
        if opted_in:
            devices.add({"device_id": "this-phone", "push_id": "push-this-phone", "key_hex": key.hex(),
                         "profile": "luna", "consent_version": 1})
        outbox = Outbox(state.root / "outbox.sqlite")
        calls = []
        relay = type("Relay", (), {"notify": lambda self, *args: (calls.append(args) or (202, None))})()
        stream = None
        try:
            if subscribed:
                stream = await phone.mux.open("notify", {"profile": "luna", "push_proofs": {
                    "luna": push_proof(key, phone.static_public, "luna")}})
                assert (await Lines(stream).next())["subscribed"] is True
            # A second handle sees the listener's leases: hooks need not share its process.
            gateway_state = SharedState(state.root)
            try:
                subject = emitter(LiveFeed(gateway_state), outbox=outbox, store=devices)
                subject.cron_send("first", "At home")
                outbox.drain(relay, devices)
                assert len(calls) == int(opted_in and not subscribed)
            finally:
                gateway_state.close()
            if stream is not None:
                await stream.close()
                await until(lambda: stream.id not in next(iter(listener._sessions))._stream_tasks)
                emitter(feed, outbox=outbox, store=devices).cron_send("away", "Away from home")
                outbox.drain(relay, devices)
                # New events resume at once, and the first, never acknowledged, is released too.
                assert len(calls) == 2 * int(opted_in)
                reopened = await phone.mux.open("notify")
                assert (await Lines(reopened).next())["subscribed"] is True
        finally:
            await phone.close()
            await listener.stop()
            outbox.close()
            state.close()

    run(scenario())


def test_subscription_suppression_is_per_device_profile_and_filter(tmp_path):
    async def scenario():
        state, feed, _, listener, phone = await connected(tmp_path, notify_heartbeat_seconds=10)
        devices = DeviceStore(state.root)
        for name in ("a", "b"):
            devices.add({"device_id": name, "push_id": "push-" + name,
                         "key_hex": ("key-" + name).encode().hex(),
                         "profile": "luna", "consent_version": 1})
        stream = await phone.mux.open("notify", {"profile": "luna", "replies": False,
            "push_proofs": {"luna": push_proof(b"key-a", phone.static_public, "luna")}})
        outbox = RecordingOutbox()
        try:
            assert (await Lines(stream).next())["subscribed"] is True
            emitter(feed, outbox=outbox, store=devices).approval_pending(tool_call_id="tool")
            assert [row[0] for row in outbox.rows] == ["b"]
            outbox.rows.clear()
            emitter(feed, outbox=outbox, store=devices).cron_send("reply", "Unsubscribed filter")
            assert [row[0] for row in outbox.rows] == ["a", "b"]
            outbox.rows.clear()
            emitter(feed, profile="default", outbox=outbox, store=devices).approval_pending(tool_call_id="other")
            # D27: consent is per profile; these phones consented only for luna.
            assert outbox.rows == []
        finally:
            await phone.close()
            await listener.stop()
            state.close()

    run(scenario())


def test_push_proof_cannot_claim_another_phone_or_profile(tmp_path):
    state = SharedState(tmp_path)
    subscriptions = NotifySubscriptions(state)
    devices = DeviceStore(tmp_path)
    devices.add({"device_id": "a", "push_id": "push-a", "key_hex": b"key-a".hex(),
                 "profile": "luna", "consent_version": 1})
    try:
        proof = push_proof(b"key-a", b"a" * 32, "luna")
        assert subscriptions.bindings({"luna": proof}, b"a" * 32) == [("a", "luna")]
        assert subscriptions.bindings({"luna": proof}, b"b" * 32) == []
        assert subscriptions.bindings({"default": proof}, b"a" * 32) == []
        assert subscriptions.bindings({"luna": "0" * 64}, b"a" * 32) == []
    finally:
        state.close()


def test_close_withdraws_suppression_at_once_and_crash_leases_expire(tmp_path):
    state = SharedState(tmp_path)
    subscriptions = NotifySubscriptions(state)
    try:
        subscriptions.refresh("subscription", [("phone", "luna")], {"replies": True}, 10, now=100)
        assert subscriptions.covers("phone", "luna", "replies", 11, now=101)
        assert not subscriptions.covers("phone", "luna", "replies", 10, now=101)
        assert not subscriptions.covers("phone", "luna", "replies", 11, now=107)
        subscriptions.close("subscription", now=101)
        assert not subscriptions.covers("phone", "luna", "replies", 11, now=101)
    finally:
        state.close()


def test_held_event_is_discharged_by_ack_and_released_on_timeout_or_close(tmp_path):
    state = SharedState(tmp_path)
    subscriptions = NotifySubscriptions(state)
    outbox = RecordingOutbox()
    try:
        subscriptions.refresh("s", [("phone", "luna")], {"replies": True}, 0, now=100)
        for event in ("acked", "late", "dropped"):
            assert subscriptions.hold("phone", "luna", "replies", 1, event, "message", event, {"n": event},
                                      None, now=100, fallback_seconds=10)
        subscriptions.acknowledge("s", "acked")
        assert subscriptions.release_due(outbox, now=105) == 0 and outbox.rows == []
        subscriptions.acknowledge("other-subscription", "late")  # Not this stream's event.
        assert subscriptions.release_due(outbox, now=111) == 2
        assert sorted(row[2] for row in outbox.rows) == ["dropped", "late"]
        outbox.rows.clear()
        subscriptions.refresh("s", [("phone", "luna")], {"replies": True}, 0, now=112)
        assert subscriptions.hold("phone", "luna", "replies", 1, "gone", "message", "gone", {}, None, now=112)
        subscriptions.close("s", now=113)
        assert not subscriptions.hold("phone", "luna", "replies", 1, "after", "message", "after", {},
                                      None, now=113)
        assert subscriptions.release(outbox, "s") == 1 and [r[2] for r in outbox.rows] == ["gone"]
        assert subscriptions.release_due(outbox, now=999) == 0
    finally:
        state.close()


def test_real_listener_acked_event_has_no_relay_fallback_but_unacked_one_falls_back(tmp_path):
    async def scenario():
        state, feed, _, listener, phone = await connected(tmp_path, notify_heartbeat_seconds=10)
        devices = DeviceStore(state.root)
        key = b"this-phone-push-key"
        devices.add({"device_id": "this-phone", "push_id": "push-this-phone", "key_hex": key.hex(),
                         "profile": "luna", "consent_version": 1})
        outbox = RecordingOutbox()
        stream = await phone.mux.open("notify", {"profile": "luna", "push_proofs": {
            "luna": push_proof(key, phone.static_public, "luna")}})
        lines = Lines(stream)
        try:
            assert (await lines.next())["subscribed"] is True
            subject = emitter(feed, outbox=outbox, store=devices)
            subject.cron_send("one", "Delivered")
            await ack(stream, (await lines.next())["id"])
            subject.cron_send("two", "Not acknowledged")
            assert (await lines.next())["payload"]["preview"] == "Not acknowledged"
            await asyncio.sleep(0.3)
            assert outbox.rows == []
            await stream.close()
            await until(lambda: len(rows(state)) == 1)
            queued = rows(state)
            assert queued[0][0] == "this-phone" and "Not acknowledged" in queued[0][1]
        finally:
            await phone.close()
            await listener.stop()
            state.close()

    def rows(state):
        outbox = Outbox(state.root / "outbox.sqlite")
        try:
            return outbox._connect().execute("SELECT device_id, payload FROM pending").fetchall()
        finally:
            outbox.close()

    run(scenario())


def test_subscribed_phone_without_away_push_registration_never_reaches_the_relay(tmp_path):
    async def scenario():
        state, feed, _, listener, phone = await connected(tmp_path, notify_heartbeat_seconds=10)
        devices = DeviceStore(state.root)  # no registration for this phone
        outbox = RecordingOutbox()
        stream = await phone.mux.open("notify", {"profile": "luna"})
        try:
            assert (await Lines(stream).next())["subscribed"] is True
            emitter(feed, outbox=outbox, store=devices).cron_send("local", "Home only")
            await stream.close()
            await asyncio.sleep(0.3)
            with state.read() as db:
                assert db.execute("SELECT COUNT(*) FROM notify_pending").fetchone()[0] == 0
            assert outbox.rows == []
        finally:
            await phone.close()
            await listener.stop()
            state.close()

    run(scenario())


def test_continuous_events_without_heartbeat_receipts_withdraw_suppression(tmp_path):
    async def scenario():
        state, feed, _, listener, phone = await connected(
            tmp_path, notify_heartbeat_seconds=0.1, notify_ack_timeout_seconds=0.4)
        devices = DeviceStore(state.root)
        key = b"this-phone-push-key"
        devices.add({"device_id": "this-phone", "push_id": "push-this-phone", "key_hex": key.hex(),
                         "profile": "luna", "consent_version": 1})
        stream = await phone.mux.open("notify", {"profile": "luna", "push_proofs": {
            "luna": push_proof(key, phone.static_public, "luna")}})
        outbox = RecordingOutbox()
        subject = emitter(feed, outbox=outbox, store=devices)
        subscriptions = NotifySubscriptions(state)
        try:
            assert (await Lines(stream).next())["subscribed"] is True
            loop = asyncio.get_running_loop()
            started = loop.time()
            covered = lambda: subscriptions.covers("this-phone", "luna", "replies",
                                                   int(feed.state()["seq"]) + 1)
            assert covered()
            while not stream.closed:  # Event traffic never renews suppression, and the phone is mute.
                subject.cron_send(f"event-{loop.time()}", "Still streaming")
                await asyncio.sleep(0.05)
                assert loop.time() - started < 3
            assert not covered()
            assert stream.close_code == StreamClose.NORMAL
            assert loop.time() - started < 1.5
        finally:
            await phone.close()
            await listener.stop()
            state.close()

    run(scenario())


def test_valid_receipt_followed_by_oversized_unterminated_tail_closes_stream(tmp_path):
    async def scenario():
        state, _, _, listener, phone = await connected(tmp_path, notify_heartbeat_seconds=10)
        stream = await phone.mux.open("notify")
        try:
            assert (await Lines(stream).next())["subscribed"] is True
            receipt = json.dumps({"op": "ack", "id": str(uuid.uuid4())}).encode() + b"\n"
            await stream.write(receipt + b"x" * 9000)
            await until(lambda: stream.closed)
            assert stream.close_code == StreamClose.POLICY
        finally:
            await phone.close()
            await listener.stop()
            state.close()

    run(scenario())


def test_opening_subscription_cannot_race_relay_enqueue_between_cursor_and_lease(tmp_path):
    listener_state, gateway_state = SharedState(tmp_path), SharedState(tmp_path)
    subscriptions = NotifySubscriptions(listener_state)
    devices = type("Devices", (), {"list": lambda self: [{"device_id": "phone", "filters": {}, "profile": "luna", "consent_version": 1}]})()
    outbox = RecordingOutbox()
    subject = emitter(LiveFeed(gateway_state), outbox=outbox, store=devices)
    selected, release, publishing = threading.Event(), threading.Event(), threading.Event()

    def trace(sql):
        if sql.startswith("SELECT COALESCE(MAX(seq)"):
            selected.set()
            assert release.wait(3)

    def publish():
        publishing.set()
        return subject.cron_send("opening", "Concurrent event")

    with listener_state.read() as db:
        db.set_trace_callback(trace)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            opened = pool.submit(subscriptions.refresh, "subscription", [("phone", "luna")],
                                 {"replies": True})
            try:
                assert selected.wait(2)
                event = pool.submit(publish)
                assert publishing.wait(2)
                assert not event.done()
            finally:
                release.set()
            assert opened.result(timeout=3) == 0
            assert event.result(timeout=3) == 1
            assert outbox.rows == []
    finally:
        listener_state.close()
        gateway_state.close()


@pytest.mark.parametrize("proofs", [None, [], {"missing": "0" * 64}, {"luna": "x" * 64},
                                     {"luna": 1}, {"default": "0" * 64}])
def test_invalid_push_proofs_are_rejected(proofs):
    filters, _ = services._notify_args({"profile": "luna", "push_proofs": proofs},
                                      ApiTarget(1, None, profiles=("default", "luna")))
    assert filters is None

