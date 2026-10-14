"""The outbox: coalescing, backoff, the daily cap, retention, and what the relay receives."""

import json

from cozychat import push
from cozychat.devices import DeviceStore

KEY = b"test-push-key"
PAYLOAD = {"kind": "message", "threadId": "bot:hermes", "agentName": "hermes", "preview": "hi"}


class FakeRelay:
    """Records every notify and replies with a scripted status."""

    def __init__(self, *statuses):
        self.statuses = list(statuses)
        self.calls = []

    def notify(self, push_id, ciphertext, category, collapse_id, interruption_level=None):
        self.calls.append({"push_id": push_id, "ciphertext": ciphertext, "category": category,
                           "collapse_id": collapse_id, "level": interruption_level})
        return self.statuses.pop(0) if self.statuses else (202, None)


def paired(tmp_path):
    store = DeviceStore(tmp_path)
    store.add({"device_id": "phone-1", "push_id": "push-abc", "key_hex": KEY.hex(),
               "profile": "default", "consent_version": 1})
    return store


class ConsentOutbox(push.Outbox):
    """The ordinary outbox tests describe already-consented test fixtures."""
    def enqueue(self, *args, **kwargs):
        kwargs.setdefault("profile", "default")
        kwargs.setdefault("consent_version", 1)
        return super().enqueue(*args, **kwargs)


def outbox(tmp_path):
    return ConsentOutbox(tmp_path / "outbox.sqlite")


def test_an_unused_outbox_creates_no_file(tmp_path):
    subject = outbox(tmp_path)
    assert subject.drain(FakeRelay(), paired(tmp_path)) == 0
    assert not (tmp_path / "outbox.sqlite").exists()


def test_a_drained_row_reaches_the_relay_sealed_for_that_device(tmp_path):
    store, subject, relay = paired(tmp_path), outbox(tmp_path), FakeRelay((202, None))
    subject.enqueue("phone-1", "message", "collapse-1", PAYLOAD, level="active")
    assert subject.drain(relay, store) == 1
    (call,) = relay.calls
    assert call["push_id"] == "push-abc"
    assert call["category"] == "message" and call["collapse_id"] == "collapse-1"
    assert call["level"] == "active"
    assert push.open_sealed(KEY, call["ciphertext"]) == PAYLOAD
    assert subject.drain(relay, store) == 0  # the row is gone, not resent


def test_a_second_payload_on_one_collapse_id_replaces_the_first(tmp_path):
    store, subject, relay = paired(tmp_path), outbox(tmp_path), FakeRelay()
    subject.enqueue("phone-1", "message", "collapse-1", PAYLOAD, now=1000.0)
    subject.enqueue("phone-1", "message", "collapse-1", dict(PAYLOAD, preview="later"), now=1003.0)
    subject.drain(relay, store, now=1004.0)
    assert len(relay.calls) == 1
    assert push.open_sealed(KEY, relay.calls[0]["ciphertext"])["preview"] == "later"


def test_past_the_coalesce_window_the_second_is_its_own_notify(tmp_path):
    store, subject, relay = paired(tmp_path), outbox(tmp_path), FakeRelay()
    late = 1000.0 + push.COALESCE_SECONDS + 1
    subject.enqueue("phone-1", "message", "collapse-1", PAYLOAD, now=1000.0)
    subject.enqueue("phone-1", "message", "collapse-1", PAYLOAD, now=late)
    assert subject.drain(relay, store, now=late) == 2


def test_different_collapse_ids_never_coalesce(tmp_path):
    store, subject, relay = paired(tmp_path), outbox(tmp_path), FakeRelay()
    subject.enqueue("phone-1", "message", "collapse-1", PAYLOAD, now=1000.0)
    subject.enqueue("phone-1", "message", "collapse-2", PAYLOAD, now=1000.0)
    assert subject.drain(relay, store, now=1000.0) == 2


def test_a_429_keeps_the_row_and_waits_out_retry_after(tmp_path):
    store, subject = paired(tmp_path), outbox(tmp_path)
    subject.enqueue("phone-1", "message", "collapse-1", PAYLOAD, now=1000.0)
    assert subject.drain(FakeRelay((429, 60.0)), store, now=1000.0) == 0
    assert subject.drain(FakeRelay(), store, now=1059.0) == 0  # still deferred
    assert subject.drain(FakeRelay(), store, now=1061.0) == 1


def test_backoff_grows_with_each_attempt(tmp_path):
    store, subject = paired(tmp_path), outbox(tmp_path)
    subject.enqueue("phone-1", "message", "collapse-1", PAYLOAD, now=1000.0)
    subject.drain(FakeRelay((500, None)), store, now=1000.0)   # attempt 1 -> +1s
    subject.drain(FakeRelay((500, None)), store, now=1002.0)   # attempt 2 -> +2s
    assert subject.drain(FakeRelay(), store, now=1003.0) == 0
    assert subject.drain(FakeRelay(), store, now=1005.0) == 1


def test_a_transport_failure_is_retried_but_a_rejection_is_dropped(tmp_path):
    store, subject = paired(tmp_path), outbox(tmp_path)
    subject.enqueue("phone-1", "message", "unreachable", PAYLOAD, now=1000.0)
    subject.drain(FakeRelay((0, None)), store, now=1000.0)
    assert subject.drain(FakeRelay(), store, now=2000.0) == 1  # the unreachable one came back

    subject.enqueue("phone-1", "message", "rejected", PAYLOAD, now=2000.0)
    subject.drain(FakeRelay((400, None)), store, now=2000.0)
    assert subject.drain(FakeRelay(), store, now=3000.0) == 0  # a rejection is not retried


def test_a_row_for_an_unpaired_device_is_dropped(tmp_path):
    subject, relay = outbox(tmp_path), FakeRelay()
    subject.enqueue("ghost", "message", "collapse-1", PAYLOAD)
    assert subject.drain(relay, DeviceStore(tmp_path)) == 0
    assert subject.drain(relay, paired(tmp_path)) == 0  # not waiting for a re-pair either
    assert relay.calls == []


def test_rows_older_than_the_retention_window_are_dropped(tmp_path):
    store, subject, relay = paired(tmp_path), outbox(tmp_path), FakeRelay()
    subject.enqueue("phone-1", "message", "collapse-1", PAYLOAD, now=1000.0)
    assert subject.drain(relay, store, now=1000.0 + push.RETENTION_SECONDS + 1) == 0
    assert relay.calls == []


def test_past_the_daily_threshold_the_device_gets_one_digest_then_silence(tmp_path):
    store, subject = paired(tmp_path), outbox(tmp_path)
    relay = FakeRelay()
    now = 1_700_000_000.0
    for i in range(push.DAILY_DIGEST_THRESHOLD + 3):
        subject.enqueue("phone-1", "message", f"collapse-{i}", PAYLOAD, now=now)
        subject.drain(relay, store, now=now)
    assert len(relay.calls) == push.DAILY_DIGEST_THRESHOLD + 1
    digest = relay.calls[-1]
    assert digest["collapse_id"].startswith("digest:")
    assert "notifications" in push.open_sealed(KEY, digest["ciphertext"])["preview"]


def test_the_queue_survives_a_restart(tmp_path):
    store = paired(tmp_path)
    first = outbox(tmp_path)
    first.enqueue("phone-1", "message", "collapse-1", PAYLOAD)
    first.close()
    relay = FakeRelay()
    assert outbox(tmp_path).drain(relay, store) == 1
    assert json.loads(json.dumps(PAYLOAD)) == push.open_sealed(KEY, relay.calls[0]["ciphertext"])


def test_a_rate_limited_daily_digest_is_retried_after_restart(tmp_path, monkeypatch):
    monkeypatch.setattr(push, "DAILY_DIGEST_THRESHOLD", 1)
    store, subject = paired(tmp_path), outbox(tmp_path)
    relay = FakeRelay((202, None), (429, 60.0), (202, None))
    now = 1_700_000_000.0
    subject.enqueue("phone-1", "message", "first", PAYLOAD, now=now)
    assert subject.drain(relay, store, now=now) == 1
    subject.enqueue("phone-1", "message", "second", PAYLOAD, now=now)
    assert subject.drain(relay, store, now=now) == 0
    subject.close()
    subject = outbox(tmp_path)
    assert subject.drain(relay, store, now=now + 59) == 0
    assert subject.drain(relay, store, now=now + 60) == 1
    assert [call["collapse_id"] for call in relay.calls[1:]] == ["digest:2023-11-14"] * 2
    subject.enqueue("phone-1", "message", "third", PAYLOAD, now=now + 61)
    assert subject.drain(relay, store, now=now + 61) == 0
    assert len(relay.calls) == 3


def test_a_payload_coalesced_during_its_own_send_is_not_thrown_away(tmp_path):
    """The live check's lost approval: an approval's `resolved` push coalesced into the `pending`
    row while the drain thread was inside relay.notify for it, and the unguarded delete-by-id took
    the newer payload with the old one. It must survive to the next drain instead."""
    store, subject = paired(tmp_path), outbox(tmp_path)

    class CoalescingRelay(FakeRelay):
        def notify(self, *args, **kwargs):
            if not self.calls:   # only during the first send, as a hook thread would
                subject.enqueue("phone-1", "approval.resolved", "call-7",
                                dict(PAYLOAD, kind="approval_resolved"))
            return super().notify(*args, **kwargs)

    relay = CoalescingRelay()
    subject.enqueue("phone-1", "approval.pending", "call-7", dict(PAYLOAD, kind="approval_pending"))
    assert subject.drain(relay, store) == 1
    assert subject.drain(relay, store) == 1
    assert [push.open_sealed(KEY, c["ciphertext"])["kind"] for c in relay.calls] \
        == ["approval_pending", "approval_resolved"]


def test_the_relay_client_names_itself_to_the_relay():
    # Cloudflare's Browser Integrity Check answers urllib's default signature with error 1010, a
    # terminal 403 the outbox would drop the push on; the client therefore always carries a name.
    seen = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self):
            return b"{}"

    def opener(request, timeout):
        seen.append(request)
        return Response()

    relay = push.Relay("https://relay.example", opener=opener)
    relay.notify("pid", "ct", "message", "c")
    relay.forget("pid")
    assert [r.get_header("User-agent") for r in seen] == [push.USER_AGENT, push.USER_AGENT]
