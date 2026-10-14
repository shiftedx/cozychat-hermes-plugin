"""What each hook turns into, and what redaction refuses to carry."""

import hashlib

import pytest

from cozychat import privacy
from cozychat.events import DELIVERED_TURNS_LIMIT, Emitter


class FakeStore:
    def __init__(self, *devices):
        self.devices = list(devices)

    def list(self):
        return self.devices


class FakeOutbox:
    def __init__(self):
        self.rows = []

    def enqueue(self, device_id, category, collapse_id, payload, *, level=None, profile="",
                consent_version=0, now=None):
        self.rows.append({"device_id": device_id, "category": category,
                          "collapse_id": collapse_id, "payload": payload, "level": level,
                          "profile": profile, "consent_version": consent_version})


def phone(device_id="phone-1", **filters):
    return {"device_id": device_id, "push_id": "push-" + device_id, "filters": filters,
            "profile": "luna", "consent_version": 1}


def emitter(*devices, **config):
    outbox = FakeOutbox()
    settings = {"profile_name": "luna"}
    settings.update(config)
    return Emitter(FakeStore(*(devices or (phone(),))), outbox, settings), outbox


# -- direct chats --------------------------------------------------------

def test_a_finished_reply_becomes_one_message_notify():
    subject, outbox = emitter()
    subject.stream_end(session_id="s1", final_text="The build is green.")
    subject.session_end(session_id="s1", platform="cli", interrupted=False)
    (row,) = outbox.rows
    assert row["category"] == "message"
    assert row["collapse_id"] == hashlib.sha256(b"s1").hexdigest()
    assert row["payload"] == {"kind": "message", "threadId": "bot:luna",
                              "agentName": "luna", "preview": "The build is green."}


def test_a_session_that_streamed_nothing_says_nothing():
    subject, outbox = emitter()
    subject.session_end(session_id="s1", platform="cli")
    assert outbox.rows == []


def test_the_api_server_path_previews_the_deltas_when_final_text_is_empty():
    # Hermes' API Server ends the stream with final_text="" because the reply went out as deltas.
    subject, outbox = emitter()
    subject.stream_start(session_id="s1")
    for word in ("push", " test", " received"):
        subject.stream_delta(session_id="s1", delta=word)
    subject.stream_end(session_id="s1", final_text="", finished=True)
    subject.session_end(session_id="s1", platform="cli")
    (row,) = outbox.rows
    assert row["category"] == "message"
    assert row["payload"]["preview"] == "push test received"


def test_a_new_stream_in_the_same_session_replaces_the_previous_deltas():
    subject, outbox = emitter()
    subject.stream_start(session_id="s1")
    subject.stream_delta(session_id="s1", delta="thinking out loud")
    subject.stream_start(session_id="s1")
    subject.stream_delta(session_id="s1", delta="the answer")
    subject.stream_end(session_id="s1", final_text="", finished=True)
    subject.session_end(session_id="s1", platform="cli")
    (row,) = outbox.rows
    assert row["payload"]["preview"] == "the answer"


def test_the_held_preview_stays_bounded_however_long_the_reply_runs():
    subject, _ = emitter()
    subject.stream_start(session_id="s1")
    for _ in range(500):
        subject.stream_delta(session_id="s1", delta="word ")
    assert len(subject._previews["s1"]) <= privacy.PREVIEW_LIMIT + 5


def test_the_preview_is_not_reused_by_the_next_session_end():
    subject, outbox = emitter()
    subject.stream_end(session_id="s1", final_text="done")
    subject.session_end(session_id="s1", platform="cli")
    subject.session_end(session_id="s1", platform="cli")
    assert len(outbox.rows) == 1


def test_a_tool_calling_turns_extra_session_end_firings_do_not_repush():
    # Live 2026-09-15 `frames` evidence (session api_1789498764_a3b7efb8, turn 63163596): a
    # two-tool-call turn is stream.started/ended (no delta — a tool decision), tool.started/
    # completed, stream.started/ended (no delta — a second tool decision), tool.started/completed,
    # stream.started/DELTAS/ended (the actual reply) — then the outbox's `sent` counter rose by
    # THREE, not one. `on_session_end` fires once per model iteration on the API Server surface,
    # not once for the whole turn, and every iteration of ONE turn carries the same turn_id.
    subject, outbox = emitter()
    subject.stream_start(session_id="s1")
    subject.stream_end(session_id="s1", final_text="", finished=False)  # tool decision 1, no delta
    subject.session_end(session_id="s1", platform="api_server", turn_id="t1")  # extra firing 1
    subject.tool_started(tool_name="terminal", session_id="s1")
    subject.tool_completed(tool_name="terminal", session_id="s1")
    subject.stream_start(session_id="s1")
    subject.stream_end(session_id="s1", final_text="", finished=False)  # tool decision 2, no delta
    subject.session_end(session_id="s1", platform="api_server", turn_id="t1")  # extra firing 2
    subject.tool_started(tool_name="terminal", session_id="s1")
    subject.tool_completed(tool_name="terminal", session_id="s1")
    subject.stream_start(session_id="s1")
    subject.stream_delta(session_id="s1", delta="The build is green.")
    subject.stream_end(session_id="s1", final_text="", finished=True)
    subject.session_end(session_id="s1", platform="api_server", turn_id="t1")  # the real end
    (row,) = outbox.rows
    assert row["payload"]["preview"] == "The build is green."


def test_a_new_turn_in_the_same_session_still_pushes():
    subject, outbox = emitter()
    subject.stream_end(session_id="s1", final_text="first reply")
    subject.session_end(session_id="s1", platform="cli", turn_id="t1")
    subject.stream_end(session_id="s1", final_text="second reply")
    subject.session_end(session_id="s1", platform="cli", turn_id="t2")
    assert [row["payload"]["preview"] for row in outbox.rows] == ["first reply", "second reply"]


def test_the_delivered_turn_memory_is_bounded_and_evicts_the_oldest():
    # The gateway process runs for weeks, so one entry per distinct session is unbounded growth.
    subject, outbox = emitter()
    for index in range(DELIVERED_TURNS_LIMIT + 10):
        subject.stream_end(session_id=f"s{index}", final_text="done")
        subject.session_end(session_id=f"s{index}", platform="cli", turn_id="t1")
    assert len(outbox.rows) == DELIVERED_TURNS_LIMIT + 10
    assert len(subject._delivered_turns) == DELIVERED_TURNS_LIMIT
    # Oldest-first: the first sessions are gone, the newest are still remembered.
    assert "s0" not in subject._delivered_turns
    assert f"s{DELIVERED_TURNS_LIMIT + 9}" in subject._delivered_turns


def test_eviction_never_drops_the_turn_that_is_still_firing():
    # The extra `session_end` firings arrive AFTER the one that would pop the entry, so the entry
    # for the session being delivered right now must be the LAST thing eviction would reach.
    subject, outbox = emitter()
    for index in range(DELIVERED_TURNS_LIMIT):
        subject.stream_end(session_id=f"s{index}", final_text="done")
        subject.session_end(session_id=f"s{index}", platform="cli", turn_id="t1")
    # Full, so the next delivery evicts in the same call it records.
    assert len(subject._delivered_turns) == DELIVERED_TURNS_LIMIT
    subject.stream_end(session_id="live", final_text="The build is green.")
    subject.session_end(session_id="live", platform="api_server", turn_id="t1")
    before = len(outbox.rows)
    subject.stream_end(session_id="live", final_text="The build is green.")
    subject.session_end(session_id="live", platform="api_server", turn_id="t1")  # extra firing
    assert len(outbox.rows) == before


def test_an_interrupted_turn_says_nothing():
    subject, outbox = emitter()
    subject.stream_end(session_id="s1", final_text="half a th")
    subject.session_end(session_id="s1", platform="cli", interrupted=True)
    assert outbox.rows == []


@pytest.mark.parametrize("platform", ["telegram", "Discord", "slack", "whatsapp"])
def test_a_platform_that_notifies_natively_gets_no_second_banner(platform):
    subject, outbox = emitter()
    subject.stream_end(session_id="s1", final_text="done")
    subject.session_end(session_id="s1", platform=platform)
    assert outbox.rows == []


@pytest.mark.parametrize("session_id", ["cron_nightly", "kanban_42", "room_plumbing_7"])
def test_plumbing_sessions_are_not_conversations(session_id):
    subject, outbox = emitter()
    subject.stream_end(session_id=session_id, final_text="done")
    subject.session_end(session_id=session_id, platform="cli")
    assert outbox.rows == []


def test_the_phone_watching_this_run_in_the_foreground_is_skipped():
    subject, outbox = emitter(phone("watching", foreground_session="s1"), phone("idle"))
    subject.stream_end(session_id="s1", final_text="done")
    subject.session_end(session_id="s1", platform="cli")
    assert [row["device_id"] for row in outbox.rows] == ["idle"]


def test_preview_mode_none_sends_no_content():
    subject, outbox = emitter(preview_mode="none")
    subject.stream_end(session_id="s1", final_text="secret plan")
    subject.session_end(session_id="s1", platform="cli")
    assert outbox.rows[0]["payload"]["preview"] == "New activity"


def test_replies_can_be_turned_off_per_device_and_globally():
    subject, outbox = emitter(phone("phone-1", replies=False))
    subject.stream_end(session_id="s1", final_text="done")
    subject.session_end(session_id="s1", platform="cli")
    assert outbox.rows == []

    subject, outbox = emitter(push_replies=False)
    subject.stream_end(session_id="s1", final_text="done")
    subject.session_end(session_id="s1", platform="cli")
    assert outbox.rows == []


# -- approvals -----------------------------------------------------------

def test_an_opened_approval_names_the_rule_and_nothing_else():
    subject, outbox = emitter()
    subject.approval_pending(command="rm -rf /srv//data", description="delete the data dir",
                             pattern_key="terminal:rm", pattern_keys=["terminal:rm"],
                             session_key="cli:1", surface="cli", turn_id="t1",
                             tool_call_id="call-9", session_id="s1")
    (row,) = outbox.rows
    assert row["category"] == "approval.pending" and row["collapse_id"] == "call-9"
    assert row["level"] == "time-sensitive"
    assert row["payload"] == {"kind": "approval_pending", "threadId": "bot:luna",
                              "agentId": "luna", "turnId": "t1", "toolCallId": "call-9",
                              "name": "terminal:rm"}


@pytest.mark.parametrize("choice,outcome", [
    ("once", "approved"), ("session", "approved"), ("always", "approved"),
    ("smart_approve", "approved"), ("deny", "denied"), ("smart_deny", "denied"),
    ("timeout", "expired"), ("something-new", "settled"),
])
def test_a_settled_approval_replaces_the_pending_banner_with_its_outcome(choice, outcome):
    subject, outbox = emitter()
    subject.approval_resolved(command="rm -rf /", pattern_key="terminal:rm", turn_id="t1",
                              tool_call_id="call-9", session_id="s1", choice=choice)
    (row,) = outbox.rows
    assert row["category"] == "approval.resolved" and row["collapse_id"] == "call-9"
    assert row["payload"]["kind"] == "approval_resolved"
    assert row["payload"]["outcome"] == outcome
    # The relay refuses an interruptionLevel on any category but approval.pending, and drops the
    # notify with a 400 (found live 2026-09-15). The answer never interrupts anybody either way.
    assert row["level"] is None


def test_an_approval_with_no_tool_call_id_does_not_collide_with_the_reply():
    """Hermes's smart-approval path builds these payloads without one, and the bare fallback was
    the same sha256(session_id) the reply's own notify collapses under: the outbox would coalesce
    one away under the other whenever both landed inside the five-second window."""
    subject, outbox = emitter()
    subject.approval_resolved(pattern_key="delete in root path", session_id="s1",
                              choice="smart_approve")
    subject.stream_end(session_id="s1", final_text="Done.")
    subject.session_end(session_id="s1", platform="cli")
    approval, reply = outbox.rows
    assert approval["collapse_id"] == "approval:" + hashlib.sha256(b"s1").hexdigest()
    assert reply["collapse_id"] == hashlib.sha256(b"s1").hexdigest()
    assert approval["collapse_id"] != reply["collapse_id"]


def test_approvals_can_be_turned_off():
    subject, outbox = emitter(push_approvals=False)
    subject.approval_pending(pattern_key="terminal:rm", tool_call_id="call-9")
    assert outbox.rows == []

    subject, outbox = emitter(phone("phone-1", approvals=False))
    subject.approval_pending(pattern_key="terminal:rm", tool_call_id="call-9")
    assert outbox.rows == []


# -- rooms ---------------------------------------------------------------

def test_a_room_approval_needs_you_right_away():
    subject, outbox = emitter()
    subject.room_activity(kind="request.opened", room_id="r1", thread_id="th", member_id="m1",
                          payload={"method": "approval", "command": "rm -rf /"})
    (row,) = outbox.rows
    assert row["collapse_id"] == "room:r1" and row["payload"]["threadId"] == "group:r1"
    assert row["payload"]["preview"] == "A room member needs your OK."
    assert "command" not in row["payload"]


def test_a_member_naming_you_reaches_you_and_ordinary_chatter_does_not():
    subject, outbox = emitter()
    subject.room_activity(kind="message.interim", room_id="r1", payload={"text": "@user look"})
    subject.room_activity(kind="message.interim", room_id="r1", payload={"text": "just talking"})
    subject.room_activity(kind="message.delta", room_id="r1", payload={"text": "@user look"})
    assert [row["payload"]["preview"] for row in outbox.rows] == ["@user look"]


def test_rooms_can_be_turned_off():
    subject, outbox = emitter(push_rooms=False)
    subject.room_activity(kind="request.opened", room_id="r1", payload={})
    assert outbox.rows == []


# -- cron ----------------------------------------------------------------

def test_cron_delivery_fans_out_to_every_paired_phone():
    subject, outbox = emitter(phone("a"), phone("b"))
    assert subject.cron_send("job-7", "Nightly report ready") == 2
    assert {row["device_id"] for row in outbox.rows} == {"a", "b"}
    assert outbox.rows[0]["collapse_id"] == hashlib.sha256(b"job-7").hexdigest()
    assert outbox.rows[0]["payload"]["preview"] == "Nightly report ready"


# -- redaction -----------------------------------------------------------

@pytest.mark.parametrize("field", [
    "command", "description", "args", "tool_input", "path", "file_path", "cwd", "session_key",
    "pattern_keys", "surface", "model", "result", "error", "transcript",
])
def test_redaction_drops_everything_it_was_not_asked_to_carry(field):
    assert field not in privacy.redact({"kind": "message", field: "sensitive"})


def test_redaction_keeps_identity_state_and_ids():
    event = {"kind": "approval_pending", "threadId": "bot:luna", "agentId": "luna",
             "turnId": "t1", "toolCallId": "c1", "name": "terminal:rm", "outcome": "denied",
             "command": "rm -rf /"}
    assert privacy.redact(event) == {k: v for k, v in event.items() if k != "command"}


def test_a_long_preview_is_cut_to_one_banner_worth():
    kept = privacy.redact({"kind": "message", "preview": "x" * 500})["preview"]
    assert len(kept) == privacy.PREVIEW_LIMIT and kept.endswith("…")


def test_a_preview_is_flattened_to_one_line():
    assert privacy.preview_text("two\n\nlines  here") == "two lines here"


# -- subagents -----------------------------------------------------------

def test_subagents_are_muted_by_default():
    subject, outbox = emitter()
    subject.subagent_stop(child_session_id="c1", child_role="Reviewer",
                          child_status="completed", parent_session_id="s1")
    assert outbox.rows == []


def test_an_unmuted_subagent_finishing_reaches_the_phones_that_asked():
    subject, outbox = emitter(phone("wants", subagents=True), phone("not", subagents=False),
                              mute_subagents=False)
    subject.subagent_stop(child_session_id="c1", child_role="Reviewer",
                          child_status="completed", parent_session_id="s1")
    (row,) = outbox.rows
    assert row["device_id"] == "wants"
    assert row["category"] == "message"
    assert row["collapse_id"] == "subagent:c1"
    assert row["payload"] == {"kind": "message", "threadId": "bot:luna",
                              "agentName": "luna", "preview": "Reviewer finished."}


def test_a_subagent_that_did_not_finish_says_so():
    subject, outbox = emitter(mute_subagents=False)
    subject.subagent_stop(child_session_id="c1", child_status="failed")
    assert outbox.rows[0]["payload"]["preview"] == "A subagent failed."
