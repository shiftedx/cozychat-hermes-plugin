"""Hermes hook facts turned into the notifications CozyChat already knows how to show.

One class, because every hook answers the same three questions in the same order: is this worth a
notification at all, which paired phones asked for it, and what does the sealed payload say. The
payload shapes are ``PushPayload``'s cases and the collapse ids are the design's table; both are
CozyChat's existing contract, not something this plugin invents.

``on_session_end`` carries no reply text (verified against Hermes 0.21.3: session_id, task_id,
turn_id, completed, failed, interrupted, turn_exit_reason, model, platform), so the preview comes
from the stream that precedes it, held per session until the session ends. Nor is
``on_stream_end``'s ``final_text`` dependable: the API Server surface ends the stream with an empty
one, so the preview is accumulated from the ``on_stream_delta`` text this emitter already sees.

``on_session_end`` is also not one-shot on that surface. The live ``frames`` table for a
tool-calling turn shows several ``stream.started``/``stream.ended`` pairs before the reply is
truly done (one per model iteration — a tool round, then another, then the text that answers),
and Hermes fires ``on_session_end`` after each of them, not only the last (2026-09-15 live count:
the outbox's ``sent`` counter rose by three for a two-iteration turn, one per stream). Each firing
carries the SAME ``turn_id``, so ``session_end`` remembers the last turn it already told a phone
about and skips a repeat — the one thing that changes between a genuine next reply and a stray
extra firing for the one just sent.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from collections import OrderedDict
from typing import Any, Dict, Iterable, List, Optional

from . import privacy
from .approvals import ApprovalDesk, approval_desk
from .feed import LiveFeed, live_feed
from .activities import LiveActivities, live_activities
from .local_push import NotifySubscriptions

# Platforms that put the reply on the user's phone themselves. A second banner is noise.
NATIVE_NOTIFY_PLATFORMS = frozenset({"telegram", "discord", "slack", "whatsapp"})
# Sessions that are machinery rather than a conversation somebody is waiting on.
PLUMBING_PREFIXES = ("cron_", "kanban_", "room_plumbing", "room_member_")

CATEGORY_MESSAGE = "message"
CATEGORY_APPROVAL_PENDING = "approval.pending"
CATEGORY_APPROVAL_RESOLVED = "approval.resolved"

# How many sessions back the "already delivered" memory reaches. It cannot be popped when a session
# ends, because the extra `session_end` firings it exists to swallow arrive AFTER the one that would
# pop it; so it is bounded instead, oldest-first, in a gateway process that runs for weeks. 512 is
# far more than the sessions alive at once on any host this plugin runs on, and evicting the oldest
# can only ever cost one duplicate banner on a session nobody has touched in 512 sessions.
DELIVERED_TURNS_LIMIT = 512


class Emitter:
    """Turns hook calls into outbox rows."""

    def __init__(self, store, outbox, config: Dict[str, Any],
                 feed: Optional[LiveFeed] = None,
                 desk: Optional[ApprovalDesk] = None,
                 activities: Optional[LiveActivities] = None) -> None:
        self.store = store
        self.outbox = outbox
        self.config = config
        self.feed = feed or live_feed()
        self.desk = desk or approval_desk()
        # The Lock Screen card for a run. It answers "nobody registered one" by doing nothing, so
        # every call below is unconditional and there is no second gate to keep in step.
        self.activities = activities or live_activities()
        self._previews: Dict[str, str] = {}
        # session_id -> the last turn_id a `message` notify went out for. One entry per session
        # (overwritten, never two), so a repeat `session_end` for a turn already delivered is a
        # no-op, and the session's NEXT real turn (a new turn_id) still fires. Insertion-ordered
        # and capped at DELIVERED_TURNS_LIMIT, newest last: the session being delivered right now
        # is the newest entry, so eviction never drops the turn the next firing must recognise.
        self._delivered_turns: "OrderedDict[str, str]" = OrderedDict()

    # -- direct chats ----------------------------------------------------

    def stream_end(self, session_id: str = "", final_text: str = "", finished: bool = False,
                   error: Optional[str] = None, **coordinates: Any) -> None:
        """Hold the reply this session just finished writing, for ``session_end`` to preview.

        ``final_text`` is whatever Hermes could read back off the provider response
        (``_stream_final_text`` in ``agent/chat_completion_helpers.py``); on the API Server surface
        it is empty, because the reply arrived as deltas. So this only OVERWRITES the text the
        deltas already accumulated — it never clears it.
        """
        if session_id and final_text:
            self._previews[session_id] = final_text
        self._frame("stream.ended", session_id=session_id,
                    payload={"text": final_text, "finished": bool(finished), "error": error},
                    **coordinates)

    def session_end(self, session_id: str = "", platform: str = "", interrupted: bool = False,
                    completed: bool = True, failed: bool = False, turn_id: str = "",
                    **_: Any) -> None:
        """A reply finished in a direct chat."""
        # FIRST, and outside every filter below: a card left saying "Thinking" over a run that ended
        # is worse than no card, and none of the reasons to skip the BANNER apply to retiring it.
        self.activities.finish(session_id, succeeded=bool(completed) and not bool(failed))
        preview = self._previews.pop(session_id, "")
        if not self.config.get("push_replies", True) or interrupted or not preview:
            return
        if (platform or "").lower() in NATIVE_NOTIFY_PLATFORMS or _is_plumbing(session_id):
            return
        # The API Server surface fires this hook once per model iteration of a tool-calling turn,
        # not once for the whole turn (live 2026-09-15: a two-iteration turn tripled the outbox's
        # `sent` count). Every iteration of ONE turn carries the same `turn_id`, so a repeat here
        # for a turn already delivered is that extra firing, not a new reply — skip it. A blank
        # `turn_id` (older Hermes, or a surface that omits it) can't be compared, so it always sends,
        # same as before this guard existed.
        if turn_id and self._delivered_turns.get(session_id) == turn_id:
            return
        if turn_id:
            self._delivered_turns[session_id] = turn_id
            self._delivered_turns.move_to_end(session_id)
            while len(self._delivered_turns) > DELIVERED_TURNS_LIMIT:
                self._delivered_turns.popitem(last=False)
        self._fan_out("replies", CATEGORY_MESSAGE, _digest(session_id),
                      self._message(self._sealed(preview)), skip_session=session_id)

    # -- the live feed ---------------------------------------------------
    #
    # The room hook's payload is already the client-safe one Hermes hands a client, so it is passed
    # through whole. The SESSION hooks are not: `pre_tool_call` carries the tool's arguments and the
    # subagent hooks carry a goal and a summary, none of which any CozyChat surface draws. They are
    # dropped here rather than forwarded, so the feed carries the same kind of thing on both paths:
    # who is doing what, and the reply text a room or a chat is there to show.

    def stream_start(self, session_id: str = "", **coordinates: Any) -> None:
        # A turn streams once per LLM iteration; the last one is the reply, so each start drops
        # what the iteration before it wrote.
        self._previews.pop(session_id, None)
        self._frame("stream.started", session_id=session_id, **coordinates)
        self.activities.update(session_id, "thinking", "Thinking")

    def stream_delta(self, session_id: str = "", delta: str = "", kind: str = "text",
                     **coordinates: Any) -> None:
        self._frame("reasoning.delta" if kind == "reasoning" else "message.delta",
                    session_id=session_id, payload={"text": delta}, **coordinates)
        if kind != "reasoning":
            # One bounded string per live session: a banner never shows more than PREVIEW_LIMIT,
            # and stopping one char past it leaves `preview_text` its "…".
            held = self._previews.get(session_id, "")
            if session_id and len(held) <= privacy.PREVIEW_LIMIT:
                self._previews[session_id] = held + delta
            self.activities.update(session_id, "writing", "Writing the reply")

    def interim_message(self, session_id: str = "", text: str = "",
                        already_streamed: bool = False, **coordinates: Any) -> None:
        self._frame("message.interim", session_id=session_id,
                    payload={"text": text, "already_streamed": bool(already_streamed)},
                    **coordinates)

    def tool_started(self, tool_name: str = "", tool_call_id: str = "", session_id: str = "",
                     **coordinates: Any) -> None:
        self._frame("tool.started", session_id=session_id,
                    payload={"tool_id": tool_call_id, "name": tool_name}, **coordinates)
        self.activities.update(session_id, "usingTools", "Using tools", tool_delta=1)

    def tool_completed(self, tool_name: str = "", tool_call_id: str = "", session_id: str = "",
                       status: str = "", duration_ms: int = 0, error_type: Optional[str] = None,
                       **coordinates: Any) -> None:
        self._frame("tool.completed", session_id=session_id,
                    payload={"tool_id": tool_call_id, "name": tool_name, "status": status or "ok",
                             "duration_ms": int(duration_ms or 0), "error_type": error_type},
                    **coordinates)
        # The count is the card's own, so this update carries the tool that just FINISHED without
        # counting it twice: `tool_delta` stays at zero.
        self.activities.update(session_id, "usingTools", "Using tools")

    def subagent_start(self, child_session_id: str = "", child_role: str = "",
                       parent_turn_id: str = "", parent_session_id: str = "",
                       **coordinates: Any) -> None:
        self._frame("subagent.started", turn_id=parent_turn_id, session_id=parent_session_id,
                    payload={"child_session_id": child_session_id, "role": child_role},
                    **coordinates)

    def subagent_stop(self, child_session_id: str = "", child_role: str = "",
                      child_status: str = "", parent_turn_id: str = "", parent_session_id: str = "",
                      duration_ms: int = 0, **coordinates: Any) -> None:
        self._frame("subagent.stopped", turn_id=parent_turn_id, session_id=parent_session_id,
                    payload={"child_session_id": child_session_id, "role": child_role,
                             "status": child_status, "duration_ms": int(duration_ms or 0)},
                    **coordinates)
        # Off by default, because a turn that fans out six subagents would otherwise buzz a phone
        # six times before the reply it was working towards exists. A reader who wants the
        # play-by-play turns `mute_subagents` off and the "subagents" filter on.
        if self.config.get("mute_subagents", True):
            return
        self._fan_out("subagents", CATEGORY_MESSAGE, f"subagent:{child_session_id}",
                      self._message(_subagent_preview(child_role, child_status)))

    def loop_stopped(self, session_key: str = "", reason: str = "",
                     invalidation_reason: str = "", **coordinates: Any) -> None:
        self._frame("turn.stopped", session_key=session_key,
                    payload={"reason": reason, "invalidation_reason": invalidation_reason},
                    **coordinates)

    def _frame(self, kind: str, *, source: str = "session",
               payload: Optional[Dict[str, Any]] = None, session_key: str = "",
               **coordinates: Any) -> None:
        """One ring entry, with only the coordinates the feed names kept."""
        self.feed.publish(kind, source=source, payload=payload, session_key=session_key,
                          **coordinates)

    # -- approvals -------------------------------------------------------

    def approval_pending(self, pattern_key: str = "", tool_call_id: str = "", turn_id: str = "",
                         session_id: str = "", request_id: str = "", **_: Any) -> None:
        # On the transport path this hook fires FIRST, carrying both ids, so noting the pair here is
        # what lets `present_fn` push under the collapse id this push already used. See
        # `ApprovalDesk.note`.
        self.desk.note(request_id, tool_call_id=tool_call_id, turn_id=turn_id,
                       session_id=session_id)
        # The card's Approve and Deny buttons resolve THIS id, so a card with no id to answer is
        # better left saying the run is blocked than given a button that resolves nothing.
        self.activities.update(session_id, "waitingOnApproval", "Waiting for your OK",
                               approval_id=request_id or tool_call_id)
        self._approval(CATEGORY_APPROVAL_PENDING, "approval_pending", pattern_key, tool_call_id,
                       turn_id, session_id, None, request_id=request_id)

    def approval_resolved(self, pattern_key: str = "", tool_call_id: str = "", turn_id: str = "",
                          session_id: str = "", choice: str = "", request_id: str = "",
                          **_: Any) -> None:
        self._approval(CATEGORY_APPROVAL_RESOLVED, "approval_resolved", pattern_key, tool_call_id,
                       turn_id, session_id, _OUTCOME.get(choice, "settled"), request_id=request_id)

    def approval_transport_pending(self, record: Dict[str, Any]) -> None:
        """The transport is holding this one and the phone is the only surface that can answer it.

        The same category and the same collapse id as the observer push a moment earlier, which is
        the point: the outbox coalesces the two into ONE alert, and this payload — the one carrying
        the `requestId` the phone answers by — is the one that survives.
        """
        self._approval(CATEGORY_APPROVAL_PENDING, "approval_pending", record.get("name", ""),
                       record.get("tool_call_id", ""), record.get("turn_id", ""),
                       record.get("session_id", ""), None,
                       request_id=record.get("request_id", ""))

    def _approval(self, category: str, kind: str, pattern_key: str, tool_call_id: str,
                  turn_id: str, session_id: str, outcome: Optional[str],
                  request_id: str = "") -> None:
        if not self.config.get("push_approvals", True):
            return
        payload = {
            "kind": kind, "threadId": self._bot_thread(), "agentId": self._profile(),
            "turnId": turn_id or "", "toolCallId": tool_call_id or "", "name": pattern_key or "",
        }
        # Only the transport path has one, and it is what the phone POSTs back. Its absence is how
        # a card knows it must answer through the API Server instead.
        if request_id:
            payload["requestId"] = request_id
        if outcome:
            payload["outcome"] = outcome
        # Two things the 2026-09-15 live check settled. The level rides the QUESTION only: the relay
        # answers 400 to an interruptionLevel on any category but `approval.pending`
        # (relay `http.ts`), which silently dropped every resolved push this plugin sent. And the
        # id fallback is namespaced, because bare `sha256(session_id)` is the collapse id
        # `session_end` already uses, so the two would coalesce each other away.
        self._fan_out("approvals", category,
                      tool_call_id or f"approval:{_digest(session_id)}", payload,
                      level="time-sensitive" if category == CATEGORY_APPROVAL_PENDING else None)

    # -- rooms -----------------------------------------------------------

    def room_activity(self, kind: str = "", room_id: str = "", payload: Optional[Dict] = None,
                      seq: Optional[int] = None, **coordinates: Any) -> None:
        """A room turn wants the user: an approval opened, or a member wrote their name.

        Every kind reaches the feed; only the two that are worth a banner reach the outbox.
        """
        payload = dict(payload or {})
        self._frame(kind, source="room", room_id=room_id, payload=payload, **coordinates)
        if not self.config.get("push_rooms", True):
            return
        if kind == "request.opened":
            preview = "A room member needs your OK."
        elif kind == "message.interim" and _mentions_user(payload, self._profile()):
            preview = self._sealed(str(payload.get("text") or ""))
        else:
            return
        self._fan_out("rooms", CATEGORY_MESSAGE, f"room:{room_id}",
                      self._message(preview, thread_id=f"group:{room_id}"))

    # -- cron ------------------------------------------------------------

    def cron_send(self, job_id: str, message: str) -> int:
        """``deliver: cozychat`` from a cron job. Returns how many phones it was queued for."""
        return self._fan_out("replies", CATEGORY_MESSAGE, _digest(job_id),
                             self._message(self._sealed(message)))

    # -- plumbing --------------------------------------------------------

    def _fan_out(self, filter_name: str, category: str, collapse_id: str, payload: Dict[str, Any],
                 *, level: Optional[str] = None, skip_session: str = "") -> int:
        body = privacy.redact(payload)
        # One event per notification, before the APNs-device fanout. The listener process tails
        # this shared feed, so local delivery works with no registered push devices and never needs
        # a second durable queue. A phone that was offline does not replay it: the notify service
        # starts at the feed's current sequence when the stream opens.
        event_id = str(uuid.uuid4())
        frame = self.feed.publish(
            "notify", source=f"notify:{filter_name}",
            payload={"v": 1, "id": event_id, "category": category,
                     "collapseId": collapse_id, "payload": body,
                     "profile": self._profile(), "at": time.time()})
        queued = 0
        subscriptions = NotifySubscriptions(self.feed.state_store)
        # Fallbacks whose phone never acknowledged are due now; sending them is never skipped.
        subscriptions.release_due(self.outbox)
        # _devices lists only phones registered for away push (D27). A covered phone keeps a relay
        # fallback until it acknowledges local delivery; an unregistered phone has none at all.
        for device in self._devices(filter_name, skip_session):
            if subscriptions.hold(device["device_id"], self._profile(), filter_name, frame["seq"],
                                  event_id, category, collapse_id, body, level):
                queued += 1  # Delivered locally, or released to the relay on timeout/disconnect.
                continue
            self.outbox.enqueue(device["device_id"], category, collapse_id, body, level=level,
                                profile=str(device["profile"]), consent_version=1)
            queued += 1
        return queued

    def _devices(self, filter_name: str, skip_session: str) -> Iterable[Dict[str, Any]]:
        wanted: List[Dict[str, Any]] = []
        for device in self.store.list():
            if (device.get("consent_version") != 1
                    or device.get("profile") != self._profile()):
                continue
            filters = device.get("filters") or {}
            if not filters.get(filter_name, True):
                continue
            # The app is already watching this run in the foreground; a banner would race its own UI.
            if skip_session and filters.get("foreground_session") == skip_session:
                continue
            wanted.append(device)
        return wanted

    def _message(self, preview: str, thread_id: str = "") -> Dict[str, Any]:
        """The `message` payload every banner-worthy reply fans out, room or direct chat."""
        return {"kind": "message", "threadId": thread_id or self._bot_thread(),
                "agentName": self._profile(), "preview": preview}

    def _sealed(self, text: str) -> str:
        return privacy.preview_text(text, mode=self.config.get("preview_mode", "sealed"))

    def _profile(self) -> str:
        return str(self.config.get("profile_name") or "hermes")

    def _bot_thread(self) -> str:
        return f"bot:{self._profile()}"


# The transport path spells a host-side failure as `transport_<failure>` (approval_prompt.py), and
# every one of them is a deny the person never made — "expired" is the honest word for all of them.
_OUTCOME = {"once": "approved", "session": "approved", "always": "approved",
            "smart_approve": "approved", "deny": "denied", "smart_deny": "denied",
            "timeout": "expired", "transport_timeout": "expired", "transport_error": "expired",
            "transport_invalid": "expired", "transport_stale": "expired",
            "transport_busy": "expired", "transport_interrupted": "expired",
            "transport_unavailable": "expired"}


def _subagent_preview(role: str, status: str) -> str:
    """Who finished and how. The role is a configured label, never a goal or a result."""
    who = (role or "").strip() or "A subagent"
    return f"{who} finished." if status in ("", "completed", "ok") else f"{who} {status}."


def _digest(value: str) -> str:
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()


def _is_plumbing(session_id: str) -> bool:
    return any((session_id or "").startswith(prefix) for prefix in PLUMBING_PREFIXES)


def _mentions_user(payload: Dict[str, Any], profile: str) -> bool:
    text = str(payload.get("text") or "")
    return "@user" in text or f"@{profile}" in text
