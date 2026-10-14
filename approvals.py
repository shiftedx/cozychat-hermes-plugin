"""The approval transport: a command this computer is holding, answered from the phone.

WHAT THE HOST OWNS AND THIS DOES NOT. Detection, policy, the allowed choices, the deadline, and the
final authorization are Hermes's (`hermes_cli/approval_transport.py`). A transport may do exactly two
things: show an immutable, already-redacted request, and hand back one decision correlated to it.
Everything here is written to that limit — there is no policy in this file, and the only answer it
can produce is one of the choices the host listed.

WHY A TABLE AND NOT A CONDITION VARIABLE. It was a condition variable, on the belief that
`present_fn`'s transport worker and `POST /api/plugins/cozychat/approvals/{id}` were the same
process. They are not: the worker runs in `hermes gateway` and the route is served by `hermes serve`.
The 2026-09-15 run measured it — an approval genuinely open on the computer answered the phone
`no open approval with that id`. So the ask is a row both processes can see, the waiter polls for
its own decision, and the route writes it. The durability is incidental and unused: the request dies
with the turn that opened it either way.

WHY THE WAITER OWNS THE DEADLINE. The host computes its deadline BEFORE it starts the worker, so a
wait of exactly `timeout_seconds` started inside the worker always wakes after it. That is
deliberate: silence reaches the agent as the host's own `timeout` — "nobody answered" — rather than
as a denial this plugin invented. It is also what makes a late decision harmless: the waiter deletes
its own row on the way out, so an answer arriving one tick later finds nothing to apply.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any, Dict, List, Optional

from . import privacy
from .state import shared_state

logger = logging.getLogger("hermes_cli.plugins.cozychat")

TRANSPORT_NAME = "cozychat"

# How often a waiting turn looks for its decision. Slower than the feed's tick because a person
# tapping a button does not notice a quarter second, and every turn under approval pays this.
POLL_SECONDS = 0.25

# What `answer()` says back, which is also what the route turns into a status code.
ANSWERED = "answered"
UNKNOWN = "unknown"       # 404: no request by that id, here or ever
SETTLED = "settled"       # 409: answered already, or the turn stopped waiting
REFUSED = "refused"       # 400: a choice this request never offered


class ApprovalDesk:
    """Open transport requests, and the decisions coming back for them."""

    def __init__(self, state: Optional[Any] = None) -> None:
        self._state = state
        self._lock = threading.Lock()
        # request_id -> the observer hook's coordinates for the same approval. `pre_approval_request`
        # fires with BOTH ids (the transport's `request_id` in its kwargs, `tool_call_id` from the
        # approval contextvars) and it fires BEFORE the transport is invoked, so by the time
        # `open()` runs the pair is already here. That is the whole reconciliation: it is what lets
        # the observer's push and this one collapse into one alert instead of two.
        #
        # In memory, not in the table: both the hook and the transport worker run in the gateway
        # process, so this map never has to cross one.
        self._observed: Dict[str, Dict[str, str]] = {}

    @property
    def state_store(self) -> Any:
        return self._state if self._state is not None else shared_state()

    # -- the observer side ------------------------------------------------

    def note(self, request_id: str, **coordinates: str) -> None:
        """Remember what the observer hook saw for one transport request."""
        if not request_id:
            return
        with self._lock:
            self._observed[request_id] = {k: v for k, v in coordinates.items() if v}
            # Bounded: a turn that opened approvals and never reached the transport leaves rows
            # behind, and this map is only ever read by the request it names.
            while len(self._observed) > 256:
                self._observed.pop(next(iter(self._observed)))

    # -- the transport side -----------------------------------------------

    def open(self, request: Any, *, now: Optional[float] = None) -> Dict[str, Any]:
        """Record one request as open, and return the row every surface reads."""
        now = time.time() if now is None else now
        timeout = max(float(getattr(request, "timeout_seconds", 0.0) or 0.0), 0.0)
        with self._lock:
            observed = self._observed.pop(request.request_id, {})
        record = {
            "request_id": request.request_id,
            # The card's identity everywhere else in CozyChat. Falls back to the request id when
            # the observer hooks are not loaded, so a card always has one.
            "tool_call_id": observed.get("tool_call_id") or request.request_id,
            "turn_id": observed.get("turn_id", ""),
            "session_id": observed.get("session_id", ""),
            "name": str(getattr(request, "pattern_key", "") or ""),
            "pattern_keys": list(getattr(request, "pattern_keys", ()) or ()),
            "detail": privacy.detail_text(
                getattr(request, "description", "") or getattr(request, "command", "")),
            "surface": str(getattr(request, "surface", "") or ""),
            "allowed_choices": list(getattr(request, "allowed_choices", ()) or ()),
            "opened_at": now,
            "expires_at": now + timeout,
            "choice": None,
        }
        with self.state_store.write() as db:
            db.execute(
                "INSERT INTO approvals (request_id, opened_at, expires_at, card, choice)"
                " VALUES (?, ?, ?, ?, NULL)"
                " ON CONFLICT(request_id) DO UPDATE SET opened_at = excluded.opened_at,"
                " expires_at = excluded.expires_at, card = excluded.card, choice = NULL",
                (record["request_id"], now, record["expires_at"],
                 json.dumps(record, separators=(",", ":"), sort_keys=True, default=str)))
        return dict(record)

    def wait(self, request_id: str, timeout: float) -> Optional[str]:
        """Block until this request is answered or its time is up. Settles it either way."""
        deadline = time.monotonic() + max(float(timeout), 0.0)
        while True:
            with self.state_store.read() as db:
                row = db.execute("SELECT choice FROM approvals WHERE request_id = ?",
                                 (request_id,)).fetchone()
            if row is None:
                return None
            if row[0] is not None:
                self._settle(request_id)
                return str(row[0])
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                # Settled here, so an answer arriving one tick later is refused rather than
                # applied to a request the host has already timed out.
                self._settle(request_id)
                return None
            time.sleep(min(POLL_SECONDS, remaining))

    def _settle(self, request_id: str) -> None:
        with self.state_store.write() as db:
            db.execute("DELETE FROM approvals WHERE request_id = ?", (request_id,))

    # -- the route side ---------------------------------------------------

    def listing(self, now: Optional[float] = None) -> List[Dict[str, Any]]:
        """Everything still open, oldest first, as the phone's cards."""
        now = time.time() if now is None else now
        with self.state_store.read() as db:
            rows = db.execute(
                "SELECT card FROM approvals WHERE choice IS NULL AND expires_at > ?"
                " ORDER BY opened_at", (now,)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def answer(self, request_id: str, choice: str) -> str:
        """Record one decision for a waiting request. One of the four outcomes above."""
        with self.state_store.write() as db:
            row = db.execute("SELECT card, choice, expires_at FROM approvals WHERE request_id = ?",
                             (request_id,)).fetchone()
            if row is None:
                return UNKNOWN
            card, existing, expires_at = row
            if existing is not None or float(expires_at) <= time.time():
                return SETTLED
            if choice not in (json.loads(card).get("allowed_choices") or []):
                return REFUSED
            db.execute("UPDATE approvals SET choice = ? WHERE request_id = ?",
                       (choice, request_id))
            return ANSWERED


class ApprovalTransport:
    """`present_fn`: push the ask, wait for the tap, hand back the host's own decision object."""

    def __init__(self, desk: ApprovalDesk, emitter: Any) -> None:
        self.desk = desk
        self.emitter = emitter

    def present(self, request: Any) -> Any:
        """Called by the host on its transport worker. Returns a decision, or nothing."""
        record = self.desk.open(request)
        try:
            self.emitter.approval_transport_pending(record)
        except Exception:
            # A phone that was not told can still answer from the list on open; a failure to notify
            # is never a reason to deny a command the person might be about to allow.
            logger.debug("cozychat could not push a transport approval", exc_info=True)
        choice = self.desk.wait(request.request_id, float(request.timeout_seconds))
        if choice is None:
            return None
        return request.respond(choice)


_DESK = ApprovalDesk()


def approval_desk() -> ApprovalDesk:
    """This process's view of the shared desk."""
    return _DESK


def transport_selected() -> bool:
    """Whether the owner actually selected this transport.

    The host already refuses to invoke an unselected transport, so this is not a gate — it is the
    one bit the app needs to decide whether to offer "answer from the phone" at all, and reading
    the same config key the host reads is the only way to answer it without a second source of
    truth.
    """
    try:
        from hermes_cli.config import load_config_readonly

        approval = ((load_config_readonly() or {}).get("security") or {}).get("approval") or {}
        return str(approval.get("transport") or "").strip().lower() == TRANSPORT_NAME
    except Exception:
        return False
