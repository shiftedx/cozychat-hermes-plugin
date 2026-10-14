"""The Lock Screen card for a run on this computer: registrations, and the updates they get.

WHAT A REGISTRATION IS. ActivityKit hands the phone a push token per card. The phone POSTs it to
`/api/plugins/cozychat/live-activities` through the tunnel; this module trades that token with the
relay for a push id (`platform: apns-liveactivity`) and keeps the push id, NOT the token. Only the
relay needs the token, so the computer stores the least it can still send with.

WHY THE SAME OUTBOX. A card update is a notify like any other and the relay's per-minute limit does
not care what is inside it, so the queue, the backoff and the retention are the ones `push.py`
already runs. What is different is the cadence: a run writes deltas many times a second, so updates
are coalesced to one per `push.LIVE_COALESCE_SECONDS` per card — except the terminal, which is the one update
a person would notice missing and is therefore never held back.

WHERE THE REGISTRATIONS LIVE. The phone POSTs to a route served by `hermes serve`; the updates are
pushed by hooks running in `hermes gateway`. Those are different processes, so a registration held
in memory — or in a JSON file beside one profile's copy of the plugin — reaches nobody. The rows are
in the shared `activities` table (see `state.py`) and the hook side reads it on every update, which
is also why a card registered while the gateway was down is driven by the next run without anything
having to notice it arrive.

ponytail: the projection (phase, tool count, sequence) lives in memory and only the push id is
written down, so a delta-rate hook costs no disk at all. A gateway restart loses the projection along
with the run it belonged to, and the next run redraws the card from its first frame.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .state import shared_state
from .locks import exclusive

logger = logging.getLogger("hermes_cli.plugins.cozychat")

# More cards than a household has phones times conversations, and small enough to bound the file.
MAX_REGISTRATIONS = 16
# The relay's own ceilings (`NotifyRequestSchema`), applied before anything is queued.
SHORT_STATUS_MAX = 80
MAX_ELAPSED_SECONDS = 604_800
# How long iOS may keep drawing a card before it greys out, per phase. The gateway's own windows.
STALE_WORKING = 120
STALE_WAITING = 30 * 60
# How long a finished card stays on the Lock Screen before iOS clears it.
DISMISS_AFTER_SECONDS = 15 * 60

PHASES = frozenset({"queued", "thinking", "usingTools", "writing", "waitingOnApproval",
                    "completed", "failed"})


class LiveActivities:
    """Every Lock Screen card this computer is driving, and the updates they are owed."""

    def __init__(self, state: Optional[Any] = None) -> None:
        self._lock = threading.Lock()
        self._state = state
        self._outbox: Any = None
        self._relay: Any = None
        self._allows_device = None
        self._retire_push = None
        # activity_id -> {tool_call_count, run_started_at}, rebuilt by the next run after a restart.
        self._runs: Dict[str, Dict[str, Any]] = {}

    # -- wiring ----------------------------------------------------------

    def configure(self, *, outbox: Any, relay: Any, allows_device=None, retire_push=None) -> None:
        """Called once by ``register()``; until then every route here answers "not loaded"."""
        with self._lock:
            self._outbox = outbox
            self._relay = relay
            self._allows_device = allows_device
            self._retire_push = retire_push

    @property
    def state_store(self) -> Any:
        return self._state if self._state is not None else shared_state()

    @property
    def ready(self) -> bool:
        return self._outbox is not None

    # -- the route side ---------------------------------------------------

    def register(self, activity_id: str, token: str, environment: str, session_id: str,
                 device_id: str = "", profile: str = "", consent_version: int = 0) -> bool:
        """Trade one ActivityKit token for a relay push id and remember it. False: the relay said no.

        Idempotent by ``activity_id``: a card whose token rotated replaces its own row, so a phone
        that re-registers does not leave the computer pushing to a dead token.
        """
        if (self._allows_device is None or not device_id or not profile or consent_version != 1
                or not self._allows_device(device_id, profile)):
            return False
        # Initialise the shared directory before taking its inter-process lock. A freshly paired
        # phone may be the first writer, before either gateway process has opened state.sqlite.
        with self.state_store.read():
            pass
        with exclusive(self.state_store.root / "outbox.lock"):
            if not self._allows_device(device_id, profile):
                return False
            push_id = self._relay.register_live_activity(token, environment, device_id, profile)
            if not push_id:
                return False
            with self.state_store.write() as db:
                row = db.execute("SELECT push_id FROM activities WHERE activity_id = ?",
                                 (activity_id,)).fetchone()
                previous = str(row[0]) if row else ""
                db.execute(
                    "INSERT INTO activities (activity_id, push_id, environment, session_id, created_at, device_id,"
                    " profile, consent_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(activity_id) DO UPDATE SET"
                    " push_id = excluded.push_id, environment = excluded.environment,"
                    " session_id = excluded.session_id, created_at = excluded.created_at,"
                    " device_id = excluded.device_id, profile = excluded.profile,"
                    " consent_version = excluded.consent_version",
                    (activity_id, push_id, environment, session_id, time.time(), device_id, profile,
                     consent_version))
                db.execute(
                    "DELETE FROM activities WHERE activity_id NOT IN"
                    " (SELECT activity_id FROM activities ORDER BY created_at DESC LIMIT ?)",
                    (MAX_REGISTRATIONS,))
            if previous and previous != push_id:
                self._retire(previous)
            return True

    def forget(self, activity_id: str) -> bool:
        """The card is gone. Drop the row and release its relay registration."""
        with self._lock:
            self._runs.pop(activity_id, None)
        with self.state_store.write() as db:
            row = db.execute("SELECT push_id, consent_version FROM activities WHERE activity_id = ?",
                             (activity_id,)).fetchone()
            db.execute("DELETE FROM activities WHERE activity_id = ?", (activity_id,))
        if row is None:
            return False
        if row[1] == 1:
            self._retire(str(row[0]))
        return True

    def listing(self) -> List[Dict[str, Any]]:
        """What `/info` reports: the cards, without the ids that address them on the relay."""
        with self.state_store.read() as db:
            rows = db.execute("SELECT activity_id, session_id FROM activities"
                              " ORDER BY created_at").fetchall()
        return [{"activity_id": row[0], "session_id": row[1]} for row in rows]

    # -- the hook side ----------------------------------------------------

    def update(self, session_id: str, phase: str, short_status: str, *,
               approval_id: str = "", tool_delta: int = 0, now: Optional[float] = None) -> int:
        """One phase change for every card watching this session. Returns how many were queued."""
        return self._send(session_id, phase, short_status, approval_id=approval_id,
                          tool_delta=tool_delta, terminal=False, now=now)

    def finish(self, session_id: str, succeeded: bool, now: Optional[float] = None) -> int:
        """The run is over. Always queued, never coalesced away, and the card retires with it."""
        return self._send(session_id, "completed" if succeeded else "failed",
                          "Finished" if succeeded else "Could not finish",
                          terminal=True, now=now)

    def _send(self, session_id: str, phase: str, short_status: str, *, terminal: bool,
              approval_id: str = "", tool_delta: int = 0, now: Optional[float] = None) -> int:
        if not self.ready or phase not in PHASES or not session_id:
            return 0
        now = time.time() if now is None else now
        queued = 0
        for row in self._matching(session_id):
            activity_id = row["activity_id"]
            with self._lock:
                run = self._runs.setdefault(activity_id, _fresh_run(now))
                run["tool_call_count"] += max(0, tool_delta)
                run["run_started_at"] = run["run_started_at"] or now
                run["event_sequence"] += 1
                body = _body(phase=phase, short_status=short_status,
                             tool_call_count=run["tool_call_count"],
                             event_sequence=run["event_sequence"],
                             elapsed_seconds=int(max(0.0, now - run["run_started_at"]))
                             if terminal else None,
                             approval_id=approval_id, terminal=terminal, now=now)
                if terminal:
                    # The card stays registered — the same conversation's next run reuses it — so
                    # only the RUN is reset. The sequence is not: the widget animates on a change in
                    # it, and a number that started over would land as no change at all.
                    run["tool_call_count"], run["run_started_at"] = 0, None
            self._outbox.enqueue_live_activity(activity_id, row["push_id"], body,
                                               device_id=row["device_id"], profile=row["profile"],
                                               consent_version=row["consent_version"], terminal=terminal, now=now)
            queued += 1
        return queued

    def _matching(self, session_id: str) -> List[Dict[str, Any]]:
        """Read on every update, so a card registered in the other process is driven by this one."""
        with self.state_store.read() as db:
            rows = db.execute(
                "SELECT activity_id, push_id, device_id, profile, consent_version FROM activities"
                " WHERE session_id = ? AND consent_version = 1"
                " ORDER BY created_at", (session_id,)).fetchall()
        return [{"activity_id": row[0], "push_id": row[1], "device_id": row[2],
                 "profile": row[3], "consent_version": row[4]} for row in rows]

    def _retire(self, push_id: str) -> None:
        if self._retire_push is not None:
            self._retire_push(push_id)
        else:
            self._relay.forget(push_id)


def migrate_registrations(path: Path, state: Any) -> int:
    """Fold one pre-shared-state ``live-activities.json`` into the table. Returns how many moved.

    The file is removed either way: a registration this computer can no longer address is worse
    than none, and the phone re-registers on its next foreground.
    """
    path = Path(path)
    try:
        loaded = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        loaded = []
    moved = 0
    with state.write() as db:
        for row in loaded if isinstance(loaded, list) else []:
            if not isinstance(row, dict) or not row.get("activity_id") or not row.get("push_id"):
                continue
            db.execute(
                "INSERT OR IGNORE INTO activities (activity_id, push_id, environment, session_id,"
                " created_at) VALUES (?, ?, ?, ?, ?)",
                (str(row["activity_id"]), str(row["push_id"]),
                 str(row.get("environment") or "production"), str(row.get("session_id") or ""),
                 float(row.get("created_at") or time.time())))
            moved += 1
    path.unlink(missing_ok=True)
    return moved


def _body(*, phase: str, short_status: str, tool_call_count: int, event_sequence: int,
          elapsed_seconds: Optional[int], approval_id: str, terminal: bool,
          now: float) -> Dict[str, Any]:
    """One `liveActivity` object, inside the relay's bounds by construction.

    No `alert` even on the terminal: `on_session_end` already pushes the reply itself, and a card
    that alerts as well would ring the same phone twice for one finished turn.
    """
    timestamp = int(now)
    state: Dict[str, Any] = {
        "phase": phase,
        "toolCallCount": max(0, min(tool_call_count, 10_000)),
        "shortStatus": (short_status or "Working")[:SHORT_STATUS_MAX],
        "eventSequence": max(0, event_sequence),
    }
    if elapsed_seconds is not None:
        state["elapsedSeconds"] = max(0, min(int(elapsed_seconds), MAX_ELAPSED_SECONDS))
    if approval_id:
        state["approvalID"] = approval_id[:200]
    body: Dict[str, Any] = {
        "timestamp": timestamp,
        "event": "end" if terminal else "update",
        "contentState": state,
        "priority": 10 if terminal else 5,
    }
    if terminal:
        body["dismissalDate"] = timestamp + DISMISS_AFTER_SECONDS
    else:
        body["staleDate"] = timestamp + (
            STALE_WAITING if phase == "waitingOnApproval" else STALE_WORKING)
    return body


def _fresh_run(now: float) -> Dict[str, Any]:
    return {"tool_call_count": 0, "run_started_at": now, "event_sequence": 0}


_ACTIVITIES = LiveActivities()


def live_activities() -> LiveActivities:
    """This process's view of the shared cards."""
    return _ACTIVITIES
