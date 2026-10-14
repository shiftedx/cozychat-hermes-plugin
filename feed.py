"""The live feed: frames written by the hooks in one process and read by the route in another.

WHY A BOUNDED TABLE AND NOT A QUEUE. The phone is not a subscriber this computer has to keep: it
holds a tunnel that flaps whenever the phone changes networks, and it reconnects with the last
``seq`` it saw. Retaining the newest 5000 frames gives that reconnect a replay for free and gives a
phone that never comes back a bounded cost. 5000 is roughly a long room round at delta granularity.

THE SEQ IS OURS, not Hermes's. ``on_room_member_activity`` carries a ``seq`` that may be ``None``
and that counts within one session; the feed needs one number that orders EVERY frame this computer
produced, so the table stamps its own (an AUTOINCREMENT, monotonic across the prune) and the room's
is left in the payload where it came from.

WHY IT IS ON DISK. It was a deque, on the belief that the hooks and the route were the same process.
On Hermes 0.21.3 they are not, and the 2026-09-15 run measured the consequence: a feed held open
across a whole turn produced nothing while ``/info`` said ``attached: true``. The frames now live in
``<root>/cozychat/state.sqlite``, which every process of this Hermes opens — see ``state.py`` for
why the ROOT home rather than the profile.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List, Optional

from .state import shared_state

# Coordinates, in the order they are worth reading. Anything a hook passes that is not named here
# stays out of the frame's top level; the payload is the only place content may live.
_COORDINATES = ("room_id", "thread_id", "member_id", "turn_id", "task_id",
                "execution_generation", "session_id", "surface")


class LiveFeed:
    """Frames in production order, readable from any ``seq``, by any process."""

    def __init__(self, state: Optional[Any] = None) -> None:
        self._state = state

    @property
    def state_store(self) -> Any:
        return self._state if self._state is not None else shared_state()

    def publish(self, kind: str, *, source: str, payload: Optional[Dict[str, Any]] = None,
                session_key: str = "", **coordinates: Any) -> Dict[str, Any]:
        """Stamp one frame and keep it. Returns the frame, which is what the tests read."""
        frame: Dict[str, Any] = {"seq": 0, "at": time.time(), "kind": kind, "source": source}
        for name in _COORDINATES:
            value = coordinates.get(name)
            if value is not None and value != "":
                frame[name] = value
        if session_key:
            frame["session_key_hash"] = hashlib.sha256(session_key.encode("utf-8")).hexdigest()[:16]
        frame["payload"] = dict(payload or {})
        frame["seq"] = self.state_store.append_frame(
            frame["at"], json.dumps(frame, separators=(",", ":")))
        return frame

    def since(self, seq: int, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Retained frames newer than ``seq``, oldest first, optionally in a bounded batch."""
        return self.state_store.frames_since(seq, limit)

    def state(self) -> Dict[str, int]:
        """What ``GET /info`` reports: how far the feed has got and how far back it can replay."""
        store = self.state_store
        bounds = store.frame_bounds()
        return {"seq": bounds["seq"], "oldest": bounds["oldest"], "capacity": store.capacity}


_FEED = LiveFeed()


def live_feed() -> LiveFeed:
    """This process's view of the shared feed."""
    return _FEED
