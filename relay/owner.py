"""Exactly one process per computer runs the listener (decision D25).

The plugin loads in ``hermes serve`` (Hermes Desktop's backend) and in ``hermes gateway run``, and
the person may run ``hermes cozychat pair`` beside them. Whichever holds an exclusive OS lock on
``<hermes root>/cozychat/relay/listener.lock`` runs the listener; every other copy checks again
every 2 seconds and takes over within 5 when the owner exits, because the kernel drops the lock with
the process. It is the outbox drain's pattern (``locks.claim``).

Nothing listens until the first pairing window opens: the supervisor claims the lock only while a
window is open or a phone is paired, and gives it back (closing the listener) when neither is true.
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any, Callable, List, Optional

from ..devices import write_private
from ..locks import claim
from .host import Listener, ListenerThread
from .pairing import PairingStore

logger = logging.getLogger("hermes_cli.plugins.cozychat")

TICK_SECONDS = 2.0


def listening_hints(store: PairingStore) -> List[str]:
    """Only the current lock holder's successfully bound endpoints may enter a QR."""
    if not (store.root / "listener.lock").exists():
        return []
    handle = claim(store.root / "listener.lock")
    if handle is not None:
        handle.close()
        return []  # a crashed owner's receipt is stale, even if the file survived
    try:
        hints = json.loads((store.root / "listener.json").read_text("utf-8"))["hints"]
        return hints if isinstance(hints, list) and all(isinstance(h, str) for h in hints) else []
    except (OSError, ValueError, KeyError, TypeError):
        return []


class ListenerOwner:
    """Claims the lock when there is something to listen for, and runs the listener while held."""

    def __init__(self, store: PairingStore, make_listener: Callable[[], Listener], *,
                 enabled: Callable[[], bool] = lambda: True,
                 tick_seconds: float = TICK_SECONDS) -> None:
        self.store = store
        self._make_listener = make_listener
        self._enabled = enabled
        self._tick = tick_seconds
        self._handle: Optional[Any] = None
        self._running: Optional[ListenerThread] = None
        self._stopped = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._mutex = threading.Lock()

    @property
    def lock_path(self) -> Path:
        return self.store.root / "listener.lock"

    @property
    def listener(self) -> Optional[Listener]:
        running = self._running
        return running.listener if running is not None else None

    @property
    def owns(self) -> bool:
        return self._running is not None

    def start(self) -> "ListenerOwner":
        self._thread = threading.Thread(target=self._loop, name="cozychat-lan-owner", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stopped.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(self._tick + 10)
        self._release()

    def tick(self) -> None:
        """One decision. The loop calls it; tests may too."""
        with self._mutex:
            try:
                wanted = self._enabled() and self.store.wants_listener()
            except Exception:
                logger.debug("cozychat could not read the pairing state", exc_info=True)
                wanted = False
            if wanted and self._running is None:
                self._acquire()
            elif not wanted and self._running is not None:
                self._release_locked()
            elif self._running is not None and not self._running.alive:
                self._release_locked()

    def _loop(self) -> None:
        while not self._stopped.is_set():
            try:
                self.tick()
            except Exception:
                logger.warning("cozychat listener supervision failed; will retry", exc_info=True)
            self._stopped.wait(self._tick)

    def _acquire(self) -> None:
        try:
            handle = claim(self.lock_path)
        except Exception:
            logger.warning("cozychat could not claim the listener lock", exc_info=True)
            return
        if handle is None:
            return
        running = None
        try:
            (self.store.root / "listener.json").unlink(missing_ok=True)
            # A new owner holds no session, so an attempt left by a dead one waits on nothing.
            self.store.clear_attempts()
            listener = self._make_listener()
            listener.on_bind = lambda hints: write_private(
                self.store.root / "listener.json", json.dumps({"hints": hints}).encode("utf-8"))
            running = ListenerThread(listener)
            running.start()
        except Exception:
            logger.warning("cozychat could not start the tunnel listener", exc_info=True)
            if running is not None:
                try:
                    running.stop()
                except Exception:
                    logger.debug("cozychat startup cleanup failed", exc_info=True)
                if running.alive:
                    self._handle, self._running = handle, running
                    return  # retain ownership while a slow startup still holds sockets
            handle.close()
            return
        self._handle, self._running = handle, running

    def _release(self) -> None:
        with self._mutex:
            self._release_locked()

    def _release_locked(self) -> None:
        running, handle = self._running, self._handle
        if running is not None:
            try:
                running.stop()
            except Exception:
                logger.warning("cozychat could not stop the tunnel listener", exc_info=True)
            if running.alive:
                return  # never release ownership while this process might still be listening
        self._running = self._handle = None
        if handle is not None:
            try:
                (self.store.root / "listener.json").unlink(missing_ok=True)
            finally:
                handle.close()
