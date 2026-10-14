"""The one-process-of-many lock: whoever holds an OS lock on a file does the job.

Used by the outbox drain (``outbox.lock``) and the tunnel listener (``relay/listener.lock``). The
plugin is loaded in several Hermes processes at once; the lock picks one of them, and the others
take over when it exits because the kernel drops the lock with the process.
"""

from __future__ import annotations

import errno
import os
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional


def _lock(handle: Any, *, blocking: bool) -> None:
    if sys.platform == "win32":
        import msvcrt

        # Lock the same byte in every process. Closing the descriptor releases it, including on
        # process death; never unlink the file, which would allow two different lock identities.
        while True:
            handle.seek(0)
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                return
            except OSError as error:
                if not blocking or error.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                    raise
                time.sleep(0.05)
    else:
        import fcntl

        flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
        fcntl.flock(handle.fileno(), flags)


def _open(lock_path: Path) -> Any:
    return os.fdopen(os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600), "r+b")


def claim(lock_path: Path) -> Optional[Any]:
    """An open handle holding the lock, or None when another process (or handle) holds it.

    Closing the handle releases the lock.
    """
    # No mkdir: a thread outliving an uninstall would otherwise put the shared directory back,
    # empty, on a computer the person had just cleaned. Seen after a live uninstall on 2026-09-15.
    try:
        # 0600 like every other file the plugin writes (P5); the lock holds no secret, but there
        # is no reason for other users to open it.
        handle = _open(lock_path)
    except OSError:
        return None
    try:
        _lock(handle, blocking=False)
        return handle
    except OSError:
        handle.close()
        return None


@contextmanager
def exclusive(lock_path: Path) -> Iterator[None]:
    """Wait for a state-file transaction's lock; failures propagate without writing unlocked."""
    with _open(lock_path) as handle:
        _lock(handle, blocking=True)
        yield
