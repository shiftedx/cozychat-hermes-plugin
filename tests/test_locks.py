"""The same lock interface selects POSIX flock or a Windows byte lock."""

import errno
import sys
from types import SimpleNamespace

import pytest

from cozychat import locks


@pytest.mark.parametrize("platform", ["darwin", "linux", "win32"])
@pytest.mark.parametrize("blocking", [True, False])
def test_lock_backend_selection(monkeypatch, tmp_path, platform, blocking):
    calls = []
    monkeypatch.setattr(locks.sys, "platform", platform)
    monkeypatch.setitem(sys.modules, "fcntl", SimpleNamespace(
        LOCK_EX=2, LOCK_NB=4, flock=lambda fd, flags: calls.append(("posix", fd, flags))))
    monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace(
        LK_NBLCK=20, locking=lambda fd, flags, count: calls.append(("windows", fd, flags, count))))
    with (tmp_path / "lock").open("w+b") as handle:
        handle.write(b"lock")
        handle.flush()
        locks._lock(handle, blocking=blocking)
        if platform == "win32":
            assert calls == [("windows", handle.fileno(), 20, 1)]
            assert handle.tell() == 0
        else:
            assert calls == [("posix", handle.fileno(), 2 if blocking else 6)]


def test_two_handles_cannot_claim_the_same_lock(tmp_path):
    path = tmp_path / "lock"
    first = locks.claim(path)
    assert first is not None
    try:
        assert locks.claim(path) is None
    finally:
        first.close()
    successor = locks.claim(path)
    assert successor is not None
    successor.close()


def test_claim_does_not_recreate_an_uninstalled_directory(tmp_path):
    assert locks.claim(tmp_path / "absent" / "lock") is None
    assert not (tmp_path / "absent").exists()


def test_windows_blocking_lock_retries_contention_but_propagates_other_errors(tmp_path, monkeypatch):
    calls = []
    failures = [PermissionError(errno.EACCES, "busy"), None]
    def locking(*args):
        calls.append(args)
        error = failures.pop(0)
        if error:
            raise error
    monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace(LK_NBLCK=42, locking=locking))
    monkeypatch.setattr(locks.sys, "platform", "win32")
    monkeypatch.setattr(locks.time, "sleep", lambda seconds: None)
    with (tmp_path / "lock").open("w+b") as handle:
        locks._lock(handle, blocking=True)
        assert len(calls) == 2
        failures.append(OSError(errno.EBADF, "invalid descriptor"))
        with pytest.raises(OSError):
            locks._lock(handle, blocking=True)
