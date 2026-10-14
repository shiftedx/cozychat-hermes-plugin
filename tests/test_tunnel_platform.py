"""The same plugin runs on native hosts and WSL; only WSL needs a LAN setup note."""

import io
import errno
import os
import sys
from types import SimpleNamespace

import pytest

from cozychat import locks
from cozychat.relay import cli, pairing, platform
from cozychat.relay.pairing import PairingStore
from cozychat.relay.runtime import Tunnel


@pytest.mark.parametrize("system,release,environ,expected", [
    ("Darwin", "25.1.0", {}, False),
    ("Windows", "11", {"WSL_DISTRO_NAME": "Ubuntu"}, False),
    ("Linux", "6.8.0-generic", {}, False),
    ("Linux", "6.6.87.2-microsoft-standard-WSL2", {}, True),
    ("Linux", "4.4.0-Microsoft", {}, True),
    ("Linux", "custom", {"WSL_INTEROP": "/run/WSL/1_interop"}, True),
    ("Linux", "custom", {"WSL_DISTRO_NAME": "Ubuntu"}, True),
])
def test_wsl_detection_is_selected_only_for_linux(system, release, environ, expected):
    assert platform.is_wsl(system=system, release=release, environ=environ) is expected


def test_native_hosts_have_no_wsl_note(monkeypatch):
    monkeypatch.setattr(platform, "is_wsl", lambda: False)
    assert platform.pairing_network_note() is None


def test_wsl_pairing_explains_nat_before_showing_a_qr(tmp_path, monkeypatch):
    monkeypatch.setattr(platform, "is_wsl", lambda: True)
    store = PairingStore(tmp_path / "relay")
    tunnel = Tunnel(store, config={}, plugin_version="0.6.0", state_version="shared-v1",
                    home=tmp_path)
    monkeypatch.setattr(tunnel, "expected_hints", lambda: [])
    monkeypatch.setattr(cli, "Gateway", lambda *args: SimpleNamespace(ensure=lambda: None))
    out = io.StringIO()
    assert cli.pair(tunnel, advertise=[], push=True, relay=None, out=out, run_listener=False) == 1
    assert "WSL2's default NAT" in out.getvalue() and "before scanning" in out.getvalue()
    assert out.getvalue().count("Hermes is running inside WSL") == 1
    assert "cozychat://pair-relay" not in out.getvalue()


@pytest.mark.parametrize("blocking", [False, True])
def test_windows_locks_byte_zero_and_only_retries_blocking_contention(tmp_path, monkeypatch, blocking):
    calls = []
    def lock(fd, mode, length):
        calls.append((os.lseek(fd, 0, os.SEEK_CUR), mode, length))
        if len(calls) == 1:
            raise OSError(errno.EACCES, "held by another process")
    monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace(locking=lock, LK_NBLCK=2))
    monkeypatch.setattr(locks.sys, "platform", "win32")
    monkeypatch.setattr(locks.time, "sleep", lambda seconds: None)
    with (tmp_path / "listener.lock").open("a+b") as handle:
        if blocking:
            locks._lock(handle, blocking=True)
            assert calls == [(0, 2, 1), (0, 2, 1)]
        else:
            with pytest.raises(OSError):
                locks._lock(handle, blocking=False)
            assert calls == [(0, 2, 1)]


def test_windows_lock_does_not_retry_io_failure(tmp_path, monkeypatch):
    def lock(fd, mode, length):
        raise OSError(errno.EIO, "not contention")
    monkeypatch.setitem(sys.modules, "msvcrt", SimpleNamespace(locking=lock, LK_NBLCK=2))
    monkeypatch.setattr(locks.sys, "platform", "win32")
    with (tmp_path / "listener.lock").open("a+b") as handle:
        with pytest.raises(OSError, match="not contention"):
            locks._lock(handle, blocking=True)


def test_pairing_pid_probe_never_sends_a_signal(monkeypatch):
    import psutil
    calls = []
    monkeypatch.setattr(psutil, "pid_exists", lambda pid: calls.append(pid) or pid == 42)
    monkeypatch.setattr(os, "kill", lambda *args: pytest.fail("liveness must not signal a process"))
    assert pairing._alive(42) and not pairing._alive(43) and not pairing._alive(0)
    assert calls == [42, 43]
