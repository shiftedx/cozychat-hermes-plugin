"""Host platform facts shared by pairing surfaces and Hermes login-service adapters."""

from __future__ import annotations

import os
import platform
import sys
from typing import Mapping, Optional


def service_platform(system: Optional[str] = None) -> str:
    found = sys.platform if system is None else system
    if found == "darwin":
        return "launchd"
    if found == "win32":
        return "windows"
    if found.startswith("linux"):
        return "systemd"
    raise RuntimeError("This computer cannot start Hermes at login.")


def is_wsl(*, system: Optional[str] = None, release: Optional[str] = None,
           environ: Optional[Mapping[str, str]] = None) -> bool:
    system = platform.system() if system is None else system
    release = platform.release() if release is None else release
    env = os.environ if environ is None else environ
    return system == "Linux" and ("microsoft" in release.lower() or "wsl" in release.lower()
                                  or bool(env.get("WSL_INTEROP") or env.get("WSL_DISTRO_NAME")))


def pairing_network_note() -> Optional[str]:
    if not is_wsl():
        return None
    return ("Hermes is running inside WSL. WSL2's default NAT network is not reachable from your "
            "phone over home Wi-Fi; use Hermes on Windows or an already configured mirrored "
            "network or forwarding to the current private WSL address and listener port before "
            "scanning. This plugin does not configure Windows networking.")


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    # os.kill(pid, 0) can terminate a process on Windows. Retain the attempt if psutil is missing.
    try:
        import psutil
        return psutil.pid_exists(pid)
    except ImportError:
        return True
