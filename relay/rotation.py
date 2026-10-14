"""Full revoke uses Hermes's supported gateway restart to replace its cached API key.

Persisting .env alone does not rotate a running default API adapter. The control response therefore
reports a pending restart; the local CLI verifies the old key gets 401 before reporting success.
No service-manager or signal implementation is duplicated here: Hermes selects its OS backend.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import secrets
import subprocess
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .control import ControlError
from .services import discover_api, rotation_state
from ..devices import write_private
from ..state import state_root
from ..locks import exclusive


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class APIKeyRotation:
    def __init__(self, home: Path, *, load=importlib.import_module, spawn=subprocess.Popen,
                 probe=None, clock=time.monotonic, sleep=time.sleep) -> None:
        self.home = Path(home)
        self._load, self._spawn = load, spawn
        self._probe = probe or self._status
        self._clock, self._sleep = clock, sleep
        self._old = self._new = None
        self._port = None

    def start(self):
        try:
            requested_at = time.time()
            root = state_root(self.home) / "relay"
            root.mkdir(parents=True, exist_ok=True)
            os.chmod(root, 0o700)
            # All plugin copies share this lock, from reading the old key through spawning its
            # restart. A queued request joins the pending rotation instead of saving a second key.
            with exclusive(root / "key-rotation.lock"):
                return self._start(root, requested_at)
        except ControlError:
            raise
        except ValueError:
            raise ControlError("rotation_key_managed", 409) from None
        except (ImportError, AttributeError, SystemExit):
            raise ControlError("rotation_unavailable", 503) from None

    def _start(self, root: Path, requested_at: float):
        config = self._load("hermes_cli.config")
        if Path(config.get_hermes_home()).resolve() != self.home.resolve():
            raise ControlError("rotation_profile_mismatch", 409)
        data = config.require_readable_config_before_write(self.home / "config.yaml")
        # An explicit adapter key or managed secret has its own authority. Never overwrite it
        # and claim that changing .env revoked it.
        if data.get("platforms", {}).get("api_server", {}).get("extra", {}).get("key"):
            raise ControlError("rotation_key_managed", 409)
        config.require_env_writable("API_SERVER_KEY", "set")
        target = discover_api(self.home)
        if target.secret_scope_missing:
            raise ControlError("rotation_unavailable", 503)
        if not target.key:
            raise ControlError("rotation_key_missing", 409)
        previous = rotation_state(self.home)
        if previous.get("restart_started") and previous.get("key_digest") == _digest(target.key) and (
                previous.get("pending") or previous.get("requested_at", 0) >= requested_at):
            self._old, self._new, self._port = None, target.key, target.port
            return {"rotated": not previous.get("pending"),
                    "rotation_pending": bool(previous.get("pending"))}
        gateway = self._load("hermes_cli.gateway")
        launchers = self._load("hermes_cli._launchers")
        argv = launchers.runtime_command(gateway.PROJECT_ROOT, ["gateway", "restart"],
                                          python=gateway.get_python_path(), home=str(self.home))
        new = secrets.token_hex(32)
        config.save_env_value("API_SERVER_KEY", new)
        if discover_api(self.home).key != new:
            raise ControlError("rotation_write_failed", 503)
        self._old, self._new, self._port = target.key, new, target.port
        retired = previous.get("retired", [])
        if not isinstance(retired, list):
            retired = []
        # Keep every retired digest: a Desktop process may have cached any earlier environment.
        retired = list(dict.fromkeys(retired + [_digest(target.key)]))
        marker = {"requested_at": time.time(),
            "retired": retired, "key_digest": _digest(new), "generation": secrets.token_hex(16),
            "pending": True, "restart_started": False}
        write_private(root / "key-rotation.json", json.dumps(marker).encode())
        # Closed stdio keeps a web/control request from waiting for terminal input. A new process
        # is necessary when the caller is itself inside the gateway that must restart.
        env = dict(os.environ)
        # A restarted gateway must reload .env, not inherit the key cached by its parent copy.
        env.pop("API_SERVER_KEY", None)
        self._spawn(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, env=env, **spawn_options(os.name))
        marker["restart_started"] = True
        write_private(root / "key-rotation.json", json.dumps(marker).encode())
        return {"rotated": False, "rotation_pending": True}

    def generation(self):
        return rotation_state(self.home).get("generation")

    def ready_generation(self):
        marker = rotation_state(self.home)
        generation = marker.get("generation")
        target = discover_api(self.home)
        if not generation or not target.key or marker.get("key_digest") != _digest(target.key):
            return None
        if marker.get("pending"):
            if self._probe(target.port, target.key) != 200:
                return None
            if not self._complete(generation, target.key):
                return None
        return generation

    def _complete(self, generation, key):
        root = state_root(self.home) / "relay"
        with exclusive(root / "key-rotation.lock"):
            marker = rotation_state(self.home)
            if marker.get("generation") == generation and marker.get("key_digest") == _digest(key):
                marker["pending"] = False
                write_private(root / "key-rotation.json", json.dumps(marker).encode())
                return True
        return False

    def wait(self, timeout: float = 60.0) -> bool:
        if self._new is None:
            return False
        deadline = self._clock() + timeout
        while self._clock() < deadline:
            generation = self.generation()
            target = discover_api(self.home)
            if target.key and self._probe(target.port, target.key) == 200 and (
                    self._old is None or self._probe(target.port, self._old) == 401):
                if self._complete(generation, target.key):
                    self._new = target.key
                    return True
            self._sleep(0.25)
        return False

    @staticmethod
    def _status(port: int, key: str):
        request = Request(f"http://127.0.0.1:{port}/v1/models",
                          headers={"Authorization": f"Bearer {key}"})
        try:
            with build_opener(ProxyHandler({}), _NoRedirect()).open(request, timeout=0.2) as response:
                return response.status
        except HTTPError as error:
            try:
                return error.code
            finally:
                error.close()
        except (OSError, URLError):
            return None


def spawn_options(platform_name: str):
    """Detach the restart command on Windows as well as POSIX; no shell or Unix-only imports."""
    if platform_name == "nt":
        return {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200) |
                                 getattr(subprocess, "DETACHED_PROCESS", 0x8)}
    return {"start_new_session": True}


def _digest(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()
