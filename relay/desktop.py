"""The Desktop pairing surface. Decisions travel through PairingStore to the listener owner."""

from __future__ import annotations

import base64
import importlib
import io
import json
import secrets
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.error import URLError
from urllib.request import ProxyHandler, Request, build_opener

from ..devices import write_private
from ..locks import exclusive
from .pairing import pairing_link
from .reachable import HermesService, Reachable
from .platform import pairing_network_note
from .runtime import Tunnel
from .control import ControlError
from .services import UPDATE_HERMES_COPY, loopback_host, rotation_state, usable_api_key

MAX_CAPABILITIES_BYTES = 1024 * 1024


class PageError(RuntimeError):
    def __init__(self, message: str, status: int = 409) -> None:
        super().__init__(message)
        self.status = status


class Gateway:
    """Start a gateway with loopback API access. Never replace a gateway that is already running."""

    def __init__(self, tunnel: Tunnel, service: HermesService, *, load=importlib.import_module,
                 clock=time.monotonic, sleep=time.sleep) -> None:
        self.tunnel, self.service = tunnel, service
        self._load, self._clock, self._sleep = load, clock, sleep

    def ready(self) -> bool:
        target = self.tunnel.api()
        if not usable_api_key(target.key) or not loopback_host(target.bind_host):
            return False
        request = Request(f"http://127.0.0.1:{target.port}/v1/capabilities",
                          headers={"Authorization": f"Bearer {target.key}"})
        try:
            with build_opener(ProxyHandler({})).open(request, timeout=1) as response:
                body = response.read(MAX_CAPABILITIES_BYTES + 1)
                if len(body) > MAX_CAPABILITIES_BYTES:
                    return False
                data = json.loads(body)
            return data.get("platform") == "hermes-agent" \
                and data.get("object") == "hermes.api_server.capabilities"
        except (OSError, URLError, ValueError, AttributeError):
            return False

    def configure(self) -> None:
        config = self._load("hermes_cli.config")
        # The active profile is Hermes's authority. Do not write a root/profile selected by a
        # different loader copy in a long-lived Desktop process.
        if Path(config.get_hermes_home()).resolve() != self.tunnel.home.resolve():
            raise PageError("Open CozyChat in the Hermes profile you want to connect to.")
        target = self.tunnel.api()
        path = self.tunnel.home / "config.yaml"
        data = config.require_readable_config_before_write(path)
        entry = data.setdefault("platforms", {}).setdefault("api_server", {})
        extra = entry.setdefault("extra", {})
        port_text = config.get_env_value_prefer_dotenv("API_SERVER_PORT") or extra.get("port") or target.port
        try:
            port = int(port_text)
            if not 0 < port < 65536:
                raise ValueError
        except (ValueError, TypeError):
            raise PageError("Choose a valid port in Hermes's API Server settings, then pair again.")
        config.require_env_writable("API_SERVER_KEY", "set")
        config.require_env_writable("API_SERVER_HOST", "set")
        config.require_env_writable("API_SERVER_PORT", "set")
        # Hermes uses a usable API_SERVER_KEY from the environment/dotenv over extra.key, and
        # extra.key otherwise; target.key is exactly the key in force. Never rotate it, and
        # bring the other authority up to it.
        key = target.key
        if not usable_api_key(key):
            key = secrets.token_hex(32)
        config.save_env_value("API_SERVER_KEY", key)
        config.save_env_value("API_SERVER_HOST", "127.0.0.1")
        config.save_env_value("API_SERVER_PORT", str(port))
        entry["enabled"] = True
        # The adapter reads extra.key first; the gateway env loader can overwrite it. Keep both
        # authorities equal so a Desktop-only setup and a gateway return the same credential.
        extra.update({"host": "127.0.0.1", "port": port, "key": key})
        config.atomic_config_write(path, data)

    def _start_service(self) -> bool:
        # An installed definition is not a loaded job. If CozyChat's own job will not start,
        # start the gateway the normal way instead of failing pairing.
        try:
            self.service.start()
            return True
        except (RuntimeError, OSError, subprocess.SubprocessError):
            return False

    def ensure(self, before_start=lambda: None) -> None:
        gateway = self._load("hermes_cli.gateway")
        ready = self.ready()
        if not ready:
            # Persist phone access before asking for a manual restart, so that restart can
            # actually enable it. No lifecycle command touches the running process here.
            self.configure()
            if gateway.find_gateway_pids():
                raise PageError("Restart Hermes after your current chat finishes to turn on "
                                "phone access. Then choose Pair a phone.")
        before_start()
        if ready:
            return
        if not self.service.hermes_installed() and self.service.installed() and self._start_service():
            pass
        elif self.service.kind == "windows":
            self.service.module()._spawn_detached(home=self.tunnel.home)
        else:
            launchers = self._load("hermes_cli._launchers")
            command = launchers.runtime_command(gateway.PROJECT_ROOT, ["gateway", "run"],
                                                 python=gateway.get_python_path(),
                                                 home=str(self.tunnel.home))
            logs = self.tunnel.home / "logs"
            logs.mkdir(parents=True, exist_ok=True)
            with (logs / "cozychat-gateway.log").open("ab") as log:
                subprocess.Popen(command, cwd=self.tunnel.home, stdin=subprocess.DEVNULL,
                                 stdout=log, stderr=log, start_new_session=True)
        deadline = self._clock() + 30
        while self._clock() < deadline:
            if self.ready():
                return
            self._sleep(0.2)
        raise PageError("Hermes is still starting. Choose Pair a phone to try again.", 503)


class PairingPage:
    def __init__(self, tunnel: Tunnel, *, wake_listener=lambda: None,
                 reachable: Optional[Reachable] = None, gateway: Optional[Gateway] = None,
                 clock=time.time, network_note=pairing_network_note) -> None:
        self.tunnel, self.store = tunnel, tunnel.store
        self.reachable = reachable or Reachable(self.store)
        self.gateway = gateway or Gateway(tunnel, self.reachable.service)
        self._wake, self._clock, self._network_note = wake_listener, clock, network_note

    @contextmanager
    def setup_locked(self):
        self.store.ensure()
        with exclusive(self.store.root / "desktop.lock"):
            yield

    def state(self) -> Dict[str, Any]:
        rotation = rotation_state(self.tunnel.home)
        if rotation.get("pending"):
            self.tunnel.rotation.ready_generation()
            rotation = rotation_state(self.tunnel.home)
        window, attempt = self.store.window(), self.store.attempt()
        if window is None or attempt is not None and attempt.window_id != window.id:
            attempt = None
        pending = None if attempt is None else {
            "id": attempt.id, "phone_name": attempt.phone_name, "code": attempt.code,
            "decision": attempt.decision}
        return {"first_visit": not (self.store.root / "desktop.json").exists()
                               and not self.store.phones() and window is None,
                "window": {"id": window.id, "exp": window.exp,
                           "remaining": max(0, window.exp - int(self._clock()))} if window else None,
                "update_required": None if self.tunnel.secret_scope_ready() else UPDATE_HERMES_COPY,
                "pending": pending, "phones": self.phones(),
                "push_cleanup_pending": bool(self.tunnel.push_devices
                                             and self.tunnel.push_devices.pending_retirements()),
                "reachable": self.reachable.state(),
                "rotation": {"available": self.tunnel.management.can_rotate,
                             "pending": bool(rotation.get("pending"))},
                "wsl_note": self._network_note()}

    def _require_secret_scope(self) -> None:
        if not self.tunnel.secret_scope_ready():
            raise PageError(UPDATE_HERMES_COPY, 503)

    def open(self, *, automatic: bool = False) -> Dict[str, Any]:
        self._require_secret_scope()
        if not self.tunnel.enabled:
            raise PageError("Turn on home-network access in CozyChat's plugin settings to pair.")
        with self.setup_locked():
            if automatic and not self.state()["first_visit"]:
                return self.state()
            # Configure/start before publishing a QR. The default is D26; an explicit off
            # choice persists across page visits and later pairing windows.
            def keep_reachable():
                # Reachable.set records native failures as a note; nothing here blocks pairing.
                if self.reachable.read().get("enabled", True):
                    self.reachable.set(True)

            self.gateway.ensure(keep_reachable)
            window = self.store.window()
            created = window is None
            if created:
                window = self.store.open_window()
            self._wake()
            deadline = time.monotonic() + 5
            while not self.tunnel.listening_hints() and time.monotonic() < deadline:
                time.sleep(0.05)
            if not self.tunnel.listening_hints():
                if created:
                    self.store.cancel_window(window.id)
                raise PageError("Connect this computer to your home Wi-Fi, then choose Pair a phone.")
            write_private(self.store.root / "desktop.json", b'{"visited":true}')
            return self.state()

    def qr(self) -> Dict[str, Any]:
        self._require_secret_scope()
        window = self.store.window()
        if window is None:
            raise PageError("This code has expired. Choose Pair a phone for a new one.", 410)
        try:
            import qrcode
            from qrcode.image.pure import PyPNGImage
        except ImportError:
            raise PageError("Update the CozyChat plugin to show a pairing code.", 503)
        self._wake()
        hints = self.tunnel.listening_hints()
        if not hints:
            raise PageError("Connect this computer to your home Wi-Fi, then choose Pair a phone.")
        link = pairing_link(self.store.host_public(), window, hints)
        code = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=4, box_size=6)
        code.add_data(link)
        code.make(fit=True)
        image = code.make_image(image_factory=PyPNGImage)
        output = io.BytesIO()
        image.save(output)
        # The expiry may have passed while rendering; never republish a closed window's QR.
        if self.store.window() != window:
            raise PageError("This code has expired. Choose Pair a phone for a new one.", 410)
        return {"window_id": window.id, "exp": window.exp, "link": link,
                "png": "data:image/png;base64," + base64.b64encode(output.getvalue()).decode("ascii")}

    def decide(self, attempt_id: str, approve: bool) -> Dict[str, Any]:
        if not isinstance(attempt_id, str) or not attempt_id:
            raise PageError("Choose the phone waiting on this page.", 400)
        if not self.store.decide(attempt_id, approve):
            raise PageError("That phone is no longer waiting. Scan the code again.")
        # The listener alone settles after P1's transport proof. The API never adds a key itself.
        return {"ok": True, "id": attempt_id, "decision": "approve" if approve else "refuse"}

    def phones(self):
        return self.tunnel.management.phones()

    def remove(self, phone_id: str, *, rotate: bool = False) -> Dict[str, Any]:
        try:
            result = self.tunnel.management.revoke(phone_id, rotate=rotate)
        except ControlError as error:
            raise PageError("Hermes could not remove this phone.", error.status) from error
        if not result["removed"] and not result.get("pending_cleanup"):
            raise PageError("This phone has already been removed.", 404)
        return {"ok": True, **result}

    def retry_push_cleanup(self) -> Dict[str, Any]:
        if self.tunnel.push_devices is None:
            return {"pending_cleanup": False}
        self.tunnel.push_devices.retry_retirements()
        return {"pending_cleanup": bool(self.tunnel.push_devices.pending_retirements())}

    def set_reachable(self, enabled: bool) -> Dict[str, Any]:
        if type(enabled) is not bool:
            raise PageError("Choose whether to keep Hermes reachable.", 400)
        with self.setup_locked():
            if self.reachable.service.hermes_installed():
                return self.reachable.state()
            if enabled:
                self.gateway.ensure(lambda: self.reachable.set(True))
                return self.reachable.state()
            return self.reachable.set(False)

    def rotate(self) -> Dict[str, Any]:
        try:
            return {"ok": True, **self.tunnel.management.rotate()}
        except ControlError as error:
            raise PageError("Hermes could not rotate the API key. Check its API Server settings.",
                            error.status) from error
