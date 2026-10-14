"""The tunnel as ``register()`` assembles it: settings, the store, the listener, the owner.

The listener only ever runs in ``hermes serve`` or ``hermes gateway run`` (D25), and only when a
pairing window is open or a phone is paired. ``hermes cozychat pair`` runs one of its own for the
length of the command when no other process holds the lock; ``cli.py`` does that explicitly.

Opt-out, three equivalent switches: ``lan: false`` in the plugin config, ``COZYCHAT_LAN=0``, or
never pairing. Off means nothing listens and ``hermes cozychat pair`` refuses to show a code.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from ..feed import live_feed
from . import lan, services
from .host import Listener, ListenerConfig
from .owner import ListenerOwner, listening_hints
from .pairing import PairingStore
from .control import PhoneManagement
from .rotation import APIKeyRotation

DEFAULTS: Dict[str, Any] = {"lan": True, "lan_port": 0, "lan_bind": [], "lan_advertise": True}


def lan_enabled(config: Mapping[str, Any], environ: Optional[Mapping[str, str]] = None) -> bool:
    env = os.environ if environ is None else environ
    if str(env.get("COZYCHAT_LAN", "")).strip().lower() in ("0", "false", "no", "off"):
        return False
    return bool(config.get("lan", True))


def listener_process(argv: Optional[Sequence[str]] = None,
                     environ: Optional[Mapping[str, str]] = None) -> bool:
    """True in serve/gateway, including Hermes's isolated plugin-host children."""
    env = os.environ if environ is None else environ
    forced = str(env.get("COZYCHAT_LISTENER", "")).strip()
    if forced in ("0", "1"):
        return forced == "1"
    if env.get("HERMES_PLUGIN_HOST_PROCESS") == "1":
        return True  # Hermes owns this child's lifetime; the same lazy single-owner lock applies
    args = list((sys.argv if argv is None else argv)[1:])
    command = _subcommand(args)
    if not command:
        return False
    if command[0] == "serve":
        return True
    if command[0] == "gateway":
        rest = [a for a in command[1:] if not a.startswith("-")]
        return not rest or rest[0] == "run"
    return False


# Hermes's top-level flags that take a value (hermes_cli/_parser.py, including ``-c``'s optional
# one, which Hermes's own pre-parser also skips). Their values are never the subcommand: in
# ``hermes -p serve chat`` the profile is called serve and the command is chat.
_VALUE_FLAGS = frozenset({
    "-p", "--profile", "-z", "--oneshot", "-m", "--model", "--provider", "--reasoning",
    "-t", "--toolsets", "-r", "--resume", "-s", "--skills", "--usage-file", "--in",
    "-c", "--continue"})


def _subcommand(args: Sequence[str]) -> List[str]:
    """The words from the subcommand on. Only the first non-flag word is the subcommand, so
    ``hermes chat -q serve`` (a message) and ``hermes sessions gateway`` are not listeners."""
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            return list(args[index + 1:])
        if not token.startswith("-"):
            return list(args[index:])
        index += 2 if "=" not in token and token in _VALUE_FLAGS else 1
    return []


class Tunnel:
    """Everything one process needs to run, or pair through, the listener."""

    def __init__(self, store: PairingStore, *, config: Mapping[str, Any], plugin_version: str,
                 state_version: str, home: Path,
                 push_devices=None,
                 environ: Optional[Mapping[str, str]] = None,
                 interfaces: Optional[Callable[[], List[lan.BindAddress]]] = None) -> None:
        self.store = store
        self.config = dict(config)
        self.plugin_version = plugin_version
        self.state_version = state_version
        self.home = Path(home)
        self.files = services.FileService(
            self.home, allowed_roots=self.config.get("files_allowed_roots"),
            workspace=self.config.get("files_workspace"), plugin_state=self.store.root.parent)
        self.push_devices = push_devices
        self._environ = environ
        # Tests only (``ListenerConfig.interfaces``); never read from the plugin config.
        self._interfaces = interfaces
        self.rotation = APIKeyRotation(self.home)
        self.management = PhoneManagement(store, push_available=self._management_push_available,
            rotate=self.rotation.start, rotation_generation=lambda: self.rotation.generation(),
            rotation_ready=lambda: self.rotation.ready_generation(),
            retire_push=self._retire_push if push_devices is not None else None,
            push_cleanup_pending=self._push_cleanup_pending,
            deliver_retirements=self.push_devices.retry_retirements if push_devices is not None else None)

    def _retire_push(self, key: bytes) -> None:
        # Durable tombstones only: this runs under pairing.lock, so no relay HTTP here.
        self.push_devices.retire_phone(key, deliver=False)

    def _push_cleanup_pending(self, key: bytes) -> bool:
        return self.push_devices is not None and bool(self.push_devices.pending_retirements(key.hex()))

    def _management_push_available(self) -> bool:
        """Legacy direct-registration gate; the consented ``push_devices`` policy supersedes it."""
        return bool(self.store.settings().get("push", True)) and bool(self.config.get("relay_url"))

    def push_available(self) -> bool:
        return bool(self.config.get("relay_url")) and self.push_devices is not None

    @property
    def enabled(self) -> bool:
        return lan_enabled(self.config, self._environ)

    def secret_scope_ready(self) -> bool:
        return services.secret_scope_available()

    def api(self) -> services.ApiTarget:
        return services.discover_api(self.home, None if self._environ is None else dict(self._environ))

    def capabilities(self, hints: List[str], phone_key: Optional[bytes] = None) -> Dict[str, Any]:
        settings = self.store.settings()
        push_available = self.push_available()
        api = self.api()
        document = services.capability_document(
            plugin_version=self.plugin_version, state_version=self.state_version,
            lan_addresses=hints, push_available=push_available,
            push_paired=push_available and bool(phone_key is not None
                and self.push_devices.paired(phone_key)),
            notify_available=True,
            api_profiles=api.profiles, dashboard_available=api.dashboard is not None,
            files=self.files.capabilities(),
            relay_url=settings.get("relay") or None)
        document["services"]["control"]["device_management"] = push_available
        if not self.enabled:
            document["reach"]["lan"] = None
        document["services"]["control"]["device_management"] = True
        document["services"]["control"]["rotate_key"] = None  # D30: host authority only
        return document

    def listener_config(self, **overrides: Any) -> ListenerConfig:
        port = int(self.config.get("lan_port") or 0)
        bind = self.config.get("lan_bind") or []
        if isinstance(bind, str):
            bind = [b.strip() for b in bind.split(",") if b.strip()]
        values: Dict[str, Any] = {"port": port or None, "bind": list(bind),
                                  "advertise_mdns": bool(self.config.get("lan_advertise", True)),
                                  "interfaces": self._interfaces}
        values.update(overrides)
        return ListenerConfig(**values)

    def make_listener(self, **overrides: Any) -> Listener:
        return Listener(self.store, self.listener_config(**overrides),
                        capabilities=lambda hints: self.capabilities(hints), api=self.api,
                        files=self.files, management=self.management, feed=live_feed(),
                        phone_capabilities=self.capabilities,
                        push_handler=self.push_devices.handle if self.push_devices else None)

    def expected_hints(self) -> List[str]:
        """The hints a listener in any process would offer: same rules, same persisted port."""
        config = self.listener_config()
        port = config.port or self.store.port()
        binds = config.interfaces() if config.interfaces is not None \
            else lan.system_bind_addresses(config.vpn_interfaces, only=config.bind)
        found = [b.hint(port) for b in binds
                 if not (b.address.version == 6 and b.address.is_link_local)]
        advertised = list(self.store.settings().get("advertise") or [])
        return list(dict.fromkeys(advertised + found))

    def listening_hints(self) -> List[str]:
        return listening_hints(self.store) if self.enabled else []

    def owner(self, **kwargs: Any) -> ListenerOwner:
        return ListenerOwner(self.store, self.make_listener, enabled=lambda: self.enabled, **kwargs)


def store_for(state_root: Path) -> PairingStore:
    return PairingStore(Path(state_root) / "relay")
