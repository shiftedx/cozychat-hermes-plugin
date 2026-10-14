"""CozyChat companion plugin: notify a paired phone about this Hermes, without a gateway.

``register`` wires the pieces and gets out of the way. Every hook body is wrapped by
:func:`_guarded`, so the worst a bug or a full disk in here can do is drop a notification — a turn
never sees an exception from this plugin. The network never happens on a hook either: hooks enqueue
into the outbox and one daemon thread drains it.

State lives in ONE directory per computer, ``<root>/cozychat/``, not beside this file. Hermes loads
this plugin in two processes and usually two profiles — hooks in ``hermes gateway``, routes in
``hermes serve`` — and anything written per plugin directory is therefore written twice and read by
nobody. ``state.py`` says why the root home is the one path both agree on. An older layout beside
this file is moved there on first load.
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Any, Callable, Dict, Optional

# Re-exported, not merely imported: `dashboard/api.py` is loaded as a standalone module and reaches
# the ring, the approval desk and the Lock Screen cards through this package's own attributes.
from .approvals import ApprovalTransport, approval_desk, transport_selected
from .devices import DeviceStore
from .events import Emitter
from .feed import live_feed
from .local_push import NotifySubscriptions
from .locks import claim as _claim
from .activities import live_activities, migrate_registrations
from .push import Outbox, Relay
from .relay import cli as tunnel_cli
from .relay import runtime as tunnel_runtime
from .relay.desktop import PairingPage
from .relay.compatibility import RELAY_PROTO
from .relay.push_devices import PushDevices
from .state import STATE_VERSION, hermes_home, migrate_plugin_dir, shared_state

VERSION = "0.6.0"
DRAIN_INTERVAL_SECONDS = 2.0

logger = logging.getLogger("hermes_cli.plugins.cozychat")
_pairing_page = None


def pairing_page():
    """The Desktop routes use the config and listener supervisor registered in this process."""
    if _pairing_page is None:
        raise RuntimeError("Enable the CozyChat plugin in Hermes to pair your phone.")
    return _pairing_page

_DEFAULTS: Dict[str, Any] = {
    "relay_url": "https://push.cozylabs.ai",
    "push_replies": True,
    "push_approvals": True,
    "push_rooms": True,
    "mute_subagents": True,
    "preview_mode": "sealed",
    # The phone tunnel's listener on the home network (relay/runtime.py).
    **tunnel_runtime.DEFAULTS,
}


def register(ctx) -> None:
    """Hermes plugin entry point."""
    global _pairing_page
    home = Path(__file__).resolve().parent
    config = {key: ctx.get_config(key, default) for key, default in _DEFAULTS.items()}
    config["profile_name"] = getattr(ctx, "profile_name", "default")

    state = shared_state()
    migrate_plugin_dir(home, state.root)
    migrate_registrations(home / "live-activities.json", state)

    desk = approval_desk()
    store = DeviceStore(state.root)
    outbox = Outbox(state.root / "outbox.sqlite")
    allows_device = lambda device_id, profile: store.consented(device_id, profile)
    relay = Relay(str(config["relay_url"]), allows=lambda push_id: push_devices.allows(push_id),
                  allows_registration=allows_device)
    push_devices = PushDevices(store, relay)
    outbox.push_devices = push_devices
    outbox.live_authority = push_devices.allows_live_activity
    # Configured before the emitter, because the emitter's first hook may be the one that updates a
    # card a phone registered while the gateway was down.
    live_activities().configure(
        outbox=outbox, relay=relay,
        allows_device=allows_device, retire_push=push_devices.retire_registration)
    emitter = Emitter(store, outbox, config, desk=desk)

    for hook, handler in (
        ("on_stream_start", emitter.stream_start),
        ("on_stream_delta", emitter.stream_delta),
        ("on_stream_end", emitter.stream_end),
        ("on_interim_message", emitter.interim_message),
        ("pre_tool_call", emitter.tool_started),
        ("post_tool_call", emitter.tool_completed),
        ("subagent_start", emitter.subagent_start),
        ("subagent_stop", emitter.subagent_stop),
        ("agent_loop_stopped", emitter.loop_stopped),
        ("on_session_end", emitter.session_end),
        ("pre_approval_request", emitter.approval_pending),
        ("post_approval_response", emitter.approval_resolved),
        ("on_room_member_activity", emitter.room_activity),
    ):
        ctx.register_hook(hook, _guarded(hook, handler))

    async def send(pconfig, chat_id, message, *, thread_id=None, media_files=None,
                   force_document=False) -> Dict[str, Any]:
        """``deliver: cozychat`` for cron, with no gateway in the process."""
        queued = emitter.cron_send(str(chat_id or thread_id or "cozychat"), str(message))
        if not queued:
            return {"error": "cozychat: no phone is paired with this Hermes"}
        return {"success": True, "platform": "cozychat", "chat_id": str(chat_id or ""),
                "message_id": f"queued:{queued}"}

    isolated_host = os.environ.get("HERMES_PLUGIN_HOST_PROCESS") == "1"
    # These two ctx surfaces hold live gateway handles and Hermes forbids them in a host child.
    if not isolated_host:
        ctx.register_platform(
            # No probe: `push` imports cryptography at module scope and it is a Hermes core dependency,
            # so an interpreter that cannot seal never got as far as importing this package.
            name="cozychat", label="CozyChat", adapter_factory=_no_adapter, check_fn=lambda: True,
            # Never an INBOUND platform. The gateway auto-enables any registered platform whose entry
            # offers no `is_connected` (`gateway/config_env.py:404` applies its credential gate only
            # when one is given), then asks `_no_adapter` for an adapter it cannot have and logs
            # "Failed to create adapter for platform 'CozyChat'" with a traceback on every start.
            # Delivery is untouched: a cron `deliver: cozychat` resolves `standalone_sender_fn` through
            # `platform_registry.get`, which never reads `config.platforms[...].enabled`.
            is_connected=lambda _config: False,
            standalone_sender_fn=send, emoji="\U0001f4f2", pii_safe=True,
            install_hint="CozyChat delivers notifications only; pair a phone from the app.")

    # Read here, in the process whose config decides it, and written where the route can see it:
    # `/info` is served by a different process, usually a different profile, and its own config has
    # nothing to say about whether THIS gateway will ask a phone.
    state.note_transport(hermes_home(), transport_selected() and not isolated_host)

    # Registered unconditionally, ACTIVE only when the owner's config says
    # `security.approval.transport: cozychat`. That gate is the host's (`plugins.py`: "inactive
    # until security.approval.transport: <name> selects it"), so a second gate here would only be
    # a second thing to disagree with it.
    if not isolated_host:
        ctx.register_approval_transport("cozychat", ApprovalTransport(desk, emitter).present)

    stop = _start_drain(relay, store, outbox, state.root / "outbox.lock",
                        sweep=lambda: NotifySubscriptions(state).release_due(outbox))
    ctx.on_unload(stop)

    def tunnel() -> tunnel_runtime.Tunnel:
        return tunnel_runtime.Tunnel(
            tunnel_runtime.store_for(state.root), config=config, plugin_version=VERSION,
            state_version=STATE_VERSION, home=hermes_home(),
            push_devices=push_devices)

    # `hermes cozychat pair`. Older Hermes builds without plugin CLI commands simply lack it.
    register_cli = getattr(ctx, "register_cli_command", None)
    if register_cli is not None:
        register_cli(name="cozychat", help="Pair CozyChat on your phone with this computer",
                     setup_fn=tunnel_cli.setup, handler_fn=tunnel_cli.handler(tunnel),
                     description="Pair CozyChat on your phone with this Hermes over your home "
                                 "network.")

    # The listener runs in `hermes serve` or `hermes gateway run`, never in a passing CLI command,
    # and in one of them only (relay/owner.py). It claims nothing until a pairing window opens.
    instance = tunnel()
    owner = None
    if tunnel_runtime.listener_process():
        try:
            owner = instance.owner().start()
        except Exception:
            logger.warning("cozychat listener could not start; Hermes will keep running",
                           exc_info=True)
    # A hosted API worker has its own argv, so it need not be the listener process. Its routes
    # still open/decide through the same store; the supervisor in serve/gateway owns the socket.
    _pairing_page = PairingPage(instance, wake_listener=owner.tick if owner else lambda: None)

    def stop_pairing() -> None:
        global _pairing_page
        _pairing_page = None
        if owner is not None:
            owner.stop()

    ctx.on_unload(stop_pairing)


def _guarded(name: str, handler: Callable[..., Any]) -> Callable[..., None]:
    """A hook body that cannot reach the turn it was called from."""
    def call(*args, **kwargs) -> None:
        try:
            handler(*args, **kwargs)
        except Exception:
            logger.debug("cozychat %s hook failed", name, exc_info=True)
    call.__name__ = f"cozychat_{name}"
    return call


def _start_drain(relay: Relay, store: DeviceStore, outbox: Outbox,
                 lock_path: Path, sweep: Optional[Callable[[], Any]] = None) -> Callable[[], None]:
    """One daemon thread doing every network call this plugin makes. Returns its stopper.

    ONE OF THEM, not one per process. The outbox is now a shared file, so every process that loaded
    the plugin would otherwise drain the same rows and the phone would get every notification twice.
    The lock decides which one sends; a process that cannot take it skips the tick and tries again,
    so the survivor picks the queue up when the holder exits.
    """
    stopped = threading.Event()

    def loop() -> None:
        while not stopped.wait(DRAIN_INTERVAL_SECONDS):
            handle = _claim(lock_path)
            if handle is None:
                continue
            try:
                if sweep is not None:
                    sweep()
                policy = getattr(outbox, "push_devices", None)
                if policy is not None:
                    policy.retry_retirements()
                outbox.drain(relay, store)
            except Exception:
                logger.debug("cozychat outbox drain failed", exc_info=True)
            finally:
                handle.close()
        outbox.close()

    threading.Thread(target=loop, name="cozychat-outbox", daemon=True).start()
    return stopped.set


def _no_adapter(_config) -> Any:
    raise RuntimeError(
        "cozychat is a delivery-only platform: it pushes to paired phones and has no inbound "
        "adapter. Use it as a cron 'deliver' target.")
