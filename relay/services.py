"""What a stream may reach: the services allowlist (contract section 7).

``api``
    Raw bytes to Hermes's own API Server on loopback. Hermes's bearer auth applies inside the
    stream; the plugin never reads or rewrites a request.
``dashboard``
    Raw HTTP and WebSocket bytes to the running Hermes Dashboard on loopback.
``control``
    Newline-delimited JSON between the phone and this plugin. ``info`` answers the capability
    document and ``bootstrap`` the API key and port, both only once the phone is approved. Before
    that the stream exists to carry the ``pairing.approved`` event.
``files``
    Bounded inbox uploads and handle-anchored reads under host-configured roots. Hidden files,
    symlinks, hardlinks and Hermes/plugin state are refused by the authoritative host policy. Present only when a FileService is available.
``notify``
    Newline-delimited live notification envelopes, heartbeats and delivery receipts. It tails from
    the current shared-feed sequence, so it deliberately has no offline replay.

Every other name closes the stream with code 1, and nothing reaches an arbitrary port. Before
approval only ``control`` opens at all; anything else is refused by policy (code 3).
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import http.client
import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import quote

from ..feed import LiveFeed
from ..local_push import NotifySubscriptions
from ..push import Outbox
from ..state import state_root

from . import framing
from .compatibility import RELAY_PROTO
from .control import ControlError, PhoneManagement
from .mux import Mux, Stream, StreamClose
from .files import FileService

DEFAULT_API_PORT = 8642
CONNECT_TIMEOUT_SECONDS = 5.0
MAX_CONTROL_LINE = 64 * 1024
MAX_NOTIFY_LINE = 8192
NOTIFY_BATCH = 32
NOTIFY_POLL_SECONDS = 0.05
# Heartbeats are sent on a fixed cadence whatever the event traffic, and only their receipts renew
# the suppression lease. No receipt within the deadline withdraws suppression and closes the stream,
# so a silent Wi-Fi departure suppresses away push for at most interval + deadline.
NOTIFY_HEARTBEAT_SECONDS = 2.0
NOTIFY_ACK_TIMEOUT_SECONDS = 4.0
NOTIFY_FILTERS = frozenset(("replies", "approvals", "rooms", "subagents"))


@dataclass(frozen=True)
class DashboardTarget:
    port: int
    token: str
    host: str = "127.0.0.1"


def discover_dashboard(home: Path, env: Dict[str, str], file_values: Dict[str, str]) -> Optional[DashboardTarget]:
    token = env.get("HERMES_DASHBOARD_SESSION_TOKEN") or file_values.get("HERMES_DASHBOARD_SESSION_TOKEN")
    if not token or len(token) < 16:
        return None
    try:
        port = int(env.get("HERMES_DASHBOARD_PORT") or file_values.get("HERMES_DASHBOARD_PORT") or "9119")
        if not 0 < port < 65536:
            return None
    except ValueError:
        return None
    # Availability is advertised only for a running, ungated Hermes Dashboard. No server is started,
    # restarted or exposed on the LAN here. This bounded loopback probe uses cross-platform stdlib.
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=0.2)
    try:
        connection.request("GET", "/api/health")
        response = connection.getresponse()
        body = json.loads(response.read(65537))
        if response.status == 200 and body.get("version") and body.get("auth_required") is False:
            return DashboardTarget(port, token)
    except (OSError, ValueError, AttributeError, http.client.HTTPException):
        pass
    finally:
        connection.close()
    return None


@dataclass(frozen=True)
class ApiTarget:
    """Hermes's API Server, as the gateway in this Hermes home runs it. Loopback, always."""

    port: int
    key: Optional[str]
    host: str = "127.0.0.1"
    profiles: Tuple[str, ...] = ("default",)
    profile_keys: Dict[str, str] = field(default_factory=dict, repr=False)
    bind_host: str = "127.0.0.1"
    dashboard: Optional[DashboardTarget] = None
    secret_scope_missing: bool = False

    def key_for(self, profile: str) -> Optional[str]:
        return self.key if profile == "default" else self.profile_keys.get(profile)


def usable_api_key(value: Any) -> bool:
    """Faithful port of hermes_cli.auth.has_usable_secret(min_length=16).

    Importing auth discovers provider plugins. Keep this read-only check independent of that
    initialization; an AST parity test pins the upstream placeholder rules.
    """
    if not isinstance(value, str):
        return False
    cleaned = value.strip()
    lowered = cleaned.lower()
    if len(cleaned) < 16 or lowered in {
            "*", "**", "***", "changeme", "your_api_key", "your_api_key_here", "your-api-key",
            "placeholder", "example", "dummy", "null", "none"}:
        return False
    if lowered.startswith("your_") and lowered.endswith("_here"):
        return False
    for prefix in ("sk-", "ghp_", "hf_"):
        if lowered.startswith(prefix):
            tail = lowered[len(prefix):]
            if tail and all(char == "x" for char in tail):
                return False
    stripped = lowered.replace(" ", "").replace("-", "").replace("_", "")
    return not (stripped and all(char == "x" for char in stripped))


def loopback_host(value: Any) -> bool:
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return value == "localhost"


def live_gateway_status(root: Path) -> Dict[str, Any]:
    try:
        from gateway.status import read_runtime_status, get_runtime_status_running_pid
        status = read_runtime_status(root / "gateway_state.json")
        if isinstance(status, dict) and get_runtime_status_running_pid(status, expected_home=root):
            return status
    except (ImportError, OSError, ValueError):
        pass
    return {}


UPDATE_HERMES_COPY = "Update Hermes to use CozyChat"


def discover_api(home: Path, environ: Optional[Dict[str, str]] = None) -> ApiTarget:
    """The root loopback listener and each named route's profile-scoped credential.

    D34: credentials come only from Hermes's profile secret scope (``agent.secret_scope``). Neither
    ``os.environ`` nor a ``.env`` file is ever read for ``API_SERVER_KEY``/``API_SERVER_PORT``. If
    that module cannot be imported the result fails closed: no key, ``secret_scope_missing``.
    ``environ`` supplies only the optional Dashboard variables (a test stand-in).
    The host is never configurable: the API Server stays on loopback.
    """
    root = state_root(home).parent
    scope = _profile_secrets(root)
    if scope is None:
        return ApiTarget(port=DEFAULT_API_PORT, key=None, secret_scope_missing=True)
    dashboard_env = {k: v for k, v in dict(os.environ if environ is None else environ).items()
                     if k.startswith("HERMES_DASHBOARD_")} if Path(home) == root else {}
    extra = _api_extra(root)
    port_text = scope.get("API_SERVER_PORT") or extra.get("port") or ""
    scoped_key = scope.get("API_SERVER_KEY")
    key = scoped_key if usable_api_key(scoped_key) else extra.get("key")
    key = key if usable_api_key(key) else None
    # Other loaded plugin copies may retain an old key after a full revoke. Rotation checked
    # Hermes's write authority before publishing this marker; the scoped value is authoritative.
    retired = rotation_state(home).get("retired", [])
    if not isinstance(retired, list):
        retired = []
    if key and hashlib.sha256(key.encode("utf-8")).hexdigest() in retired:
        key = scoped_key if usable_api_key(scoped_key) and \
            hashlib.sha256(scoped_key.encode("utf-8")).hexdigest() not in retired else None
    # config_env._api_server overlays the scoped host only when its API_SERVER_KEY is usable.
    bind_host = extra.get("host", "127.0.0.1")
    if usable_api_key(scoped_key):
        bind_host = scope.get("API_SERVER_HOST") or bind_host
    status = live_gateway_status(root)
    metrics = status.get("platforms", {}).get("api_server", {}).get("metrics", {})
    bind_host = metrics.get("host", bind_host)
    try:
        port = int(port_text)
    except (ValueError, TypeError):
        port = DEFAULT_API_PORT
    profile_root = root / "profiles"
    try:
        from hermes_cli.profiles import profiles_to_serve
        # Hermes owns the served set, including standalone/parked/tombstoned/ghost exclusions.
        # Never use a selector scoped to another Hermes root in this loaded copy.
        served = [] if status.get("multiplex_standalone_reason") else status.get("served_profiles", [])
        served = served if isinstance(served, list) else []
        names = [name for name, path in profiles_to_serve(True) if name != "default" and name in served
                 and Path(path) == profile_root / name and not Path(path).is_symlink()]
    except (ImportError, OSError):
        names = []
    keys = {name: (_profile_secrets(profile_root / name) or {}).get("API_SERVER_KEY") for name in names}
    # Named routes fail closed upstream: YAML or the root key cannot authorize /p/<profile>.
    keys = {name: value for name, value in keys.items() if usable_api_key(value)}
    return ApiTarget(port=port, key=key, profiles=tuple(["default"] + sorted(keys)),
                     profile_keys=keys, bind_host=bind_host,
                     dashboard=discover_dashboard(home, dashboard_env, scope))


def _api_extra(home: Path) -> Dict[str, Any]:
    try:
        import yaml
        data = yaml.safe_load((home / "config.yaml").read_text("utf-8")) or {}
        return dict(data.get("platforms", {}).get("api_server", {}).get("extra", {}))
    except (OSError, ValueError, TypeError, AttributeError, yaml.YAMLError):
        return {}


def secret_scope_available() -> bool:
    try:
        import agent.secret_scope as secret_scope
        return callable(getattr(secret_scope, "build_profile_secret_scope", None))
    except ImportError:
        return False


def _profile_secrets(home: Path) -> Optional[Dict[str, str]]:
    """Hermes's scoped secrets for one profile home, or None when the API is unavailable.

    The listener runs on its own thread, so the scope is bound for this read only and the caller's
    scope restored afterwards. There is no file or environment fallback (D34).
    """
    try:
        import agent.secret_scope as secret_scope
        build = secret_scope.build_profile_secret_scope
    except (ImportError, AttributeError):
        return None
    scope = dict(build(home))
    bind, reset, get = (getattr(secret_scope, name, None)
                        for name in ("set_secret_scope", "reset_secret_scope", "get_secret"))
    if bind is None or reset is None or get is None:
        return scope
    token = bind(scope, profile_home=str(home))
    try:
        key = get("API_SERVER_KEY")
        if key:
            scope["API_SERVER_KEY"] = key
        return scope
    finally:
        reset(token)


def rotation_state(home: Path) -> Dict[str, Any]:
    try:
        value = json.loads((state_root(home) / "relay" / "key-rotation.json").read_text("utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def capability_document(*, plugin_version: str, state_version: str, lan_addresses: List[str],
                        push_available: bool, push_paired: bool,
                        notify_available: bool = False,
                        relay_url: Optional[str] = None,
                        api_profiles: Tuple[str, ...] = ("default",),
                        files: Optional[Dict[str, Any]] = None,
                        dashboard_available: bool = False) -> Dict[str, Any]:
    """Contract section 6. ``None`` means the feature does not exist on this computer.

    Optional services are advertised only when their implementation is available on this host.
    The runtime adds its control-management capabilities here, so a bare listener fixture
    cannot accidentally advertise them. A running loopback ``dashboard`` is advertised when it is
    ungated, and ``notify`` when the live feed is served.
    """
    available_services: Dict[str, Any] = {
        "api": {"profiles": [{"name": name, "base_path": "" if name == "default"
                               else f"/p/{quote(name, safe='')}"} for name in api_profiles]},
        "dashboard": {"available": True} if dashboard_available else None,
        "files": files,
        "control": {"device_management": None, "rotate_key": None, "relay_update": None},
        "terminal": None,
        "update": None,
    }
    features: Dict[str, Any] = {
        "push": {"available": push_available, "paired": push_paired},
    }
    if notify_available:
        available_services["notify"] = {"version": 1}
        features["local_push"] = {"available": True}
    return {
        "relay_proto": RELAY_PROTO,
        "plugin_version": plugin_version,
        "state": state_version,
        "services": available_services,
        "features": features,
        "reach": {
            "lan": {"addresses": list(lan_addresses), "advertising": False},
            "relay": {"url": relay_url} if relay_url else None,
        },
    }


class SessionContext:
    """What one session's services need to know about the phone on the other end."""

    def __init__(self, *, approved: bool, capabilities: Callable[[], Dict[str, Any]],
                 api: Callable[[], ApiTarget], files: Optional[FileService] = None,
                 feed: Optional[LiveFeed] = None, phone_key: Optional[bytes] = None,
                 publication_guard=None, management: Optional[PhoneManagement] = None,
                 push_handler=None,
                 notify_heartbeat_seconds: float = NOTIFY_HEARTBEAT_SECONDS,
                 notify_ack_timeout_seconds: float = NOTIFY_ACK_TIMEOUT_SECONDS) -> None:
        self.approved = approved
        self.capabilities = capabilities
        self.api = api
        self.files = files
        self.feed = feed
        self.phone_key = phone_key
        self.publication_guard = publication_guard
        self.management = management
        self.rotation_generation = management.rotation_generation() if management else None
        self.notify_heartbeat_seconds = notify_heartbeat_seconds
        self.notify_ack_timeout_seconds = notify_ack_timeout_seconds
        self.push_handler = push_handler
        self.control_streams: List[Stream] = []
        # Events raised before any control stream was being served; the first one gets them.
        self.backlog: List[Dict[str, Any]] = []
        self.notify_subscribed = False

    def is_approved(self) -> bool:
        return self.approved and (self.management is None or
                                 self.management.store.is_approved(self.phone_key))

    async def announce(self, event: Dict[str, Any]) -> None:
        if not self.control_streams:
            self.backlog.append(event)
            return
        for stream in list(self.control_streams):
            try:
                await stream.write(_line(event))
            except ConnectionError:
                pass


async def serve(mux: Mux, stream: Stream, context: SessionContext) -> None:
    """The ``on_open`` the listener hands its mux."""
    if stream.service == "control":
        await _control(stream, context)
    elif stream.service == "notify":
        await _notify(stream, context)
    elif stream.service == "api":
        if not await asyncio.to_thread(context.is_approved):
            await stream.close(StreamClose.POLICY)
            return
        await _api(stream, context.api(), context)
    elif stream.service == "files":
        if not await asyncio.to_thread(context.is_approved):
            await stream.close(StreamClose.POLICY)
        elif context.files is None or context.files.capabilities() is None:
            await stream.close(StreamClose.UNKNOWN_SERVICE)
        else:
            await context.files.serve(stream, context.phone_key, context.publication_guard)
    elif stream.service == "dashboard":
        if not await asyncio.to_thread(context.is_approved):
            await stream.close(StreamClose.POLICY)
            return
        target = context.api().dashboard
        if target is None:
            await stream.close(StreamClose.UNKNOWN_SERVICE)
            return
        await _forward(stream, target.host, target.port, context)
    else:
        await stream.close(StreamClose.UNKNOWN_SERVICE)


async def _notify(stream: Stream, context: SessionContext) -> None:
    """Tail live notification events from the sequence current when this stream opens."""
    if context.feed is None or not await asyncio.to_thread(context.is_approved):
        await stream.close(StreamClose.POLICY, "not approved")
        return
    if context.notify_subscribed:
        await stream.close(StreamClose.POLICY, "already subscribed")
        return
    filters, profile = _notify_args(stream.args, context.api())
    if filters is None:
        await stream.close(StreamClose.POLICY, "invalid arguments")
        return
    context.notify_subscribed = True
    try:
        await _notify_stream(stream, context, filters, profile)
    finally:
        context.notify_subscribed = False


async def _notify_stream(stream: Stream, context: SessionContext, filters, profile) -> None:
    subscriptions = NotifySubscriptions(context.feed.state_store)
    proofs = stream.args.get("push_proofs", {})
    bindings = await asyncio.to_thread(subscriptions.bindings, proofs, context.phone_key) \
        if context.phone_key is not None and proofs else []
    identifier = str(uuid.uuid4())
    lease = context.notify_heartbeat_seconds + context.notify_ack_timeout_seconds
    outbox = Outbox(context.feed.state_store.root / "outbox.sqlite")
    # A receipt flood stops this reader, then mux credit stops the peer. It cannot grow memory.
    acks: "asyncio.Queue[str]" = asyncio.Queue(maxsize=64)
    receipt_task = None
    loop = asyncio.get_running_loop()
    last_heartbeat = loop.time()
    outstanding: Dict[str, float] = {}
    try:
        start_seq = cursor = await asyncio.to_thread(
            subscriptions.refresh, identifier, bindings, filters, None, None, lease)
        receipt_task = asyncio.ensure_future(_notify_receipts(stream, acks))
        await stream.write(_line({"v": 1, "subscribed": True}))
        while not stream.closed:
            while not acks.empty():
                receipt = acks.get_nowait()
                if receipt in outstanding:
                    del outstanding[receipt]
                    # Only a heartbeat receipt proves the phone is still there: it renews the lease.
                    await asyncio.to_thread(subscriptions.refresh, identifier, bindings, filters,
                                            start_seq, None, lease)
                else:
                    await asyncio.to_thread(subscriptions.acknowledge, identifier, receipt)
            now = loop.time()
            if outstanding and now - min(outstanding.values()) >= context.notify_ack_timeout_seconds:
                # Withdraw suppression now; the finally block releases anything still unacknowledged.
                await asyncio.to_thread(subscriptions.close, identifier)
                await stream.close(StreamClose.NORMAL, "heartbeat timeout")
                return
            frames = await asyncio.to_thread(context.feed.since, cursor, NOTIFY_BATCH)
            for frame in frames:
                cursor = max(cursor, int(frame.get("seq") or 0))
                envelope = frame.get("payload")
                source = str(frame.get("source") or "")
                filter_name = source.removeprefix("notify:") if source.startswith("notify:") else ""
                if frame.get("kind") != "notify" or filter_name not in NOTIFY_FILTERS:
                    continue
                if not filters[filter_name] or not isinstance(envelope, dict):
                    continue
                if profile is not None and envelope.get("profile") != profile:
                    continue
                line = _line(envelope)
                # Emitter payloads are much smaller because previews are already capped. A malformed
                # or future producer cannot make this service violate the v1 line bound.
                if len(line) > MAX_NOTIFY_LINE:
                    continue
                await stream.write(line)
            now = loop.time()
            if now - last_heartbeat >= context.notify_heartbeat_seconds and len(outstanding) < 16:
                heartbeat = str(uuid.uuid4())
                await stream.write(_line({"v": 1, "heartbeat": heartbeat}))
                outstanding[heartbeat] = last_heartbeat = loop.time()
            await asyncio.to_thread(subscriptions.release_due, outbox)
            await asyncio.sleep(NOTIFY_POLL_SECONDS)
    finally:
        if receipt_task is not None:
            receipt_task.cancel()
            await asyncio.gather(receipt_task, return_exceptions=True)
        # Close first (so nothing new is held), then send whatever the phone never acknowledged.
        await asyncio.to_thread(subscriptions.close, identifier)
        await asyncio.to_thread(subscriptions.release, outbox, identifier)
        outbox.close()


async def _notify_receipts(stream: Stream, acks: "asyncio.Queue[str]") -> None:
    """Consume heartbeat and delivered-notification receipts under the same line bound.

    A notification ACK follows local submission and discharges that event's relay fallback; a
    heartbeat ACK renews the suppression lease.
    """
    buffer = b""
    while True:
        chunk = await stream.read()
        if not chunk:
            return
        buffer += chunk
        if len(buffer) > MAX_NOTIFY_LINE and b"\n" not in buffer:
            await stream.close(StreamClose.POLICY, "line too long")
            return
        while b"\n" in buffer:
            line, _, buffer = buffer.partition(b"\n")
            if len(line) > MAX_NOTIFY_LINE:
                await stream.close(StreamClose.POLICY, "line too long")
                return
            if not line.strip():
                continue
            try:
                message = json.loads(line)
                if (not isinstance(message, dict) or set(message) != {"op", "id"}
                        or message.get("op") != "ack"):
                    raise ValueError
                receipt = str(uuid.UUID(message["id"]))
            except (ValueError, TypeError, KeyError, AttributeError):
                await stream.close(StreamClose.POLICY, "invalid receipt")
                return
            await acks.put(receipt)
        # The unterminated tail left after a valid receipt is bounded before the next read too.
        if len(buffer) > MAX_NOTIFY_LINE:
            await stream.close(StreamClose.POLICY, "line too long")
            return


def _notify_args(args: Dict[str, Any], target: ApiTarget):
    """Validate the small, closed subscription vocabulary. ``None`` means all profiles."""
    if len(json.dumps(args, separators=(",", ":")).encode("utf-8")) > MAX_NOTIFY_LINE:
        return None, None
    if any(key not in NOTIFY_FILTERS and key not in ("profile", "push_proofs") for key in args):
        return None, None
    filters = {name: True for name in NOTIFY_FILTERS}
    for name in NOTIFY_FILTERS:
        if name in args:
            if type(args[name]) is not bool:
                return None, None
            filters[name] = args[name]
    profile = args.get("profile")
    if profile is not None and (not isinstance(profile, str) or profile not in target.profiles):
        return None, None
    proofs = args.get("push_proofs", {})
    if not isinstance(proofs, dict) or len(proofs) > 32:
        return None, None
    for name, proof in proofs.items():
        if (name not in target.profiles or (profile is not None and name != profile)
                or not isinstance(proof, str) or len(proof) != 64
                or any(character not in "0123456789abcdef" for character in proof)):
            return None, None
    return filters, profile


async def _control(stream: Stream, context: SessionContext) -> None:
    context.control_streams.append(stream)
    buffer = b""
    try:
        while context.backlog:
            await stream.write(_line(context.backlog.pop(0)))
        while True:
            chunk = await stream.read()
            if not chunk:
                return
            buffer += chunk
            if len(buffer) > MAX_CONTROL_LINE and b"\n" not in buffer:
                await stream.close(StreamClose.POLICY, "line too long")
                return
            while b"\n" in buffer:
                line, _, buffer = buffer.partition(b"\n")
                if len(line) > MAX_CONTROL_LINE:
                    await stream.close(StreamClose.POLICY, "line too long")
                    return
                if line.strip():
                    await stream.write(_line(await asyncio.to_thread(_answer, line, context)))
    finally:
        if stream in context.control_streams:
            context.control_streams.remove(stream)


def _answer(line: bytes, context: SessionContext) -> Dict[str, Any]:
    try:
        request = json.loads(line)
        request_id = request.get("id")
        op = request.get("op")
    except (ValueError, AttributeError):
        return {"id": None, "ok": False, "error": "bad_request"}
    if not context.approved:
        return {"id": request_id, "ok": False, "error": "not_approved"}
    if isinstance(op, str) and op.startswith("device.") and context.push_handler is not None:
        # D27: the consented push policy owns device registration; approval is rechecked first.
        if context.phone_key is None or not context.is_approved():
            return {"id": request_id, "ok": False, "error": "not_approved"}
        try:
            return {"id": request_id, "ok": True, **context.push_handler(context.phone_key, request)}
        except (ValueError, TypeError, KeyError):
            return {"id": request_id, "ok": False, "error": "bad_device"}
    if op not in ("info", "bootstrap"):
        if context.management is None:
            return {"id": request_id, "ok": False, "error": "unsupported"}
        try:
            result = context.management.answer(request, context.phone_key)
            return {"id": request_id, "ok": True, **result}
        except ControlError as error:
            return {"id": request_id, "ok": False, "error": str(error)}
        except (ValueError, TypeError, KeyError):
            return {"id": request_id, "ok": False, "error": "bad_request"}
        except (OSError, RuntimeError):
            return {"id": request_id, "ok": False, "error": "operation_failed"}
    if context.management:
        with context.management.store.locked():
            return _credentials(request_id, op, context, request)
    return _credentials(request_id, op, context, request)


def _credentials(request_id, op: str, context: SessionContext, request: Dict[str, Any]) -> Dict[str, Any]:
    if not context.is_approved():
        return {"id": request_id, "ok": False, "error": "not_approved"}
    if op == "info":
        return {"id": request_id, "ok": True, "capabilities": context.capabilities()}
    target = context.api()
    profile = request.get("profile", "default")
    if profile not in target.profiles:
        return {"id": request_id, "ok": False, "error": "unknown_profile"}
    dashboard = target.dashboard
    return {"id": request_id, "ok": True, "api_key": target.key_for(profile), "api_port": target.port,
            "dashboard_token": dashboard.token if dashboard else None,
            "dashboard_port": dashboard.port if dashboard else None}


async def _api(stream: Stream, target: ApiTarget, context: SessionContext) -> None:
    # The phone uses the advertised /p/<profile> base_path in its HTTP request. As with SSH,
    # bytes cross unchanged and Hermes owns profile routing and bearer authorization.
    if str(stream.args.get("profile") or "default") not in target.profiles:
        await stream.close(StreamClose.UNREACHABLE, "unknown profile")
        return
    await _forward(stream, target.host, target.port, context)


async def _forward(stream: Stream, host: str, port: int, context: SessionContext) -> None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), CONNECT_TIMEOUT_SECONDS)
    except (OSError, asyncio.TimeoutError):
        await stream.close(StreamClose.UNREACHABLE)
        return
    if not await asyncio.to_thread(context.is_approved):
        writer.close()
        await stream.close(StreamClose.POLICY)
        return

    async def phone_to_hermes() -> None:
        while True:
            chunk = await stream.read()
            if not chunk:
                return
            writer.write(chunk)
            await asyncio.wait_for(writer.drain(), stream.mux._write_seconds)

    async def hermes_to_phone() -> None:
        while True:
            # One frame's worth at a time: ``stream.write`` waits for credit, and while it waits
            # nothing more is read from Hermes, so TCP pushes back on the API Server.
            chunk = await reader.read(framing.MAX_DATA)
            if not chunk:
                return
            await stream.write(chunk)

    tasks = [asyncio.ensure_future(phone_to_hermes()), asyncio.ensure_future(hermes_to_phone())]
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()  # an upstream error closes just this stream through Mux._serve
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), stream.mux._write_seconds)
        except (OSError, asyncio.TimeoutError):
            pass


def _line(value: Dict[str, Any]) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8") + b"\n"
