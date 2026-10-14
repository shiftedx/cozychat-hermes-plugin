"""The plugin's LAN listener: TCP on the home network, Noise inside (handoff 4.10, contract 5.1).

Anyone on the network can connect, so most of this file is about what a stranger gets: nothing.

- A peer outside the subnet of the interface address it arrived on is closed at once.
- At most 16 connections may sit between accept and the first valid transport frame, at most 4 of
  them from one source address, and each has 10 seconds in all (P4). Message 1 must arrive within
  5 seconds and every pre-handshake message is capped at 1 KiB.
- A message 1 from a key that is not on the allowlist, with no pairing window open, gets no
  message 2, no error and no different timing: the transport is closed (P3).
- Inside a window an unknown key gets the minimal payload ``{"relay_proto":1,"pairing":true}``.
  A wrong psk shows up only when its first transport frame fails to decrypt, and is dropped
  silently with the window untouched (P2).
- Only after that first valid frame does the attempt become visible to the person (P1 a), with
  its 6-digit code, and only their approval puts the key on the allowlist (P1 b).
- At most 8 sessions; the 9th is closed with session close code 5.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

from ..feed import LiveFeed
from . import compatibility, framing, lan, mdns, noise, pairing, services
from .mux import CLOSE, Mux, ProtocolError, SessionClose, decode_frame
from .limits import HandshakeLimiter
from .control import PhoneManagement

logger = logging.getLogger("hermes_cli.plugins.cozychat")

PAIRING_PAYLOAD = json.dumps({"relay_proto": services.RELAY_PROTO, "pairing": True},
                             separators=(",", ":")).encode("utf-8")


@dataclass
class ListenerConfig:
    # None: the persisted random port. 0: any free port (tests only).
    port: Optional[int] = None
    # ``lan_bind``: only these of the addresses the interface scan allows. It can only narrow.
    bind: Sequence[str] = ()
    vpn_interfaces: Sequence[str] = ()
    # Address hints that lead the list. ``--advertise`` hints are read from the pairing settings.
    advertise: Sequence[str] = ()
    advertise_mdns: bool = True
    refresh_seconds: float = 30.0
    message_1_seconds: float = 5.0
    half_open_seconds: float = 10.0
    max_half_open: int = 16
    max_half_open_per_source: int = 4
    max_sessions: int = 8
    handshakes_per_minute: float = 20
    handshake_burst: int = 20
    global_handshakes_per_minute: float = 120
    global_handshake_burst: int = 32
    idle_seconds: float = 300.0
    write_seconds: float = 10.0
    decision_poll_seconds: float = 0.25
    # How often a live session re-checks that its phone is still on the allowlist.
    allowlist_poll_seconds: float = 0.25
    # Tests only: the bind list itself, bypassing the scan and its rules (loopback lives here).
    # No plugin config key reaches it; ``Tunnel.listener_config`` maps only ``lan_port`` and
    # ``lan_bind``.
    interfaces: Optional[Callable[[], List[lan.BindAddress]]] = field(default=None, repr=False)
    # Production constants are 30/90 seconds. Tests lower them through this constructor-only seam;
    # no plugin setting, environment variable or CLI flag maps to these fields.
    notify_heartbeat_seconds: float = services.NOTIFY_HEARTBEAT_SECONDS
    notify_ack_timeout_seconds: float = services.NOTIFY_ACK_TIMEOUT_SECONDS


class Listener:
    """One listener per computer, run by whichever process holds ``listener.lock``."""

    def __init__(self, store: pairing.PairingStore, config: ListenerConfig, *,
                 capabilities: Callable[[List[str]], Dict], api: Callable[[], services.ApiTarget],
                 files: Optional[services.FileService] = None,
                 management: Optional[PhoneManagement] = None,
                 feed: Optional[LiveFeed] = None,
                 phone_capabilities=None, push_handler=None) -> None:
        self.store = store
        self.config = config
        self._capabilities = capabilities
        self._api = api
        self.on_bind: Callable[[List[str]], None] = lambda hints: None
        self._files = files
        self.management = management or PhoneManagement(store)
        self._feed = feed
        self._phone_capabilities = phone_capabilities
        self._push_handler = push_handler
        self._host_key = b""
        self._port: Optional[int] = None
        self._servers: Dict[lan.BindAddress, asyncio.base_events.Server] = {}
        self._half_open = 0
        self._half_open_by_source: Counter = Counter()
        self._sessions: Set[Mux] = set()
        self._connections: Set[asyncio.StreamWriter] = set()
        self._refresh: Optional[asyncio.Task] = None
        self._advertiser: Optional[mdns.Advertiser] = None
        self._handlers: Set[asyncio.Task] = set()
        self._limiter = HandshakeLimiter(
            per_minute=config.handshakes_per_minute, burst=config.handshake_burst,
            global_per_minute=config.global_handshakes_per_minute,
            global_burst=config.global_handshake_burst)

    # -- lifecycle ----------------------------------------------------------------------------

    async def start(self) -> None:
        self._host_key = self.store.host_private()
        self._advertiser = mdns.Advertiser(noise.public_key(self._host_key))
        if self.config.port is not None:
            self._port = self.config.port
        else:
            self._port = self.store.port()
        await self._rebind()
        self._refresh = asyncio.ensure_future(self._refresh_loop())

    async def stop(self) -> None:
        if self._refresh is not None:
            self._refresh.cancel()
            await asyncio.gather(self._refresh, return_exceptions=True)
            self._refresh = None
        if self._advertiser is not None:
            await self._advertiser.stop()
        servers = list(self._servers.values())
        for server in servers:
            server.close()
        self._servers.clear()
        # Python 3.12.1+ makes Server.wait_closed() wait for every accepted connection, so live
        # sessions are closed first; awaiting it before them would never return with a phone up.
        await asyncio.gather(*(mux.close(SessionClose.SHUTTING_DOWN) for mux in list(self._sessions)),
                             return_exceptions=True)
        for writer in list(self._connections):
            writer.close()
        await asyncio.gather(*(server.wait_closed() for server in servers))
        handlers = list(self._handlers)
        for task in handlers:
            task.cancel()
        await asyncio.gather(*handlers, return_exceptions=True)

    @property
    def port(self) -> Optional[int]:
        return self._port

    @property
    def binds(self) -> List[lan.BindAddress]:
        return list(self._servers)

    def hints(self) -> List[str]:
        """``ip:port`` for the pairing link and ``reach.lan``. Link-local v6 needs a scope no
        phone can know, so it is bound but never offered."""
        found = [b.hint(self._port or 0) for b in self._servers
                 if not (b.address.version == 6 and b.address.is_link_local)]
        advertised = list(self.config.advertise) + list(self.store.settings().get("advertise") or [])
        return list(dict.fromkeys(advertised + found))

    def capabilities(self, phone_key: Optional[bytes] = None) -> Dict:
        document = self._phone_capabilities(self.hints(), phone_key) if self._phone_capabilities \
            else self._capabilities(self.hints())
        reach = document.get("reach")
        if isinstance(reach, dict) and isinstance(reach.get("lan"), dict):
            reach["lan"]["advertising"] = bool(self._advertiser and self._advertiser.advertising)
        return document

    # -- binding ------------------------------------------------------------------------------

    def _wanted(self) -> List[lan.BindAddress]:
        if self.config.interfaces is not None:
            return self.config.interfaces()
        try:
            return lan.system_bind_addresses(self.config.vpn_interfaces, only=self.config.bind)
        except Exception:
            logger.debug("cozychat could not read the network interfaces", exc_info=True)
            return []

    async def _rebind(self) -> None:
        wanted = self._wanted()
        for bind in [b for b in self._servers if b not in wanted]:
            self._servers.pop(bind).close()
        for bind in wanted:
            if bind in self._servers:
                continue
            try:
                server = await asyncio.start_server(
                    lambda r, w, b=bind: self._accept(r, w, b), host=bind.host, port=self._port,
                    reuse_address=True)
            except OSError:
                logger.debug("cozychat could not bind %s", bind.host, exc_info=True)
                continue
            if not self._port:
                self._port = server.sockets[0].getsockname()[1]
            self._servers[bind] = server
        if self._advertiser is not None:
            addresses = self.binds if self.config.advertise_mdns and self.store.wants_listener() \
                else []
            await self._advertiser.update(addresses, self._port or 0)
        self.on_bind(self.hints() if self._servers else [])

    async def _refresh_loop(self) -> None:
        while True:
            await asyncio.sleep(self.config.refresh_seconds)
            try:
                await self._rebind()
            except Exception:
                logger.debug("cozychat listener refresh failed", exc_info=True)

    # -- one connection -----------------------------------------------------------------------

    async def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                      bind: lan.BindAddress) -> None:
        peer = writer.get_extra_info("peername") or ("",)
        source = str(peer[0])
        if not bind.admits(source) or self._half_open >= self.config.max_half_open \
                or self._half_open_by_source[source] >= self.config.max_half_open_per_source \
                or not self._limiter.admits(source):
            writer.close()
            return
        task = asyncio.current_task()
        self._handlers.add(task)
        self._connections.add(writer)
        try:
            await self._converse(reader, writer, source)
        except Exception:
            logger.debug("cozychat tunnel connection failed", exc_info=True)
        finally:
            self._connections.discard(writer)
            self._handlers.discard(task)
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), self.config.write_seconds)
            except (OSError, asyncio.TimeoutError):
                pass

    async def _converse(self, reader, writer, source: str) -> None:
        loop = asyncio.get_running_loop()
        self._half_open += 1
        self._half_open_by_source[source] += 1
        released = False

        def release() -> None:
            nonlocal released
            if not released:
                released = True
                self._half_open -= 1
                self._half_open_by_source[source] -= 1
                if self._half_open_by_source[source] <= 0:
                    del self._half_open_by_source[source]

        try:
            handshake = await self._handshake(reader, writer, loop.time())
        finally:
            release()
        if handshake is None:
            return
        session, first, approved, phone_name, window, protocol_range = handshake
        await self._run_session(reader, writer, session, first, approved, phone_name, window,
                                protocol_range)

    async def _handshake(self, reader, writer, started: float):
        """Message 1, message 2 and the first valid transport frame, or None for a silent close."""
        loop = asyncio.get_running_loop()
        deadline = started + self.config.half_open_seconds
        try:
            message_1 = await asyncio.wait_for(
                framing.read_message(reader, framing.PRE_HANDSHAKE_MAX),
                min(self.config.message_1_seconds, deadline - loop.time()))
            responder = noise.Responder(self._host_key)
            payload = responder.read_message_1(message_1)
            phone_key = responder.remote_static
            assert phone_key is not None
            phone_name = pairing.phone_name_from(payload)
            if phone_name is None:
                return None  # over 64 bytes, missing or not a string: dropped silently (section 2)
            protocol_range = compatibility.peer_protocol_range(payload)
            if protocol_range is None:
                return None
            approved = self.store.is_approved(phone_key)
            window = None
            if approved:
                psk = noise.ZERO_PSK
                document = self.capabilities(phone_key)
                reply = json.dumps(document, separators=(",", ":")).encode("utf-8")
                if len(reply) + noise.MESSAGE_2_MIN_LEN > framing.PRE_HANDSHAKE_MAX:
                    # Optional path-policy hints remain available through control.info. They
                    # must not grow an approved reconnect beyond the 1 KiB handshake contract.
                    document = dict(document)
                    document["services"] = dict(document["services"])
                    files = document["services"].get("files")
                    if isinstance(files, dict):
                        document["services"]["files"] = {k: v for k, v in files.items()
                            if k not in ("user_home", "read_roots", "denied_roots", "inbox")}
                    reply = json.dumps(document, separators=(",", ":")).encode("utf-8")
            else:
                window = self.store.window()
                if window is None:
                    return None  # P3: no window, no answer
                psk, reply = window.psk, PAIRING_PAYLOAD
            message_2, session = responder.write_message_2(psk, reply)
            if len(message_2) > framing.PRE_HANDSHAKE_MAX:
                return None
            writer.write(framing.encode(message_2))
            await asyncio.wait_for(writer.drain(), max(0.0, deadline - loop.time()))
            first = await asyncio.wait_for(
                framing.read_message(reader, framing.TRANSPORT_MAX),
                max(0.0, deadline - loop.time()))
            plaintext = session.decrypt(first)  # P1 a; a wrong psk fails here (P2)
        except (asyncio.TimeoutError, EOFError, framing.FrameError, noise.NoiseError,
                ConnectionError, OSError, ValueError):
            return None
        return session, plaintext, approved, phone_name, window, protocol_range

    async def _run_session(self, reader, writer, session: noise.Session, first: bytes,
                           approved: bool, phone_name: pairing.PhoneName,
                           window: Optional[pairing.Window], protocol_range: Tuple[int, int]) -> None:
        @contextmanager
        def publication_guard():
            # remove_phone uses this same lock, including when another Hermes process revokes.
            with self.store.locked():
                yield self.store.is_approved(session.remote_static)

        context = services.SessionContext(approved=approved,
                                          capabilities=lambda: self.capabilities(session.remote_static),
                                          api=self._api, files=self._files, feed=self._feed,
                                          phone_key=session.remote_static, push_handler=self._push_handler,
                                          publication_guard=publication_guard, management=self.management,
                                          notify_heartbeat_seconds=(
                                              self.config.notify_heartbeat_seconds),
                                          notify_ack_timeout_seconds=(
                                              self.config.notify_ack_timeout_seconds))
        mux = Mux(session, reader, writer, initiator=False,
                  on_open=lambda m, s: services.serve(m, s, context),
                  idle_seconds=self.config.idle_seconds, write_seconds=self.config.write_seconds)
        if not protocol_range[0] <= compatibility.RELAY_PROTO <= protocol_range[1]:
            await mux.close(SessionClose.PROTO_UNSUPPORTED)
            return
        try:
            kind, stream_id, _ = decode_frame(first)
        except ProtocolError:
            await mux.close(SessionClose.PROTOCOL)
            return
        if kind == CLOSE and stream_id == 0:
            # The phone may reject our protocol or plugin version before opening control. That
            # proves the PSK but must never put a pairing code on the computer or consume it.
            await mux.run(first)
            return
        if approved and not await asyncio.to_thread(self.store.is_approved, session.remote_static):
            await mux.close(SessionClose.REVOKED)
            return
        if len(self._sessions) >= self.config.max_sessions:
            await mux.close(SessionClose.OVERLOADED)
            return
        attempt_id: Optional[str] = None
        watcher: Optional[asyncio.Task] = None
        # Reserve before begin_attempt yields to a worker: concurrent successful handshakes
        # must not all see the same spare slot.
        self._sessions.add(mux)
        try:
            if not approved:
                assert window is not None
                code = noise.pairing_code(session.handshake_hash, phone_name.raw)
                attempt_id = await asyncio.to_thread(
                    self.store.begin_attempt, window.id, session.remote_static, phone_name.display,
                    code)
                if attempt_id is None:
                    await mux.close(SessionClose.PAIRING_ENDED)
                    return
                watcher = asyncio.ensure_future(self._watch_safely(
                    mux, self._await_decision(mux, context, attempt_id, session.remote_static)))
            else:
                watcher = asyncio.ensure_future(self._watch_safely(
                    mux, self._watch_allowlist(mux, session.remote_static, context)))
            await mux.run(first)
        finally:
            self._sessions.discard(mux)
            await mux.close()
            if watcher is not None:
                watcher.cancel()
                await asyncio.gather(watcher, return_exceptions=True)
            if attempt_id is not None and not context.approved:
                await asyncio.to_thread(self.store.abandon_attempt, attempt_id)

    async def _watch_safely(self, mux: Mux, watch) -> None:
        try:
            await watch
        except Exception:
            logger.debug("cozychat session state check failed", exc_info=True)
            await mux.close()

    async def _await_decision(self, mux: Mux, context: services.SessionContext,
                              attempt_id: str, phone_key: bytes) -> None:
        while not mux.done.is_set():
            outcome = await asyncio.to_thread(self.store.settle, attempt_id)
            if outcome == "approved":
                if not await asyncio.to_thread(self.store.is_approved, phone_key):
                    await mux.close(SessionClose.REVOKED)
                    return
                context.approved = True
                await context.announce({"event": "pairing.approved"})
                await self._watch_allowlist(mux, phone_key, context)
                return
            if outcome != "pending":
                await mux.close(SessionClose.PAIRING_ENDED)
                return
            try:
                await asyncio.wait_for(mux.done.wait(), self.config.decision_poll_seconds)
            except asyncio.TimeoutError:
                pass


    async def _watch_allowlist(self, mux: Mux, phone_key: bytes,
                             context: Optional[services.SessionContext] = None) -> None:
        """Removing a phone ends its live sessions with close code 2 (contract section 8): an
        approved session is only as good as the allowlist entry behind it."""
        while not mux.done.is_set():
            if not await asyncio.to_thread(self.store.is_approved, phone_key):
                await mux.close(SessionClose.REVOKED)
                return
            if context is not None and context.management is not None:
                generation = await asyncio.to_thread(context.management.rotation_ready)
                if not await asyncio.to_thread(self.store.is_approved, phone_key):
                    await mux.close(SessionClose.REVOKED)
                    return
                if generation is not None and generation != context.rotation_generation:
                    await context.announce({"event": "credentials.rotated"})
                    context.rotation_generation = generation
            try:
                await asyncio.wait_for(mux.done.wait(), self.config.allowlist_poll_seconds)
                return
            except asyncio.TimeoutError:
                pass


class ListenerThread:
    """A :class:`Listener` on an event loop of its own, so it never shares Hermes's loop."""

    def __init__(self, listener: Listener) -> None:
        self.listener = listener
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, name="cozychat-lan", daemon=True)
        self._started = threading.Event()
        self.error: Optional[BaseException] = None

    def start(self, timeout: float = 10.0) -> None:
        self._thread.start()
        if not self._started.wait(timeout):
            raise TimeoutError("cozychat listener startup timed out")
        if self.error is not None:
            raise self.error

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self.listener.start())
            self._started.set()
            self._loop.run_forever()
        except BaseException as error:  # reported to start()
            self.error = error
            logger.warning("cozychat listener stopped after a failure", exc_info=True)
        finally:
            self._started.set()
            try:
                self._loop.run_until_complete(self.listener.stop())
                pending = asyncio.all_tasks(self._loop)
                for task in pending:
                    task.cancel()
                self._loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                self._loop.run_until_complete(self._loop.shutdown_asyncgens())
                self._loop.run_until_complete(self._loop.shutdown_default_executor())
            except Exception:
                logger.debug("cozychat listener cleanup failed", exc_info=True)
            finally:
                self._loop.close()

    def call(self, fn, *args):
        """Run ``fn(*args)`` on the listener's loop and wait for it."""
        async def invoke():
            return fn(*args)
        return asyncio.run_coroutine_threadsafe(invoke(), self._loop).result(5)

    def stop(self, timeout: float = 5.0) -> None:
        if not self._thread.is_alive():
            return
        future = asyncio.run_coroutine_threadsafe(self.listener.stop(), self._loop)
        try:
            future.result(timeout)
        except Exception:
            logger.debug("cozychat listener stop failed", exc_info=True)
        if not self._loop.is_closed():
            self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout)

    @property
    def alive(self) -> bool:
        return self._thread.is_alive()
