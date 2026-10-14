"""Streams inside one Noise session (contract section 7).

Each transport plaintext is ``type (u8) | stream (u32) | data``. The phone opens streams with odd,
increasing ids; stream 0 is the session itself and only carries ``CLOSE``. Every direction of every
stream starts with 256 KiB of credit: a sender never sends more ``DATA`` than it holds, and a
receiver hands credit back with ``WINDOW`` as its consumer takes the bytes. That is what keeps a
slow phone from making this computer buffer without bound, and a slow Hermes from making the phone
do the same.

The same :class:`Mux` runs both ends. The plugin is the responder and serves ``OPEN`` through an
``on_open`` callback; the tests' stand-in phone is the initiator and calls :meth:`Mux.open`.
"""

from __future__ import annotations

import asyncio
import json
import logging
import struct
from collections import deque
from enum import IntEnum
from typing import Any, Awaitable, Callable, Dict, Optional, Set, Tuple

from . import framing, noise

logger = logging.getLogger("hermes_cli.plugins.cozychat")

OPEN, DATA, CLOSE, WINDOW, PAD = 1, 2, 3, 4, 5
_TYPES = {OPEN, DATA, CLOSE, WINDOW, PAD}

INITIAL_WINDOW = 256 * 1024
MAX_STREAMS = 32
IDLE_SECONDS = 300.0
WRITE_SECONDS = 10.0
WRITE_BUFFER_HIGH = 64 * 1024

_HEADER = struct.Struct(">BI")
_U16 = struct.Struct(">H")
_U32 = struct.Struct(">I")


class SessionClose(IntEnum):
    """``CLOSE`` on stream 0 (contract section 9)."""

    NORMAL = 0
    PROTOCOL = 1
    REVOKED = 2
    PROTO_UNSUPPORTED = 3
    PLUGIN_TOO_OLD = 4
    OVERLOADED = 5
    SHUTTING_DOWN = 6
    PAIRING_ENDED = 7


class StreamClose(IntEnum):
    """``CLOSE`` on stream n (contract section 9)."""

    NORMAL = 0
    UNKNOWN_SERVICE = 1
    UNREACHABLE = 2
    POLICY = 3
    FLOW_CONTROL = 4
    LIMIT = 5


class ProtocolError(Exception):
    """A frame the contract does not allow. The session closes with code 1."""


class StreamClosed(ConnectionError):
    """A write to a stream either end has already closed."""


def encode_frame(kind: int, stream: int, data: bytes = b"") -> bytes:
    if len(data) > framing.MAX_DATA:
        raise ValueError("frame over 16 KiB, header included")
    return _HEADER.pack(kind, stream) + bytes(data)


def decode_frame(plaintext: bytes) -> Tuple[int, int, bytes]:
    if len(plaintext) < framing.FRAME_HEADER_LEN or len(plaintext) > framing.MAX_PLAINTEXT:
        raise ProtocolError("bad frame length")
    kind, stream = _HEADER.unpack_from(plaintext)
    if kind not in _TYPES:
        raise ProtocolError("unknown frame type")
    return kind, stream, bytes(plaintext[framing.FRAME_HEADER_LEN:])


def close_payload(code: int, reason: str = "") -> bytes:
    return _U16.pack(int(code)) + reason.encode("utf-8")[: framing.MAX_DATA - _U16.size]


def parse_close(data: bytes) -> Optional[int]:
    return _U16.unpack_from(data)[0] if len(data) >= _U16.size else None


def parse_open(data: bytes) -> Tuple[str, Dict[str, Any]]:
    """``service`` then optionally ``\\n`` and a JSON object."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ProtocolError("service name is not UTF-8") from None
    service, _, raw = text.partition("\n")
    args: Any = {}
    if raw.strip():
        try:
            args = json.loads(raw)
        except ValueError:
            raise ProtocolError("OPEN argument is not JSON") from None
        if not isinstance(args, dict):
            raise ProtocolError("OPEN argument is not an object")
    return service, args


class Stream:
    """One stream: bytes in, bytes out, both under credit."""

    def __init__(self, mux: "Mux", stream_id: int, service: str, args: Dict[str, Any]) -> None:
        self.mux = mux
        self.id = stream_id
        self.service = service
        self.args = args
        self.closed = False
        self.close_code: Optional[int] = None
        # Coalesce tiny DATA frames: byte credit alone would allow 262,144 queue objects per
        # stream. Here at most one window's bytes plus 17 chunk objects wait for the consumer.
        self._inbound = deque()
        self._readable = asyncio.Event()
        self._receive_credit = INITIAL_WINDOW  # what the peer may still send us
        self._unreturned = 0  # handed to our consumer, credit not yet sent back
        self._send_credit = INITIAL_WINDOW  # what we may still send the peer
        self._credit = asyncio.Event()
        self.bytes_sent = 0

    @property
    def send_credit(self) -> int:
        return self._send_credit

    async def read(self) -> bytes:
        """The next chunk, or ``b""`` once the stream has ended.

        The credit for a chunk goes back to the peer when the consumer comes back for the next one,
        so a consumer that stops reading stops the peer within one window.
        """
        await self._return_credit()
        while not self._inbound and not self.closed:
            self._readable.clear()
            await self._readable.wait()
        if not self._inbound:
            return b""
        chunk = bytes(self._inbound.popleft())
        self._unreturned = len(chunk)
        return chunk

    async def write(self, data: bytes) -> None:
        view = memoryview(bytes(data))
        while view:
            while self._send_credit <= 0 and not self.closed:
                self._credit.clear()
                await self._credit.wait()
            if self.closed:
                raise StreamClosed("stream closed")
            n = min(len(view), framing.MAX_DATA, self._send_credit)
            self._send_credit -= n
            self.bytes_sent += n
            await self.mux.send(DATA, self.id, bytes(view[:n]))
            view = view[n:]

    async def close(self, code: int = StreamClose.NORMAL, reason: str = "") -> None:
        if self.closed:
            return
        self._end()
        try:
            await self.mux.send(CLOSE, self.id, close_payload(code, reason))
        except ConnectionError:
            pass

    # -- driven by the mux -------------------------------------------------

    async def _return_credit(self) -> None:
        if self._unreturned and not self.closed:
            amount, self._unreturned = self._unreturned, 0
            self._receive_credit += amount
            try:
                await self.mux.send(WINDOW, self.id, _U32.pack(amount))
            except ConnectionError:
                pass

    def _on_data(self, data: bytes) -> bool:
        """False when the peer overran the credit it was given."""
        if len(data) > self._receive_credit:
            return False
        self._receive_credit -= len(data)
        if data:
            view = memoryview(data)
            while view:
                if not self._inbound or len(self._inbound[-1]) == framing.MAX_DATA:
                    self._inbound.append(bytearray())
                amount = min(len(view), framing.MAX_DATA - len(self._inbound[-1]))
                self._inbound[-1].extend(view[:amount])
                view = view[amount:]
            self._readable.set()
        return True

    def _on_window(self, amount: int) -> None:
        if amount == 0 or self._send_credit + amount > INITIAL_WINDOW:
            raise ProtocolError("WINDOW exceeds outstanding credit")
        self._send_credit += amount
        self._credit.set()

    def _on_close(self, code: Optional[int]) -> None:
        self.close_code = code
        self._end()

    def _end(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.mux._forget(self)
        self._readable.set()
        self._credit.set()


OnOpen = Callable[["Mux", Stream], Awaitable[None]]


class Mux:
    """Frames in and out of one established Noise session over one framed byte stream."""

    def __init__(self, session: noise.Session, reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter, *, initiator: bool,
                 on_open: Optional[OnOpen] = None, max_streams: int = MAX_STREAMS,
                 idle_seconds: float = IDLE_SECONDS, write_seconds: float = WRITE_SECONDS) -> None:
        self._session = session
        self._reader = reader
        self._writer = writer
        self._initiator = initiator
        self._on_open = on_open
        self._max_streams = max_streams
        self._idle_seconds = idle_seconds
        self._write_seconds = write_seconds
        self._writer.transport.set_write_buffer_limits(high=WRITE_BUFFER_HIGH,
                                                       low=WRITE_BUFFER_HIGH // 4)
        self._streams: Dict[int, Stream] = {}
        self._next_id = 1
        self._highest_remote = 0
        self._write_lock = asyncio.Lock()
        self._tasks: Set["asyncio.Task[None]"] = set()
        self._stream_tasks: Dict[int, "asyncio.Task[None]"] = {}
        self._dead = False
        self._closing = False
        self.remote_close_code: Optional[int] = None
        self.done = asyncio.Event()

    @property
    def open_streams(self) -> int:
        return len(self._streams)

    async def send(self, kind: int, stream: int, data: bytes = b"") -> None:
        if self._dead or (self._closing and (kind != CLOSE or stream != 0)):
            raise ConnectionError("session closed")
        plaintext = encode_frame(kind, stream, data)
        # Encrypt under the lock: the nonce order must be the order the bytes reach the socket.
        async with self._write_lock:
            if self._dead:
                raise ConnectionError("session closed")
            self._writer.write(framing.encode(self._session.encrypt(plaintext)))
            try:
                await asyncio.wait_for(self._writer.drain(), self._write_seconds)
            except asyncio.TimeoutError:
                self._teardown()
                raise ConnectionError("tunnel write timed out") from None

    async def open(self, service: str, args: Optional[Dict[str, Any]] = None) -> Stream:
        """Initiator only: open a stream to ``service``."""
        if self._dead or self._closing:
            raise ConnectionError("session closed")
        if not self._initiator:
            raise RuntimeError("only the phone opens streams")
        stream_id = self._next_id
        self._next_id += 2
        stream = Stream(self, stream_id, service, dict(args or {}))
        self._streams[stream_id] = stream
        payload = service.encode("utf-8")
        if args:
            payload += b"\n" + json.dumps(args).encode("utf-8")
        await self.send(OPEN, stream_id, payload)
        return stream

    async def run(self, first_plaintext: Optional[bytes] = None) -> None:
        """Read frames until the peer leaves, misbehaves, or closes the session."""
        try:
            if first_plaintext is not None:
                await self._dispatch(first_plaintext)
            while not self._dead:
                message = await asyncio.wait_for(
                    framing.read_message(self._reader, framing.TRANSPORT_MAX), self._idle_seconds)
                await self._dispatch(self._session.decrypt(message))
        except ProtocolError:
            await self.close(SessionClose.PROTOCOL)
        except asyncio.TimeoutError:
            await self.close(SessionClose.NORMAL)
        except (EOFError, framing.FrameError, noise.NoiseError, ConnectionError,
                asyncio.IncompleteReadError, _SessionEnded):
            pass
        finally:
            self._teardown()
            await asyncio.gather(*list(self._tasks), return_exceptions=True)

    async def close(self, code: int = SessionClose.NORMAL) -> None:
        """End the whole session with a session close code."""
        if self._dead:
            return
        self._closing = True
        for stream in list(self._streams.values()):
            stream._end()
        try:
            # A revoked phone must lose every live stream within one second, even if its socket
            # is backpressured. The allowlist watcher reserves the rest for its cross-process poll.
            timeout = 0.25 if code == SessionClose.REVOKED else 2.0
            await asyncio.wait_for(self.send(CLOSE, 0, close_payload(code)), timeout)
        except (ConnectionError, asyncio.TimeoutError, OSError):
            pass
        self._teardown()

    # -- inbound -------------------------------------------------------------

    async def _dispatch(self, plaintext: bytes) -> None:
        kind, stream_id, data = decode_frame(plaintext)
        if kind == PAD:
            return
        if stream_id == 0:
            if kind != CLOSE:
                raise ProtocolError("stream 0 carries only CLOSE")
            self.remote_close_code = parse_close(data)
            raise _SessionEnded
        if kind == OPEN:
            await self._remote_open(stream_id, data)
            return
        stream = self._streams.get(stream_id)
        if stream is None:
            if self._was_used(stream_id):
                return  # in flight when one end closed it
            raise ProtocolError("frame for a stream nobody opened")
        if kind == DATA:
            if not stream._on_data(data):
                await stream.close(StreamClose.FLOW_CONTROL)
        elif kind == WINDOW:
            if len(data) != _U32.size:
                raise ProtocolError("bad WINDOW")
            stream._on_window(_U32.unpack(data)[0])
        elif kind == CLOSE:
            stream._on_close(parse_close(data))

    async def _remote_open(self, stream_id: int, data: bytes) -> None:
        if self._closing:
            return
        if self._initiator:
            raise ProtocolError("only the phone opens streams")
        if stream_id % 2 == 0 or stream_id <= self._highest_remote:
            raise ProtocolError("stream ids are odd and increasing")
        self._highest_remote = stream_id
        service, args = parse_open(data)
        if len(self._streams) >= self._max_streams or len(self._tasks) >= self._max_streams:
            await self.send(CLOSE, stream_id, close_payload(StreamClose.LIMIT))
            return
        stream = Stream(self, stream_id, service, args)
        self._streams[stream_id] = stream
        if self._on_open is None:
            await stream.close(StreamClose.UNKNOWN_SERVICE)
            return
        task = asyncio.ensure_future(self._serve(stream))
        self._stream_tasks[stream_id] = task
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _serve(self, stream: Stream) -> None:
        try:
            assert self._on_open is not None
            await self._on_open(self, stream)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.debug("cozychat tunnel stream %s failed", stream.id, exc_info=True)
            await stream.close(StreamClose.UNREACHABLE)
        else:
            await stream.close(StreamClose.NORMAL)  # a service that returned is done with it

    def _was_used(self, stream_id: int) -> bool:
        if stream_id % 2 == 0:
            return False
        return stream_id < self._next_id if self._initiator else stream_id <= self._highest_remote

    def _forget(self, stream: Stream) -> None:
        if self._streams.get(stream.id) is stream:
            del self._streams[stream.id]
        task = self._stream_tasks.pop(stream.id, None)
        if task is not None and task is not asyncio.current_task():
            task.cancel()

    def _teardown(self) -> None:
        if self._dead:
            return
        self._dead = True
        for stream in list(self._streams.values()):
            stream._end()
        for task in list(self._tasks):
            task.cancel()
        try:
            self._writer.close()
        except Exception:
            pass
        self.done.set()


class _SessionEnded(Exception):
    """The peer sent ``CLOSE`` on stream 0."""
