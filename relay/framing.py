"""How a Noise message travels over TCP: ``u32 big-endian length | bytes`` (contract section 5.1).

``length`` counts the Noise message only. There is no connection-id prefix: on the home network
there is no relay to multiplex. A bad length closes the connection with no reply, so the reader
raises :class:`FrameError` and the caller drops the socket without writing anything.
"""

from __future__ import annotations

import asyncio
import struct

from . import noise

LENGTH = struct.Struct(">I")

# Any message before the handshake completes, message 1 included (P4).
PRE_HANDSHAKE_MAX = 1024
# The largest plaintext frame after the handshake: 16,384 bytes INCLUDING the 5-byte
# ``type | stream`` header, so at most 16,379 bytes of stream data (contract section 7). The
# transport message adds the 16-byte Noise tag: at most 16,400 bytes (section 5.1).
FRAME_HEADER_LEN = 5
MAX_PLAINTEXT = 16 * 1024
MAX_DATA = MAX_PLAINTEXT - FRAME_HEADER_LEN
TRANSPORT_MAX = MAX_PLAINTEXT + noise.TAG_LEN


class FrameError(Exception):
    """A length of zero, a length over the limit, or a connection that ended inside a frame."""


def encode(message: bytes) -> bytes:
    return LENGTH.pack(len(message)) + message


async def read_message(reader: asyncio.StreamReader, limit: int) -> bytes:
    """One length-prefixed message of at most ``limit`` bytes.

    Raises :class:`EOFError` on a clean end between messages and :class:`FrameError` on anything
    else, so a caller can tell a peer that left from a peer that misbehaved.
    """
    try:
        header = await reader.readexactly(LENGTH.size)
    except asyncio.IncompleteReadError as error:
        if not error.partial:
            raise EOFError from None
        raise FrameError("connection ended inside a length prefix") from None
    (length,) = LENGTH.unpack(header)
    if length == 0 or length > limit:
        raise FrameError("bad length")
    try:
        return await reader.readexactly(length)
    except asyncio.IncompleteReadError:
        raise FrameError("connection ended inside a frame") from None
