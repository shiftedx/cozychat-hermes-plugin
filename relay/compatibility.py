"""Version negotiation for the tunnel, independent of Hermes's own API versions."""

from __future__ import annotations

import json
from typing import Optional, Tuple

RELAY_PROTO = 1


def peer_protocol_range(payload: bytes) -> Optional[Tuple[int, int]]:
    """Message 1 carries an inclusive range of positive protocol integers.

    Malformed metadata is a silent handshake failure. A valid but incompatible range gets the
    host's ordinary message 2, then close code 3 after proof of the PSK, never a service stream.
    """
    try:
        hello = json.loads(payload)
    except (ValueError, UnicodeError):
        return None
    if not isinstance(hello, dict):
        return None
    versions = hello.get("relay_proto")
    if not isinstance(versions, list) or len(versions) != 2:
        return None
    low, high = versions
    if type(low) is not int or type(high) is not int or not 1 <= low <= high:
        return None
    return low, high
