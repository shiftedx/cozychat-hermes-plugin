"""The host key, the pairing window, the allowlist, and the one pending attempt (rules P1 to P5).

Everything lives in ``<hermes root>/cozychat/relay/``, 0700, files 0600, never in a profile
directory. It is shared state for the same reason the rest of the plugin's is (``state.py``): the
process that runs the listener (``hermes gateway run`` or ``hermes serve``, whichever holds
``listener.lock``) is usually not the process the person pairs from (``hermes cozychat pair``, or
the Desktop page later). The two talk through these files only:

``host.key``
    The host's static X25519 private key, hex. Made once, on the first pairing.
``pairing.json``
    ``window`` (the open pairing window: psk, expiry, id, or null), ``phones`` (the allowlist) and
    ``settings`` (what the pairing surface was told: push on or off, a relay URL, extra address
    hints).
``attempt.json``
    The one phone waiting for approval: its key, name and 6-digit code, and the decision once the
    person makes it. The listener writes it after the phone's first valid transport frame (P1 a);
    the pairing surface writes ``decision``; the listener acts on it.
``lan.json``
    The persisted listener port.

Every read-modify-write holds an exclusive OS lock on ``pairing.lock``. ``exp`` is checked on
this computer's clock only.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import secrets
import time
import unicodedata
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence
from urllib.parse import urlsplit

from ..devices import write_private
from ..locks import exclusive
from . import noise
from .platform import pid_alive

WINDOW_SECONDS = 600
LINK_VERSION = 1
LINK_PREFIX = "cozychat://pair-relay?d="
PORT_RANGE = (49152, 65535)
PHONE_NAME_MAX_BYTES = 64


@dataclass(frozen=True)
class Window:
    id: str
    psk: bytes
    exp: int


@dataclass(frozen=True)
class Attempt:
    id: str
    window_id: str
    phone_key: bytes
    phone_name: str
    code: str
    decision: Optional[str]
    pid: int


class PairingStore:
    """The files above, for one Hermes root."""

    def __init__(self, root: Path, *, clock=time.time) -> None:
        self.root = Path(root)
        self._clock = clock

    # -- the directory ------------------------------------------------------------------------

    def exists(self) -> bool:
        return self.root.is_dir()

    def ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        if self.root.parent.name == "cozychat":
            os.chmod(self.root.parent, 0o700)
        os.chmod(self.root, 0o700)

    @contextmanager
    def locked(self) -> Iterator[None]:
        self.ensure()
        with exclusive(self.root / "pairing.lock"):
            yield

    # -- the host key ---------------------------------------------------------------------------

    def host_private(self) -> bytes:
        path = self.root / "host.key"
        with self.locked():
            try:
                key = bytes.fromhex(path.read_text("utf-8").strip())
                if len(key) == noise.KEY_LEN:
                    return key
            except (OSError, ValueError):
                pass
            key = noise.generate_private_key()
            write_private(path, key.hex().encode("ascii"))
            return key

    def host_public(self) -> bytes:
        return noise.public_key(self.host_private())

    # -- the port -----------------------------------------------------------------------------

    def port(self) -> int:
        """The listener port: chosen once at random and kept, so address hints stay valid."""
        path = self.root / "lan.json"
        with self.locked():
            try:
                port = int(json.loads(path.read_text("utf-8"))["port"])
                if PORT_RANGE[0] <= port <= PORT_RANGE[1]:
                    return port
            except (OSError, ValueError, KeyError, TypeError):
                pass
            port = secrets.randbelow(PORT_RANGE[1] - PORT_RANGE[0] + 1) + PORT_RANGE[0]
            write_private(path, json.dumps({"port": port}).encode("utf-8"))
            return port

    # -- pairing.json -------------------------------------------------------------------------

    def _read(self) -> Dict[str, Any]:
        try:
            data = json.loads((self.root / "pairing.json").read_text("utf-8"))
        except (OSError, ValueError):
            data = {}
        if not isinstance(data, dict):
            data = {}
        data.setdefault("window", None)
        data.setdefault("phones", [])
        data.setdefault("settings", {})
        return data

    def _write(self, data: Dict[str, Any]) -> None:
        write_private(self.root / "pairing.json",
                      json.dumps(data, indent=2, sort_keys=True).encode("utf-8"))

    def open_window(self, settings: Optional[Dict[str, Any]] = None) -> Window:
        """A fresh pairing window of 10 minutes. Replaces any open one and any pending attempt."""
        self.host_private()
        with self.locked():
            data = self._read()
            window = {"id": secrets.token_hex(8), "psk": secrets.token_hex(noise.PSK_LEN),
                      "exp": int(self._clock()) + WINDOW_SECONDS}
            data["window"] = window
            if settings is not None:
                data["settings"] = dict(settings)
            self._write(data)
            (self.root / "attempt.json").unlink(missing_ok=True)
        return Window(window["id"], bytes.fromhex(window["psk"]), window["exp"])

    def cancel_window(self, window_id: Optional[str] = None) -> None:
        if not self.exists():
            return
        with self.locked():
            data = self._read()
            current = data.get("window") or {}
            if window_id is None or current.get("id") == window_id:
                data["window"] = None
                self._write(data)
                (self.root / "attempt.json").unlink(missing_ok=True)

    def window(self) -> Optional[Window]:
        """The open window, or None when there is none or it has expired on this clock."""
        if not self.exists():
            return None
        raw = self._read().get("window")
        try:
            window = Window(str(raw["id"]), bytes.fromhex(raw["psk"]), int(raw["exp"]))
        except (TypeError, KeyError, ValueError):
            return None
        if len(window.psk) != noise.PSK_LEN or self._clock() >= window.exp:
            return None
        return window

    def settings(self) -> Dict[str, Any]:
        return dict(self._read().get("settings") or {}) if self.exists() else {}

    def phones(self) -> List[Dict[str, Any]]:
        if not self.exists():
            return []
        return [p for p in self._read().get("phones", []) if isinstance(p, dict) and p.get("key")]

    def is_approved(self, phone_key: bytes) -> bool:
        return any(p.get("key") == phone_key.hex() for p in self.phones())

    def remove_phone(self, phone_key: bytes) -> bool:
        with self.locked():
            data = self._read()
            kept = [p for p in data["phones"] if p.get("key") != phone_key.hex()]
            if len(kept) == len(data["phones"]):
                return False
            data["phones"] = kept
            self._write(data)
            return True

    def wants_listener(self) -> bool:
        """Nothing listens until the first pairing window opens (the upgrade posture of 4.10)."""
        return self.window() is not None or bool(self.phones())

    # -- the pending attempt ------------------------------------------------------------------

    def attempt(self) -> Optional[Attempt]:
        if not self.exists():
            return None
        try:
            raw = json.loads((self.root / "attempt.json").read_text("utf-8"))
            return Attempt(str(raw["id"]), str(raw["window_id"]), bytes.fromhex(raw["phone_key"]),
                           str(raw["phone_name"]), str(raw["code"]), raw.get("decision"),
                           int(raw.get("pid") or 0))
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def begin_attempt(self, window_id: str, phone_key: bytes, phone_name: str,
                      code: str) -> Optional[str]:
        """Record the phone waiting for approval. None while a different phone already waits.

        The same phone coming back (a dropped connection, a second scan) replaces its own attempt.
        A pending attempt whose listener process is gone is stale and is replaced too.
        """
        with self.locked():
            window = self.window()
            if window is None or window.id != window_id:
                return None
            current = self.attempt()
            if current is not None and current.window_id == window_id \
                    and current.phone_key != phone_key and _alive(current.pid):
                return None
            attempt_id = secrets.token_hex(8)
            write_private(self.root / "attempt.json", json.dumps({
                "id": attempt_id, "window_id": window_id, "phone_key": phone_key.hex(),
                "phone_name": phone_name, "code": code, "decision": None, "pid": os.getpid(),
                "at": int(self._clock())}, sort_keys=True).encode("utf-8"))
            return attempt_id

    def decide(self, attempt_id: str, approve: bool) -> bool:
        """The person's answer, from whichever surface they used. False if that attempt is gone."""
        with self.locked():
            current = self.attempt()
            window = self.window()
            if current is None or current.id != attempt_id or current.decision is not None \
                    or window is None or current.window_id != window.id:
                return False
            raw = json.loads((self.root / "attempt.json").read_text("utf-8"))
            raw["decision"] = "approve" if approve else "refuse"
            write_private(self.root / "attempt.json",
                          json.dumps(raw, sort_keys=True).encode("utf-8"))
            return True

    def settle(self, attempt_id: str) -> str:
        """Act on the decision for ``attempt_id``. Called by the listener that holds the session.

        ``approved``: the phone joined the allowlist, the psk is consumed and the window closed
        (P1 b). ``refused``, ``expired`` or ``gone`` end the session with close code 7.
        ``pending`` means nobody has answered yet.
        """
        with self.locked():
            current = self.attempt()
            if current is None or current.id != attempt_id:
                return "gone"
            window = self.window()
            if window is None or window.id != current.window_id:
                (self.root / "attempt.json").unlink(missing_ok=True)
                return "expired"
            if current.decision is None:
                return "pending"
            (self.root / "attempt.json").unlink(missing_ok=True)
            if current.decision != "approve":
                return "refused"
            data = self._read()
            data["phones"] = [p for p in data["phones"] if p.get("key") != current.phone_key.hex()]
            data["phones"].append({"key": current.phone_key.hex(), "name": current.phone_name,
                                   "added_at": int(self._clock())})
            data["window"] = None
            self._write(data)
            return "approved"

    def abandon_attempt(self, attempt_id: str) -> None:
        """The phone left before a decision. The window stays open and unchanged (P2)."""
        if not self.exists():
            return
        with self.locked():
            current = self.attempt()
            if current is not None and current.id == attempt_id:
                (self.root / "attempt.json").unlink(missing_ok=True)

    def clear_attempts(self) -> None:
        """A new listener holds no session, so no attempt can still be waiting on one."""
        if self.exists():
            with self.locked():
                (self.root / "attempt.json").unlink(missing_ok=True)


# -- the link ---------------------------------------------------------------------------------


def pairing_link(host_public: bytes, window: Window, lan: Sequence[str],
                 relay: Optional[str] = None) -> str:
    """``cozychat://pair-relay?d=<base64url(JSON)>``. Refuses a link with no route at all."""
    if not lan and not relay:
        raise ValueError("a pairing link needs a home-network address or a relay")
    body: Dict[str, Any] = {"v": LINK_VERSION, "host": host_public.hex(), "psk": window.psk.hex(),
                            "exp": window.exp}
    if lan:
        body["lan"] = list(lan)
    if relay:
        body["relay"] = relay
    encoded = base64.urlsafe_b64encode(json.dumps(body, separators=(",", ":")).encode("utf-8"))
    return LINK_PREFIX + encoded.decode("ascii").rstrip("=")


def decode_link(link: str) -> Dict[str, Any]:
    if not link.startswith(LINK_PREFIX):
        raise ValueError("not a pair-relay link")
    data = link[len(LINK_PREFIX):].split("&", 1)[0]
    return json.loads(base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)))


def check_advertise(value: str) -> str:
    """``host:port`` or ``[ipv6]:port``, as ``--advertise`` takes it."""
    text = value.strip()
    if text.startswith("["):
        host, sep, port = text[1:].partition("]:")
        if not sep:
            raise ValueError(f"{value!r} is not [ipv6]:port")
        ipaddress.IPv6Address(host)
    else:
        host, sep, port = text.rpartition(":")
        if not sep or not host or ":" in host:
            raise ValueError(f"{value!r} is not host:port")
    if not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError(f"{value!r} has no valid port")
    return text


def check_relay_url(value: str) -> str:
    """``wss://``, or ``ws://`` only for a private-range or ``localhost`` host (contract 1)."""
    parts = urlsplit(value.strip())
    if not parts.hostname:
        raise ValueError(f"{value!r} is not a relay URL")
    if parts.scheme == "wss":
        return value.strip()
    if parts.scheme == "ws":
        host = parts.hostname
        if host == "localhost":
            return value.strip()
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address is not None and (address.is_private or address.is_loopback):
            return value.strip()
        raise ValueError("ws:// is allowed only for a private address or localhost; use wss://")
    raise ValueError("a relay URL starts with wss://")


@dataclass(frozen=True)
class PhoneName:
    """Message 1's ``phone_name``, twice.

    ``raw`` is the exact UTF-8 bytes the phone sent, with no trimming, truncation or fallback. The
    pairing code is computed over these and nothing else, so the phone, which hashes its own name,
    always gets the same code (rule R1).

    ``display`` is only for the prompt and ``pairing.json``: control, format and bidi characters
    removed so a name cannot rewrite the terminal line, and ``Phone`` when nothing printable is left.
    It never feeds the code.
    """

    raw: bytes
    display: str


def phone_name_from(payload: bytes) -> Optional[PhoneName]:
    """The name from message 1, or None when the contract says to drop message 1 silently: no JSON
    object, ``phone_name`` missing or not a string, not encodable as UTF-8 (a lone surrogate escape),
    or longer than 64 UTF-8 bytes (contract section 2). The host never truncates: the phone already
    cut its name before computing its code, so a longer one is not from a phone that follows the
    contract."""
    try:
        name = json.loads(payload.decode("utf-8")).get("phone_name")
    except (ValueError, AttributeError, UnicodeDecodeError):
        return None
    if not isinstance(name, str):
        return None
    try:
        raw = name.encode("utf-8")
    except UnicodeEncodeError:
        return None
    if len(raw) > PHONE_NAME_MAX_BYTES:
        return None
    return PhoneName(raw, display_name(name))


def display_name(name: str) -> str:
    """``name`` safe to print: no C0/C1 controls, no bidi or other format characters (ZWJ, which
    joins emoji, stays), whitespace runs as one space, at most 64 UTF-8 bytes, never empty.

    The 64-byte cut only guards callers that pass a name not checked by :func:`phone_name_from`;
    a name from message 1 is already at most 64 bytes."""
    kept = []
    for char in name:
        category = unicodedata.category(char)
        if category in ("Zl", "Zp") or char.isspace():
            kept.append(" ")
        elif category.startswith("C") and char != "\u200d":
            continue
        else:
            kept.append(char)
    text = " ".join("".join(kept).split())
    text = text.encode("utf-8")[:PHONE_NAME_MAX_BYTES].decode("utf-8", "ignore").strip()
    return text or "Phone"


def grouped(code: str) -> str:
    """``428913`` as ``428 913``."""
    return f"{code[:3]} {code[3:]}"


def _alive(pid: int) -> bool:
    return pid_alive(pid)
