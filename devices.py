"""Paired phones and their push keys, on disk in the shared state directory.

Two files so the secret and the index have different blast radii: ``devices.json`` answers "what is
paired" and can be read out to the owner, ``keys/<device_id>`` holds the raw key material and
nothing else. Both are written 0600 through a temp file + ``os.replace`` so a crash mid-write
leaves the previous state, never half of the new one.

Beside the plugin folder until 2026-09-15, and moved out of it because the pairing has to be
readable by every process of this Hermes and the plugin folder is per profile. ``state.py`` says
why, and moves an older layout across on first load.

The key bytes are the HKDF input keying material the phone uses, which is the UTF-8 encoding of the
push-key string CozyChat generated and stored in its Keychain. The plugin never sees it in any other
form and never sends it anywhere: it arrives over the SSH session on stdin and is only ever used as
an argument to :func:`push.seal`.
"""

from __future__ import annotations

import json
import os
import re
import time
import hashlib
from pathlib import Path
from typing import Any, Dict, List

from .locks import exclusive

# A device id becomes a file name, so it is constrained rather than escaped.
_DEVICE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def relay_url_or_empty(value: Any) -> str:
    """A relay base URL a registration may be retired at, or "" when it is not an acceptable one.

    It arrives from the paired phone and becomes the target of a DELETE, so it is held to the
    relay's own rule: https, or plain http only for a loopback or private host.
    """
    import ipaddress
    from urllib.parse import urlsplit
    if not isinstance(value, str) or not value.strip():
        return ""
    parts = urlsplit(value.strip())
    host = parts.hostname
    if not host or parts.query or parts.fragment or parts.username or parts.password:
        return ""
    if parts.scheme == "https":
        return value.strip().rstrip("/")
    if parts.scheme == "http":
        if host == "localhost":
            return value.strip().rstrip("/")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return ""
        if address.is_private or address.is_loopback:
            return value.strip().rstrip("/")
    return ""


class DeviceStore:
    """The paired devices for one Hermes profile."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.index_path = self.path / "devices.json"
        self.keys_path = self.path / "keys"

    # -- reading ---------------------------------------------------------

    def list(self) -> List[Dict[str, Any]]:
        """Every paired device, newest last. Missing or corrupt index reads as "nothing paired"."""
        try:
            loaded = json.loads(self.index_path.read_text("utf-8"))
        except (OSError, ValueError):
            return []
        if not isinstance(loaded, list):
            return []
        return [d for d in loaded if isinstance(d, dict) and d.get("device_id")]

    def key(self, device_id: str) -> bytes:
        """The HKDF input keying material for one device.

        ponytail: the design names a separate ``key_id`` so one device could hold two live keys
        through a rotation. One key per device is all pairing produces today, so the key file is
        named by the device id; a rotation that needs an overlap adds the indirection then.
        """
        return (self.keys_path / _checked(device_id)).read_bytes()

    def key_for(self, device_id: str, profile: str) -> bytes:
        """The key for one explicitly consented phone/profile pair."""
        return (self.keys_path / _key_name(_checked(device_id), _checked_profile(profile))).read_bytes()

    # -- writing ---------------------------------------------------------

    def add(self, device: Dict[str, Any]) -> None:
        self.path.mkdir(parents=True, exist_ok=True)
        with exclusive(self.path / "devices.lock"):
            self._add(device)

    def _add(self, device: Dict[str, Any]) -> None:
        """Pair (or re-pair) one device. ``key_hex`` is consumed into the key file, never indexed."""
        device_id = _checked(device.get("device_id"))
        # No length floor: the relay contract froze the push key as any non-empty string, and the
        # app's own frozen interop vector uses a short one.
        key = bytes.fromhex(str(device["key_hex"]))
        if not key:
            raise ValueError("key_hex carries no key material")
        profile = str(device.get("profile") or "")
        consent_version = int(device.get("consent_version") or 0)
        record = {
            "device_id": device_id,
            "push_id": str(device.get("push_id") or ""),
            "environment": str(device.get("environment") or "production"),
            "filters": dict(device.get("filters") or {}),
            "created_at": float(device.get("created_at") or time.time()),
            "profile": profile,
            "consent_version": consent_version,
        }
        if device.get("phone_key") is not None:
            record["phone_key"] = device["phone_key"]
        relay_url = relay_url_or_empty(device.get("relay_url"))
        if relay_url:
            # Where THIS registration lives, so a later DELETE goes there and not to the default.
            record["relay_url"] = relay_url
        if not record["push_id"]:
            raise ValueError("push_id is required")
        self.keys_path.mkdir(parents=True, exist_ok=True)
        os.chmod(self.keys_path, 0o700)
        key_name = _key_name(device_id, profile) if consent_version else device_id
        write_private(self.keys_path / key_name, key)
        self._save([d for d in self.list() if not _same_identity(d, device_id, profile)] + [record])

    def remove(self, device_id: str, profile: str = "") -> bool:
        """Forget one device and its key. False when it was not paired."""
        self.path.mkdir(parents=True, exist_ok=True)
        with exclusive(self.path / "devices.lock"):
            return self._remove(device_id, profile)

    def _remove(self, device_id: str, profile: str = "") -> bool:
        device_id = _checked(device_id)
        paired = self.list()
        if profile:
            profile = _checked_profile(profile)
            removed = [d for d in paired if _same_identity(d, device_id, profile)]
            remaining = [d for d in paired if not _same_identity(d, device_id, profile)]
        else:
            removed = [d for d in paired if d["device_id"] == device_id]
            remaining = [d for d in paired if d["device_id"] != device_id]
        for device in removed:
            key_name = _key_name(device_id, str(device.get("profile") or "")) \
                if int(device.get("consent_version") or 0) else device_id
            (self.keys_path / key_name).unlink(missing_ok=True)
        if len(remaining) == len(paired):
            return False
        self._save(remaining)
        return True

    def legacy(self) -> List[Dict[str, Any]]:
        """Records that predate explicit consent and must never authorize delivery."""
        return [d for d in self.list() if not _consented(d)]

    def consented(self, device_id: str, profile: str) -> bool:
        return any(_same_identity(d, device_id, profile) and _consented(d) for d in self.list())

    def discard_orphan_keys(self) -> None:
        """Legacy keys have no consent record and must not survive an upgrade."""
        expected = {_key_name(str(d["device_id"]), str(d["profile"])) for d in self.list()
                    if _consented(d)}
        try:
            paths = list(self.keys_path.iterdir())
        except OSError:
            return
        for path in paths:
            if path.name not in expected:
                path.unlink(missing_ok=True)

    def _save(self, devices: List[Dict[str, Any]]) -> None:
        self.path.mkdir(parents=True, exist_ok=True)
        # The shared state directory, which the host script may reach before anything has opened
        # the database that would otherwise set this. It holds key material either way.
        os.chmod(self.path, 0o700)
        write_private(self.index_path, json.dumps(devices, indent=2, sort_keys=True).encode("utf-8"))


def _checked(device_id: Any) -> str:
    text = str(device_id or "")
    if not _DEVICE_ID.fullmatch(text):
        raise ValueError(f"invalid device id: {device_id!r}")
    return text


def _checked_profile(profile: Any) -> str:
    text = str(profile or "")
    if not _DEVICE_ID.fullmatch(text):
        raise ValueError(f"invalid profile: {profile!r}")
    return text


def _consented(device: Dict[str, Any]) -> bool:
    return int(device.get("consent_version") or 0) == 1 and bool(device.get("profile"))


def _same_identity(device: Dict[str, Any], device_id: str, profile: str) -> bool:
    return device.get("device_id") == device_id and str(device.get("profile") or "") == profile


def _key_name(device_id: str, profile: str) -> str:
    """A safe stable name; a phone may consent independently for multiple profiles."""
    return hashlib.sha256((device_id + "\0" + profile).encode("utf-8")).hexdigest()


def write_private(path: Path, data: bytes) -> None:
    """Atomic 0600 write: a reader sees the old bytes or the new ones, never a truncated file.

    Shared with ``live_activities.py``, which keeps its registrations under the same rules.
    """
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    os.replace(tmp, path)
    os.chmod(path, 0o600)
