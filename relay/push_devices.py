"""Explicit, versioned push consent and its durable retirement path (D27)."""

from __future__ import annotations

import json
import os
import time
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

from ..devices import DeviceStore, relay_url_or_empty
from ..locks import exclusive
from ..state import SharedState, shared_state

CONSENT_VERSION = 1


class PushDevices:
    """Push authority is one consented phone/profile pair, never merely a pairing."""

    def __init__(self, store: DeviceStore, relay: Any, state: Optional[SharedState] = None) -> None:
        self.store, self.relay = store, relay
        self.state = state or shared_state()
        self.quarantine_legacy()

    def paired(self, phone_key: bytes, profile: Optional[str] = None) -> bool:
        device_id = phone_key.hex()
        return any(d["device_id"] == device_id and d.get("consent_version") == CONSENT_VERSION
                   and (profile is None or d.get("profile") == profile) for d in self.store.list())

    def allows(self, push_id: str) -> bool:
        devices = self.store.list()
        if any(d["push_id"] == push_id and d.get("consent_version") == CONSENT_VERSION for d in devices):
            return True
        with self.state.read() as db:
            row = db.execute("SELECT device_id, profile, consent_version FROM activities WHERE push_id = ?",
                             (push_id,)).fetchone()
        return bool(row and row[2] == CONSENT_VERSION and self.store.consented(row[0], row[1]))

    def allows_live_activity(self, activity_id: str, push_id: str, device_id: str,
                              profile: str) -> bool:
        """A queued card must still belong to this consented phone/profile pair."""
        if not self.store.consented(device_id, profile):
            return False
        with self.state.read() as db:
            row = db.execute(
                "SELECT 1 FROM activities WHERE activity_id = ? AND push_id = ?"
                " AND device_id = ? AND profile = ? AND consent_version = ?",
                (activity_id, push_id, device_id, profile, CONSENT_VERSION)).fetchone()
        return row is not None

    def quarantine_legacy(self) -> None:
        """Drop pre-consent authority locally. This migration never contacts the relay."""
        legacy = self.store.legacy()
        with self.state.write() as db:
            db.execute("DELETE FROM activities WHERE consent_version != ?", (CONSENT_VERSION,))
        if legacy:
            for device in legacy:
                _discard_outbox(self.store.path / "outbox.sqlite", str(device["device_id"]))
                self.store.remove(str(device["device_id"]), str(device.get("profile") or ""))
        self.store.discard_orphan_keys()
        _quarantine_outbox(self.store.path / "outbox.sqlite")

    def handle(self, phone_key: bytes, request: Dict[str, Any]) -> Dict[str, Any]:
        device_id = phone_key.hex()
        op = request["op"]
        if request.get("device_id", device_id) != device_id:
            raise ValueError("wrong_device")
        profile = str(request.get("profile") or "")
        self.store.path.mkdir(parents=True, exist_ok=True)
        with exclusive(self.store.path / "outbox.lock"):
            if op == "device.list":
                return {"devices": [d for d in self.store.list() if d["device_id"] == device_id
                                    and d.get("consent_version") == CONSENT_VERSION]}
            if op == "device.add":
                if not self.relay.base:
                    raise ValueError("push_unavailable")
                device = dict(request.get("device") or {})
                profile = profile or str(device.get("profile") or "")
                if device.get("device_id", device_id) != device_id:
                    raise ValueError("wrong_device")
                if int(device.get("consent_version") or 0) != CONSENT_VERSION or not profile:
                    raise ValueError("consent_required")
                if device.get("profile") not in (None, profile):
                    raise ValueError("wrong_profile")
                device.update(device_id=device_id, profile=profile, consent_version=CONSENT_VERSION)
                return self._add(device, profile)
            if op == "device.remove":
                if not profile:
                    raise ValueError("profile_required")
                removed = self.retire(device_id, profile)
                return {"removed": removed, "enabled": False,
                        "pending_cleanup": self.pending_retirements(device_id, profile) > 0}
        raise ValueError("unsupported")

    def retire_phone(self, phone_key: bytes, *, deliver: bool = True) -> bool:
        return self.retire(phone_key.hex(), deliver=deliver)

    def list_from_host(self, profile: Optional[str] = None) -> list[Dict[str, Any]]:
        return [d for d in self.store.list() if d.get("consent_version") == CONSENT_VERSION
                and (profile is None or d.get("profile") == profile)]

    def add_from_host(self, device: Dict[str, Any], profile: Optional[str] = None) -> Dict[str, Any]:
        """The setup script's equivalent of an explicit ``device.add`` control request."""
        device = dict(device)
        device_id = str(device.get("device_id") or "")
        profile = str(profile or device.get("profile") or "")
        if int(device.get("consent_version") or 0) != CONSENT_VERSION or not profile:
            raise ValueError("consent_required")
        device.update(profile=profile, consent_version=CONSENT_VERSION)
        with exclusive(self.store.path / "outbox.lock"):
            return self._add(device, profile)

    def _add(self, device: Dict[str, Any], profile: str) -> Dict[str, Any]:
        device_id = str(device.get("device_id") or "")
        previous = next((d for d in self.store.list() if d["device_id"] == device_id
                         and d.get("profile") == profile), None)
        self.store.add(device)
        if previous and previous["push_id"] != device["push_id"]:
            self._tombstone(previous["push_id"], device_id, profile,
                            relay_url_or_empty(previous.get("relay_url")))
        self.retry_retirements()
        return {"device_id": device_id, "profile": profile, "enabled": True}

    def retire(self, device_id: str, profile: Optional[str] = None, *, deliver: bool = True) -> bool:
        """Revoke authority first, then retain consented registrations as tombstones."""
        devices = [d for d in self.store.list() if d["device_id"] == device_id
                   and d.get("consent_version") == CONSENT_VERSION
                   and (profile is None or d.get("profile") == profile)]
        if not devices:
            return False
        profiles = {str(d["profile"]) for d in devices}
        with self.state.write() as db:
            placeholders = ",".join("?" for _ in profiles)
            cards = db.execute("SELECT activity_id, push_id, profile FROM activities WHERE device_id = ?"
                               f" AND profile IN ({placeholders}) AND consent_version = ?",
                               (device_id, *profiles, CONSENT_VERSION)).fetchall()
            db.execute("DELETE FROM activities WHERE device_id = ?"
                       f" AND profile IN ({placeholders})", (device_id, *profiles))
        for profile_name in profiles:
            _discard_outbox(self.store.path / "outbox.sqlite", device_id,
                            [card[0] for card in cards], profile_name)
        for device in devices:
            self._tombstone(str(device["push_id"]), device_id, str(device["profile"]),
                            relay_url_or_empty(device.get("relay_url")))
            self.store.remove(device_id, str(device["profile"]))
        # A card's registration was made by this plugin, at the relay it posts to.
        card_relay = relay_url_or_empty(getattr(self.relay, "base", ""))
        for _, push_id, card_profile in cards:
            self._tombstone(str(push_id), device_id, str(card_profile), card_relay)
        if deliver:
            self.retry_retirements()
        return True

    def _tombstone(self, push_id: str, device_id: str = "", profile: str = "",
                   relay_url: str = "") -> None:
        """Retain a registration for DELETE at the relay it was made at ("" means the current one)."""
        if not push_id:
            return
        now = time.time()
        with self.state.write() as db:
            db.execute("INSERT OR IGNORE INTO push_tombstones"
                       " (push_id, created_at, attempts, retry_after, device_id, profile, relay_url)"
                       " VALUES (?, ?, 0, ?, ?, ?, ?)",
                       (push_id, now, now, device_id, profile, relay_url))

    def retire_registration(self, push_id: str) -> None:
        """Retire a consented Live Activity registration after its local row is gone."""
        self._tombstone(push_id)
        self.retry_retirements()

    def retry_retirements(self, now: Optional[float] = None) -> int:
        now = time.time() if now is None else now
        with self.state.read() as db:
            rows = db.execute("SELECT push_id, attempts, relay_url FROM push_tombstones"
                              " WHERE retry_after <= ?", (now,)).fetchall()
        completed = 0
        for push_id, attempts, relay_url in rows:
            # The relay this registration was made at, never silently the default one.
            target = relay_url_or_empty(relay_url)
            status = self.relay.forget(str(push_id), relay_url=target) if target \
                else self.relay.forget(str(push_id))
            with self.state.write() as db:
                if 200 <= status < 300 or status == 404:
                    db.execute("DELETE FROM push_tombstones WHERE push_id = ?", (push_id,))
                    completed += 1
                else:
                    db.execute("UPDATE push_tombstones SET attempts = ?, retry_after = ? WHERE push_id = ?",
                               (int(attempts) + 1, now + _backoff(int(attempts)), push_id))
        return completed

    def pending_retirements(self, device_id: Optional[str] = None,
                            profile: Optional[str] = None) -> int:
        with self.state.read() as db:
            if device_id is None:
                row = db.execute("SELECT COUNT(*) FROM push_tombstones").fetchone()
            elif profile is None:
                row = db.execute("SELECT COUNT(*) FROM push_tombstones WHERE device_id = ?",
                                 (device_id,)).fetchone()
            else:
                row = db.execute("SELECT COUNT(*) FROM push_tombstones WHERE device_id = ? AND profile = ?",
                                 (device_id, profile)).fetchone()
            return int(row[0])


def export_tombstones(root: Path, destination: Path) -> int:
    """Copy the retained registrations out of the state directory so an uninstall cannot lose them.

    Holds relay URLs and push ids only: no key, token or device secret. Returns how many remain.
    """
    state = SharedState(Path(root))
    try:
        with state.read() as db:
            rows = db.execute("SELECT push_id, device_id, profile, relay_url, attempts"
                              " FROM push_tombstones").fetchall()
    finally:
        state.close()
    kept = [{"push_id": r[0], "device_id": r[1], "profile": r[2], "relay_url": r[3], "attempts": r[4]}
            for r in rows]
    _write_tombstone_file(Path(destination), kept)
    return len(kept)


def retry_exported_tombstones(source: Path, relay_url: str = "https://push.cozylabs.ai") -> int:
    """DELETE every registration in an exported file, keeping the ones that still fail."""
    source = Path(source)
    try:
        loaded = json.loads(source.read_text("utf-8"))
    except (OSError, ValueError):
        return 0
    if not isinstance(loaded, list):
        return 0
    remaining = []
    for row in loaded:
        if not isinstance(row, dict) or not row.get("push_id"):
            continue
        target = relay_url_or_empty(row.get("relay_url")) or relay_url
        status = _CleanupRelay(target).forget(str(row["push_id"]))
        if not (200 <= status < 300 or status == 404):
            row["attempts"] = int(row.get("attempts") or 0) + 1
            remaining.append(row)
    _write_tombstone_file(source, remaining)
    return len(remaining)


def _write_tombstone_file(path: Path, rows: list) -> None:
    if not rows:
        path.unlink(missing_ok=True)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(rows, handle, indent=2, sort_keys=True)
    os.replace(temporary, path)


def cleanup_from_path(root: Path, device_id: Optional[str] = None, profile: Optional[str] = None,
                      relay_url: str = "https://push.cozylabs.ai") -> Dict[str, Any]:
    """Host-script entry point, intentionally independent of a Hermes runtime."""
    root = Path(root)
    state = SharedState(root)
    store = DeviceStore(root)
    relay = _CleanupRelay(relay_url)
    try:
        policy = PushDevices(store, relay, state)
        removed = policy.retire(device_id, profile) if device_id else False
        if device_id is None:
            for device in list(store.list()):
                if device.get("consent_version") == CONSENT_VERSION:
                    removed = policy.retire(str(device["device_id"]), str(device["profile"])) or removed
        policy.retry_retirements()
        pending = policy.pending_retirements()
        return {"removed": removed, "devices": store.list(), "pending_cleanup": bool(pending),
                "tombstones": pending}
    finally:
        state.close()


def device_operation_from_path(root: Path, op: str, payload_or_device_id: Any,
                               profile: Optional[str] = None,
                               relay_url: str = "https://push.cozylabs.ai") -> Dict[str, Any]:
    """Minimal host-script API. Adds must carry the same explicit-consent fields as control."""
    root = Path(root)
    state = SharedState(root)
    store = DeviceStore(root)
    relay = _CleanupRelay(relay_url)
    try:
        policy = PushDevices(store, relay, state)
        if op == "list":
            return {"devices": policy.list_from_host(profile)}
        if op == "remove":
            return cleanup_from_path(root, str(payload_or_device_id), profile, relay_url)
        if op != "add" or not isinstance(payload_or_device_id, dict):
            raise ValueError("unsupported")
        return policy.add_from_host(payload_or_device_id, profile)
    finally:
        state.close()


def _backoff(attempts: int) -> float:
    return min(2.0 ** min(attempts, 10), 900.0)


def _quarantine_outbox(path: Path) -> None:
    if not path.exists():
        return
    with sqlite3.connect(path, timeout=10.0) as db:
        for table in ("pending", "live_pending"):
            columns = {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
            if "consent_version" in columns:
                db.execute(f"DELETE FROM {table} WHERE consent_version != ?", (CONSENT_VERSION,))
            else:
                db.execute(f"DELETE FROM {table}")


def _discard_outbox(path: Path, device_id: str, activity_ids=(), profile: Optional[str] = None) -> None:
    if not path.exists():
        return
    with sqlite3.connect(path, timeout=10.0) as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(pending)")}
        if profile is not None and "profile" in columns:
            db.execute("DELETE FROM pending WHERE device_id = ? AND profile = ?", (device_id, profile))
        else:
            db.execute("DELETE FROM pending WHERE device_id = ?", (device_id,))
        for activity_id in activity_ids:
            db.execute("DELETE FROM live_pending WHERE activity_id = ?", (activity_id,))


class _CleanupRelay:
    """The host script's stdlib-only DELETE client."""

    def __init__(self, url: str) -> None:
        self.base = url.rstrip("/")

    def forget(self, push_id: str, relay_url: Optional[str] = None) -> int:
        request = urllib.request.Request(
            (relay_url.rstrip("/") if relay_url else self.base) + "/register/" + urllib.parse.quote(push_id, safe=""), method="DELETE",
            headers={"User-Agent": "cozychat-hermes-plugin"})
        try:
            with urllib.request.urlopen(request, timeout=15.0) as response:
                return int(response.status)
        except urllib.error.HTTPError as error:
            return int(error.code)
        except Exception:
            return 0
