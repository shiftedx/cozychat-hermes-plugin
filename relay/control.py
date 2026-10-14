"""Phone management shared by the encrypted control stream, Desktop and CLI.

The Noise static key identifies a phone. Push registrations belong to that key, so revoking a
phone removes its notification keys too; a phone cannot replace another phone's registration.
"""

from __future__ import annotations

import threading
from typing import Any, Callable, Dict, Optional

from ..devices import DeviceStore
from .pairing import PairingStore


class ControlError(RuntimeError):
    def __init__(self, code: str, status: int = 400) -> None:
        super().__init__(code)
        self.status = status


def phone_key(value: Any) -> bytes:
    try:
        key = bytes.fromhex(value)
        if len(key) != 32 or value != key.hex():
            raise ValueError
        return key
    except (TypeError, ValueError):
        raise ControlError("invalid_phone") from None


class PhoneManagement:
    def __init__(self, store: PairingStore, *, devices: Optional[DeviceStore] = None,
                 push_available: Callable[[], bool] = lambda: False,
                 rotate: Optional[Callable[[], Optional[Dict[str, Any]]]] = None,
                 rotation_generation: Callable[[], Optional[str]] = lambda: None,
                 rotation_ready: Callable[[], Optional[str]] = lambda: None,
                 retire_push: Optional[Callable[[bytes], Any]] = None,
                 push_cleanup_pending: Callable[[bytes], bool] = lambda key: False,
                 deliver_retirements: Optional[Callable[[], Any]] = None) -> None:
        self.store = store
        # D27: revoking a phone retires its consented relay registrations as durable tombstones.
        self._retire_push, self._push_cleanup_pending = retire_push, push_cleanup_pending
        # Relay HTTP never runs under pairing.lock: revoking only writes durable tombstones, and
        # this callable delivers them afterwards on a background thread.
        self._deliver_retirements = deliver_retirements
        self._delivery_lock = threading.Lock()
        self._delivery_wanted = False
        self._delivery_running = False
        self.delivery_thread: Optional[threading.Thread] = None
        self.devices = devices or DeviceStore(store.root.parent)
        self.push_available = push_available
        self._rotate = rotate
        self.rotation_generation, self.rotation_ready = rotation_generation, rotation_ready

    @property
    def can_rotate(self) -> bool:
        return self._rotate is not None

    def phones(self, caller: Optional[bytes] = None):
        if caller is not None:
            return [{"name": p.get("name") or "Phone", "is_this_phone": p["key"] == caller.hex()}
                    for p in self.store.phones()]
        return [{"id": p["key"], "name": p.get("name") or "Phone",
                 "added_at": p.get("added_at"), "is_this_phone": False} for p in self.store.phones()]

    def revoke(self, phone_id: str, *, rotate: bool = False) -> Dict[str, Any]:
        key = phone_key(phone_id)
        if type(rotate) is not bool:
            raise ControlError("bad_request")
        if rotate and not self.can_rotate:
            raise ControlError("rotation_unavailable", 503)
        with self.store.locked():
            removed = self._revoke_locked(key)
        self._deliver_later()
        # Revocation is durable even if rotation fails. Retry of a full revoke is idempotent.
        result = self.rotate() if rotate else {"rotated": False}
        return {"removed": removed, "pending_cleanup": self._push_cleanup_pending(key), **result}

    def _deliver_later(self) -> None:
        """Run tombstone delivery off the caller's thread, one worker at a time, never under a lock."""
        if self._deliver_retirements is None:
            return
        with self._delivery_lock:
            self._delivery_wanted = True
            if self._delivery_running:
                return
            self._delivery_running = True
            thread = threading.Thread(target=self._deliver_loop, name="cozychat-retire-push", daemon=True)
            self.delivery_thread = thread
        thread.start()

    def _deliver_loop(self) -> None:
        while True:
            with self._delivery_lock:
                if not self._delivery_wanted:
                    self._delivery_running = False
                    return
                self._delivery_wanted = False
            try:
                self._deliver_retirements()
            except Exception:
                pass  # Tombstones stay durable and are retried later.

    def _revoke_locked(self, key: bytes) -> bool:
        data = self.store._read()
        remaining = [p for p in data["phones"] if p.get("key") != key.hex()]
        removed = len(remaining) != len(data["phones"])
        data["phones"] = remaining
        self.store._write(data)
        if self._retire_push is not None:
            self._retire_push(key)
        else:
            for device in self.devices.list():
                if device.get("phone_key") == key.hex():
                    self.devices.remove(device["device_id"])
        return removed

    def rotate(self) -> Dict[str, Any]:
        if self._rotate is None:
            raise ControlError("rotation_unavailable", 503)
        return self._rotate() or {"rotated": True}

    def answer(self, request: Dict[str, Any], caller: bytes) -> Dict[str, Any]:
        result = self._answer_locked(request, caller)
        if request.get("op") == "revoke":
            self._deliver_later()
        return result

    def _answer_locked(self, request: Dict[str, Any], caller: bytes) -> Dict[str, Any]:
        with self.store.locked():
            if not self.store.is_approved(caller):
                raise ControlError("not_approved", 403)
            op = request.get("op")
            if op == "phones.list":
                return {"phones": self.phones(caller)}
            if op == "revoke":
                key = phone_key(request.get("phone_id", caller.hex()))
                rotate = request.get("rotate", False)
                if type(rotate) is not bool:
                    raise ControlError("bad_request")
                if key != caller or rotate:
                    raise ControlError("host_authority_required", 403)
                return {"removed": self._revoke_locked(caller), "rotated": False}
            if op == "rotate":
                raise ControlError("host_authority_required", 403)
            if op not in ("device.add", "device.remove", "device.list"):
                raise ControlError("unsupported")
            if not self.push_available():
                raise ControlError("push_unavailable", 403)
            owned = [d for d in self.devices.list() if d.get("phone_key") == caller.hex()]
            if op == "device.list":
                return {"devices": owned}
            device_id = request.get("device_id")
            if any(d["device_id"] == device_id and d.get("phone_key") != caller.hex()
                   for d in self.devices.list()):
                raise ControlError("device_owned_by_another_phone", 403)
            if op == "device.remove":
                return {"removed": self.devices.remove(device_id)}
            device = {k: request[k] for k in ("device_id", "push_id", "key_hex",
                                             "environment", "filters") if k in request}
            device["phone_key"] = caller.hex()
            self.devices.add(device)
            return {"added": True}
