"""Per-phone notify subscriptions visible to the gateway and listener in different processes."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Dict, List

from .devices import DeviceStore

# A lease is renewed only by a heartbeat receipt from the phone, never by event traffic, so it is
# sized to one heartbeat interval plus the receipt deadline (see relay/services.py).
LEASE_SECONDS = 6.0
# How long a locally delivered event may stay unacknowledged before it falls back to the relay.
FALLBACK_SECONDS = 10.0
PROOF_DOMAIN = b"cozychat-local-push-v1\0"


def push_proof(key: bytes, phone_key: bytes, profile: str) -> str:
    """A push key proves this phone owns a registration, without putting that key on the wire."""
    return hmac.new(key, PROOF_DOMAIN + phone_key + profile.encode("utf-8"), hashlib.sha256).hexdigest()


class NotifySubscriptions:
    def __init__(self, state) -> None:
        self.state = state

    def bindings(self, proofs: Dict[str, str], phone_key: bytes):
        store = DeviceStore(self.state.root)
        found = []
        for device in store.list():
            # D27: only an explicitly consented phone/profile registration can bind a subscription.
            profile = str(device.get("profile") or "")
            proof = proofs.get(profile)
            if proof is None or device.get("consent_version") != 1:
                continue
            try:
                key = store.key_for(device["device_id"], profile)
            except OSError:
                continue
            if hmac.compare_digest(push_proof(key, phone_key, profile), proof):
                found.append((device["device_id"], profile))
        return found

    def refresh(self, identifier: str, bindings, filters, start_seq=None, now=None,
                lease_seconds=LEASE_SECONDS) -> int:
        now = time.time() if now is None else now
        with self.state.write() as db:
            if start_seq is None:
                # Opening and stamping the tail cursor must be one writer transaction. Otherwise
                # an event can be queued for relay in the gap and then also delivered locally.
                db.execute("BEGIN IMMEDIATE")
                start_seq = int(db.execute("SELECT COALESCE(MAX(seq), 0) FROM frames").fetchone()[0])
            db.execute("DELETE FROM notify_subscriptions WHERE expires_at <= ?", (now,))
            for device_id, profile in bindings:
                db.execute(
                    "INSERT INTO notify_subscriptions"
                    " (subscription_id, device_id, profile, filters, start_seq, expires_at, closed_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, NULL)"
                    " ON CONFLICT(subscription_id, device_id, profile)"
                    " DO UPDATE SET expires_at = excluded.expires_at",
                    (identifier, device_id, profile, json.dumps(filters), start_seq,
                     now + lease_seconds))
        return start_seq

    def close(self, identifier: str, now=None) -> None:
        """Withdraw suppression at once. Later events go to the relay; held ones are released."""
        now = time.time() if now is None else now
        with self.state.write() as db:
            db.execute("UPDATE notify_subscriptions SET closed_at = ?, expires_at = ?"
                       " WHERE subscription_id = ?", (now, now, identifier))

    def hold(self, device_id: str, profile: str, filter_name: str, seq: int, event_id: str,
             category: str, collapse_id: str, payload, level, now=None,
             fallback_seconds=FALLBACK_SECONDS) -> bool:
        """Keep a relay fallback for an event routed locally, until the phone acknowledges it.

        Coverage and the held row are one writer transaction, so a stream that closes at the same
        moment either sees the row (and releases it) or is seen closed (and the caller enqueues).
        The caller only asks for devices that opted in to away push; others are never held.
        """
        now = time.time() if now is None else now
        with self.state.write() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute(
                "SELECT subscription_id, filters FROM notify_subscriptions"
                " WHERE device_id = ? AND profile = ? AND start_seq < ? AND expires_at > ?"
                " AND closed_at IS NULL", (device_id, profile, seq, now)).fetchall()
            for subscription_id, filters in rows:
                if json.loads(filters).get(filter_name, False):
                    db.execute(
                        "INSERT OR REPLACE INTO notify_pending (event_id, device_id, subscription_id,"
                        " category, collapse_id, payload, level, deadline)"
                        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (event_id, device_id, subscription_id, category, collapse_id,
                         json.dumps(payload, separators=(",", ":"), sort_keys=True), level,
                         now + fallback_seconds))
                    return True
        return False

    def acknowledge(self, identifier: str, event_id: str) -> None:
        with self.state.write() as db:
            db.execute("DELETE FROM notify_pending WHERE event_id = ? AND subscription_id = ?",
                       (event_id, identifier))

    def release(self, outbox, identifier=None, now=None) -> int:
        """Send unacknowledged events to the relay outbox: this subscription's, or every due one."""
        now = time.time() if now is None else now
        with self.state.read() as db:
            if identifier is None:
                rows = db.execute("SELECT event_id, device_id, category, collapse_id, payload, level,"
                                  " (SELECT profile FROM notify_subscriptions s WHERE"
                                  " s.subscription_id = notify_pending.subscription_id AND"
                                  " s.device_id = notify_pending.device_id LIMIT 1)"
                                  " FROM notify_pending WHERE deadline <= ?", (now,)).fetchall()
            else:
                rows = db.execute("SELECT event_id, device_id, category, collapse_id, payload, level,"
                                  " (SELECT profile FROM notify_subscriptions s WHERE"
                                  " s.subscription_id = notify_pending.subscription_id AND"
                                  " s.device_id = notify_pending.device_id LIMIT 1)"
                                  " FROM notify_pending WHERE subscription_id = ?",
                                  (identifier,)).fetchall()
        released = 0
        for event_id, device_id, category, collapse_id, payload, level, profile in rows:
            body = json.loads(payload)
            # Enqueue before delete: a crash in between duplicates a banner instead of losing it.
            # The consent version is re-checked by the drain, which refuses a revoked registration.
            outbox.enqueue(device_id, category, collapse_id, body, level=level,
                           profile=str(profile or body.get("agentName") or ""), consent_version=1)
            with self.state.write() as db:
                db.execute("DELETE FROM notify_pending WHERE event_id = ? AND device_id = ?",
                           (event_id, device_id))
            released += 1
        return released

    def release_due(self, outbox, now=None) -> int:
        return self.release(outbox, None, now)

    def covers(self, device_id: str, profile: str, filter_name: str, seq: int, now=None) -> bool:
        now = time.time() if now is None else now
        with self.state.read() as db:
            rows = db.execute(
                "SELECT filters FROM notify_subscriptions WHERE device_id = ? AND profile = ?"
                " AND start_seq < ? AND expires_at > ? AND closed_at IS NULL",
                (device_id, profile, seq, now)).fetchall()
        return any(json.loads(row[0]).get(filter_name, False) for row in rows)
