"""Sealing, the relay client, and the durable outbox between them.

Sealing is byte-for-byte the ``push-v0`` envelope CozyChat's Notification Service Extension already
opens: HKDF-SHA256 over the phone's key material (empty salt, info ``cozygateway-push-v0``, 32
bytes) then AES-256-GCM, wire form ``base64url(nonce(12) || ciphertext || tag(16))`` with no
padding. ``tests/vectors.json`` pins both directions against the app's own bytes.

The outbox exists because the notify has to survive the two things that reliably go wrong on a
laptop: the relay rate-limiting a burst, and the machine sleeping mid-turn. A hook enqueues and
returns; one drain thread does the network.
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HKDF_INFO = b"cozygateway-push-v0"

# The relay allows 500 notifies per push id per day; past this the device gets one digest instead.
DAILY_DIGEST_THRESHOLD = 400
# One notify per (device, collapse id) inside this window; a later one replaces the pending payload.
COALESCE_SECONDS = 5.0
# The same idea for Lock Screen cards, which update far more often and are worth far less each.
LIVE_COALESCE_SECONDS = 2.0
RETENTION_SECONDS = 7 * 24 * 3600
_MAX_BACKOFF_SECONDS = 900.0


def seal(key: bytes, payload: Dict[str, Any]) -> str:
    """Seal one payload for a device. The nonce is fresh per call, as AES-GCM requires."""
    aes = AESGCM(HKDF(algorithm=SHA256(), length=32, salt=b"", info=HKDF_INFO).derive(key))
    nonce = os.urandom(12)
    plaintext = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    combined = nonce + aes.encrypt(nonce, plaintext, None)
    return base64.urlsafe_b64encode(combined).decode("ascii").rstrip("=")


def open_sealed(key: bytes, ciphertext: str) -> Dict[str, Any]:
    """Inverse of :func:`seal`. Only the tests use it; the phone is the real reader."""
    aes = AESGCM(HKDF(algorithm=SHA256(), length=32, salt=b"", info=HKDF_INFO).derive(key))
    raw = base64.urlsafe_b64decode(ciphertext + "=" * (-len(ciphertext) % 4))
    return json.loads(aes.decrypt(raw[:12], raw[12:], None))


# Named because the relay sits behind Cloudflare, whose Browser Integrity Check answers error 1010
# (a 403 with no origin log line) to urllib's default `Python-urllib/x.y` signature. A 403 is
# terminal for the outbox, so an unnamed client drops every push it queues.
USER_AGENT = "cozychat-hermes-plugin"


class Relay:
    """``POST <relay>/notify``. Registration is the phone's job, so this only ever sends."""

    def __init__(self, url: str, *, timeout: float = 15.0, opener=None,
                 allows: Optional[Callable[[str], bool]] = None,
                 allows_registration: Optional[Callable[[str], bool]] = None) -> None:
        self.base = url.rstrip("/")
        self.url = self.base + "/notify"
        self.timeout = timeout
        self._opener = opener or urllib.request.urlopen
        self._allows = allows
        self._allows_registration = allows_registration

    def notify(self, push_id: str, ciphertext: str, category: str, collapse_id: str,
               interruption_level: Optional[str] = None) -> Tuple[int, Optional[float]]:
        """``(status, retry_after)``. A transport failure is status 0, which the outbox retries."""
        if self._allows is not None and not self._allows(push_id):
            return 410, None
        body: Dict[str, Any] = {
            "pushId": push_id, "ciphertext": ciphertext,
            "category": category, "collapseId": collapse_id,
        }
        if interruption_level:
            body["interruptionLevel"] = interruption_level
        return self._post(self.url, body)[0]

    def notify_live_activity(self, push_id: str,
                             live_activity: Dict[str, Any]) -> Tuple[int, Optional[float]]:
        """One Lock Screen card update.

        The relay takes EXACTLY ONE of `ciphertext` and `liveActivity`, and refuses a category or an
        interruption level beside a card, so this body carries neither: the card is its own routing.
        """
        if self._allows is not None and not self._allows(push_id):
            return 410, None
        return self._post(self.url, {"pushId": push_id, "liveActivity": live_activity})[0]

    def register_live_activity(self, token: str, environment: str, device_id: str = "",
                               profile: str = "") -> Optional[str]:
        """Trade an ActivityKit push token for a relay push id, or nil when the relay refused."""
        if self._allows_registration is not None and not self._allows_registration(device_id, profile):
            return None
        (status, _), payload = self._post(
            self.base + "/register",
            {"platform": "apns-liveactivity", "token": token, "environment": environment})
        if not 200 <= status < 300:
            return None
        push_id = (payload or {}).get("pushId")
        return push_id if isinstance(push_id, str) and push_id else None

    def forget(self, push_id: str, relay_url: Optional[str] = None) -> int:
        """Release a relay registration. The caller retains a tombstone until this succeeds.

        ``relay_url`` is the relay the registration was made at, when that is not this one.
        """
        request = urllib.request.Request(
            (relay_url.rstrip("/") if relay_url else self.base) + "/register/" + urllib.parse.quote(push_id, safe=""), method="DELETE",
            headers={"User-Agent": USER_AGENT})
        try:
            with self._opener(request, timeout=self.timeout) as response:
                return int(response.status)
        except urllib.error.HTTPError as error:
            return int(error.code)
        except Exception:
            return 0

    def _post(self, url: str, body: Dict[str, Any]) -> Tuple[Tuple[int, Optional[float]],
                                                             Optional[Dict[str, Any]]]:
        """``((status, retry_after), decoded body)``. A transport failure is status 0, and retried."""
        request = urllib.request.Request(
            url, data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": USER_AGENT}, method="POST")
        try:
            with self._opener(request, timeout=self.timeout) as response:
                try:
                    payload = json.loads(response.read().decode("utf-8"))
                except Exception:
                    payload = None
                return (int(response.status), None), payload if isinstance(payload, dict) else None
        except urllib.error.HTTPError as error:
            return (int(error.code), _retry_after(error.headers.get("Retry-After"))), None
        except Exception:
            return (0, None), None


def _retry_after(value: Optional[str]) -> Optional[float]:
    try:
        return max(0.0, float(value))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


class Outbox:
    """Durable queue of payloads waiting for the relay, one SQLite file per profile."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._db: Optional[sqlite3.Connection] = None
        # activity_id -> when its last card update actually went out. In memory rather than on disk
        # because it exists only to space updates apart: a restart that forgets it lets ONE extra
        # update through, and the alternative is a table written several times a second.
        self._live_last_sent: Dict[str, float] = {}

    def close(self) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None

    def _connect(self) -> sqlite3.Connection:
        if self._db is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(self.path, check_same_thread=False, timeout=10.0)
            os.chmod(self.path, 0o600)
            self._db.executescript(
                "CREATE TABLE IF NOT EXISTS pending ("
                " id INTEGER PRIMARY KEY, device_id TEXT NOT NULL, category TEXT NOT NULL,"
                " collapse_id TEXT NOT NULL, payload TEXT NOT NULL, level TEXT,"
                " created_at REAL NOT NULL, send_after REAL NOT NULL, attempts INTEGER NOT NULL,"
                " profile TEXT NOT NULL DEFAULT '', consent_version INTEGER NOT NULL DEFAULT 0);"
                "CREATE TABLE IF NOT EXISTS sent ("
                " device_id TEXT NOT NULL, day TEXT NOT NULL, count INTEGER NOT NULL,"
                " digested INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (device_id, day));"
                # A table of its own rather than a column on `pending`: a card update is not sealed,
                # is addressed by activity rather than device, and keeps one row per card. An
                # upgrade over an existing outbox therefore needs no migration.
                "CREATE TABLE IF NOT EXISTS live_pending ("
                " activity_id TEXT PRIMARY KEY, push_id TEXT NOT NULL, body TEXT NOT NULL,"
                " terminal INTEGER NOT NULL, created_at REAL NOT NULL, send_after REAL NOT NULL,"
                " attempts INTEGER NOT NULL, device_id TEXT NOT NULL DEFAULT '',"
                " profile TEXT NOT NULL DEFAULT '', consent_version INTEGER NOT NULL DEFAULT 0);")
            pending_columns = {row[1] for row in self._db.execute("PRAGMA table_info(pending)")}
            if "profile" not in pending_columns:
                self._db.execute("ALTER TABLE pending ADD COLUMN profile TEXT NOT NULL DEFAULT ''")
            if "consent_version" not in pending_columns:
                self._db.execute("ALTER TABLE pending ADD COLUMN consent_version INTEGER NOT NULL DEFAULT 0")
            live_columns = {row[1] for row in self._db.execute("PRAGMA table_info(live_pending)")}
            if "device_id" not in live_columns:
                self._db.execute("ALTER TABLE live_pending ADD COLUMN device_id TEXT NOT NULL DEFAULT ''")
            if "profile" not in live_columns:
                self._db.execute("ALTER TABLE live_pending ADD COLUMN profile TEXT NOT NULL DEFAULT ''")
            if "consent_version" not in live_columns:
                self._db.execute("ALTER TABLE live_pending ADD COLUMN consent_version INTEGER NOT NULL DEFAULT 0")
            self._db.commit()
        return self._db

    def enqueue(self, device_id: str, category: str, collapse_id: str, payload: Dict[str, Any],
                *, level: Optional[str] = None, profile: str = "", consent_version: int = 0,
                now: Optional[float] = None) -> None:
        """Queue one notify, replacing a same-collapse payload queued inside the coalesce window."""
        now = time.time() if now is None else now
        db = self._connect()
        with db:
            row = db.execute(
                "SELECT id FROM pending WHERE device_id = ? AND collapse_id = ?"
                " AND created_at > ? ORDER BY id DESC LIMIT 1",
                (device_id, collapse_id, now - COALESCE_SECONDS)).fetchone()
            body = json.dumps(payload, separators=(",", ":"), sort_keys=True)
            if row:
                db.execute("UPDATE pending SET payload = ?, category = ?, level = ? WHERE id = ?",
                           (body, category, level, row[0]))
            else:
                db.execute(
                    "INSERT INTO pending (device_id, category, collapse_id, payload, level,"
                    " created_at, send_after, attempts, profile, consent_version)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)",
                    (device_id, category, collapse_id, body, level, now, now, profile, consent_version))

    def enqueue_live_activity(self, activity_id: str, push_id: str, body: Dict[str, Any], *,
                              device_id: str = "", profile: str = "", consent_version: int = 0,
                              terminal: bool = False, now: Optional[float] = None) -> None:
        """Queue one Lock Screen card update, at most one per card per ``LIVE_COALESCE_SECONDS``.

        A card has ONE pending row: a newer state replaces an older one that has not gone out yet,
        because nobody wants to watch a card catch up through states the run has already left. The
        terminal is the exception in both directions — it replaces whatever is pending AND it is due
        at once, so a finished run is never a card still saying "Thinking".
        """
        now = time.time() if now is None else now
        earliest = self._live_last_sent.get(activity_id, 0.0) + LIVE_COALESCE_SECONDS
        send_after = now if terminal else max(now, earliest)
        db = self._connect()
        with db:
            row = db.execute("SELECT send_after FROM live_pending WHERE activity_id = ?",
                             (activity_id,)).fetchone()
            payload = json.dumps(body, separators=(",", ":"), sort_keys=True)
            if row:
                db.execute(
                    "UPDATE live_pending SET push_id = ?, body = ?, terminal = ?, send_after = ?,"
                    " device_id = ?, profile = ?, consent_version = ? WHERE activity_id = ?",
                    (push_id, payload, int(terminal), min(float(row[0]), send_after), device_id,
                     profile, consent_version, activity_id))
            else:
                db.execute(
                    "INSERT INTO live_pending (activity_id, push_id, body, terminal, created_at,"
                    " send_after, attempts, device_id, profile, consent_version)"
                    " VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)",
                    (activity_id, push_id, payload, int(terminal), now, send_after, device_id,
                     profile, consent_version))

    def _drain_live(self, relay: Relay, store, now: float) -> int:
        """Send every card update that is due. Returns how many the relay accepted."""
        db = self._connect()
        self._write("DELETE FROM live_pending WHERE created_at < ?", (now - RETENTION_SECONDS,))
        sent = 0
        rows = db.execute(
            "SELECT activity_id, push_id, body, attempts, device_id, profile, consent_version"
            " FROM live_pending WHERE send_after <= ?"
            " ORDER BY created_at", (now,)).fetchall()
        for activity_id, push_id, body, attempts, device_id, profile, consent_version in rows:
            device = next((candidate for candidate in store.list()
                           if candidate["device_id"] == device_id
                           and candidate.get("profile") == profile
                           and int(candidate.get("consent_version") or 0) == 1), None)
            authority = getattr(self, "live_authority", None)
            if (consent_version != 1 or not device_id or not profile or device is None
                    or authority is None or not authority(activity_id, push_id, device_id, profile)):
                self._write("DELETE FROM live_pending WHERE activity_id = ?", (activity_id,))
                continue
            status, retry_after = relay.notify_live_activity(push_id, json.loads(body))
            if status in (0, 429) or status >= 500:
                self._write("UPDATE live_pending SET attempts = attempts + 1, send_after = ?"
                            " WHERE activity_id = ? AND push_id = ? AND body = ?",
                            (now + _backoff(attempts, retry_after), activity_id, push_id, body))
                continue
            # A hook may replace this state while the relay call is in flight, including with
            # the terminal update. Only retire the registration and body we actually sent.
            self._write("DELETE FROM live_pending WHERE activity_id = ? AND push_id = ? AND body = ?",
                        (activity_id, push_id, body))
            if 200 <= status < 300:
                self._live_last_sent[activity_id] = now
                sent += 1
        return sent

    def drain(self, relay: Relay, store, now: Optional[float] = None) -> int:
        """Send everything that is due. Returns how many notifies the relay accepted."""
        if not self.path.exists():
            return 0
        now = time.time() if now is None else now
        db = self._connect()
        self._write("DELETE FROM pending WHERE created_at < ?", (now - RETENTION_SECONDS,))
        devices = store.list()
        sent = 0
        rows = db.execute(
            "SELECT id, device_id, category, collapse_id, payload, level, attempts, profile,"
            " consent_version FROM pending"
            " WHERE send_after <= ? ORDER BY id", (now,)).fetchall()
        for row_id, device_id, category, collapse_id, payload, level, attempts, profile, consent_version in rows:
            device = next((candidate for candidate in devices if candidate["device_id"] == device_id
                           and candidate.get("profile") == profile
                           and int(candidate.get("consent_version") or 0) == 1), None)
            if device is None or consent_version != 1:  # unpaired or pre-consent queued work
                self._delete(row_id, payload)
                continue
            body, category, collapse_id = self._apply_daily_cap(
                device_id, json.loads(payload), category, collapse_id, now)
            if body is None:
                self._delete(row_id, payload)
                continue
            status, retry_after = relay.notify(
                device["push_id"], seal(store.key_for(device_id, profile), body), category, collapse_id, level)
            if status in (0, 429) or status >= 500:
                self._write(
                    "UPDATE pending SET attempts = attempts + 1, send_after = ? WHERE id = ?",
                    (now + _backoff(attempts, retry_after), row_id))
                continue
            self._delete(row_id, payload)
            if 200 <= status < 300:
                self._count(device_id, now)
                if collapse_id == f"digest:{_day(now)}":
                    self._write("UPDATE sent SET digested = 1 WHERE device_id = ? AND day = ?",
                                (device_id, _day(now)))
                sent += 1
        # The card lane shares the thread and the retention, not the sealing or the daily cap: a
        # Lock Screen card carries no content to seal and expires on its own within the hour.
        return sent + self._drain_live(relay, store, now)

    def discard_device(self, device_id: str, activity_ids=(), profile: Optional[str] = None) -> None:
        if not self.path.exists():
            return
        if profile is None:
            self._write("DELETE FROM pending WHERE device_id = ?", (device_id,))
        else:
            self._write("DELETE FROM pending WHERE device_id = ? AND profile = ?", (device_id, profile))
        for activity_id in activity_ids:
            self._write("DELETE FROM live_pending WHERE activity_id = ?", (activity_id,))

    # -- row bookkeeping --------------------------------------------------

    def _write(self, sql: str, args: tuple) -> None:
        db = self._connect()
        with db:
            db.execute(sql, args)

    def _delete(self, row_id: int, payload: str) -> None:
        """Delete the row ONLY if it still holds the payload that was just sent.

        A hook thread can coalesce a newer payload into a row while the drain thread is inside
        `relay.notify` for it, and an unguarded delete by id then throws that newer payload away —
        an approval's `resolved` push lost under its own `pending`. Guarded, the rewritten row
        survives and goes out on the next drain.
        """
        self._write("DELETE FROM pending WHERE id = ? AND payload = ?", (row_id, payload))

    def _apply_daily_cap(self, device_id: str, payload: Dict[str, Any], category: str,
                         collapse_id: str, now: float):
        """Past the daily threshold a device gets one digest for the rest of the day, then silence."""
        day = _day(now)
        row = self._connect().execute(
            "SELECT count, digested FROM sent WHERE device_id = ? AND day = ?",
            (device_id, day)).fetchone()
        count, digested = (row or (0, 0))
        if count < DAILY_DIGEST_THRESHOLD:
            return payload, category, collapse_id
        if digested:
            return None, category, collapse_id
        digest = {"kind": "message", "threadId": payload.get("threadId", ""),
                  "agentName": payload.get("agentName", ""),
                  "preview": "More activity than notifications can carry today."}
        return digest, "message", f"digest:{day}"

    def _count(self, device_id: str, now: float) -> None:
        self._write("INSERT INTO sent (device_id, day, count) VALUES (?, ?, 1)"
                    " ON CONFLICT (device_id, day) DO UPDATE SET count = count + 1",
                    (device_id, _day(now)))


def _backoff(attempts: int, retry_after: Optional[float]) -> float:
    """Exponential backoff, never shorter than the relay's own Retry-After."""
    delay = min(2.0 ** min(attempts, 10), _MAX_BACKOFF_SECONDS)
    return delay if retry_after is None else max(delay, retry_after)


def _day(now: float) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(now))
