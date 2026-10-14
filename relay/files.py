"""Bounded file transfers inside the authenticated tunnel.

OPEN carries ``op`` plus ``path`` (stat/read_range) or ``name``, ``size`` and ``sha256`` (put).
Replies start with one JSON line. A read_range then sends exactly ``size`` raw bytes; a put
answers ``ready`` before accepting exactly the declared bytes, then a receipt and normal CLOSE.
Policy refusals use stream code 3, I/O failures code 2. No path or OS error leaks in a refusal.
"""

from __future__ import annotations

import asyncio
import errno
import hashlib
import json
import os
import re
import stat
import sys
import threading
import time
import unicodedata
import uuid
from contextlib import nullcontext
from datetime import date
from pathlib import Path, PurePath
from typing import Any, Dict, Optional

from ..state import state_root
from .framing import MAX_DATA
from .mux import Stream, StreamClose

MAX_BYTES = 100 * 1024 * 1024
WINDOW_LIMIT = 4 * 1024 * 1024

# Secondary guards shared with TunnelFilePolicy (also used by SSH and Dashboard).
DENIED_TREES = ("/etc", "/proc", "/sys", "/dev", "/root", "/boot", "/var/log",
                "/var/lib", "/var/run")
# Mirrors upstream Hermes `_MEDIA_DELIVERY_CACHE_SUBDIRS` (gateway/platforms/base.py) with
# `GENERATED_SUBDIR = "generated"` (agent/provider_media.py): the media Hermes itself delivers.
MEDIA_CACHE_SUBDIRS = ("images", "audio", "videos", "documents", "screenshots", "generated")
# Default personal-media read roots under the user's home (those that exist).
USER_MEDIA_DIRECTORIES = ("Desktop", "Documents", "Downloads", "Pictures", "Movies", "Music")
DENIED_DIRECTORIES = frozenset((
    ".ssh", ".aws", ".gnupg", ".kube", ".docker", ".config", ".azure", ".gcloud", "keychains",
    "mcp-tokens", "pairing", "browser-profile", "vault", "sessions"))
# SSH key files need no name entry: credential_path refuses every path with a dot-component
# (``~/.ssh``), and the system-wide key locations sit under the denied ``/etc`` tree.
DENIED_NAMES = frozenset((
    ".anthropic_oauth.json", ".envrc", ".git-credentials", "auth.json", "auth.lock",
    "bws_cache.enc.json", "bws_cache.json", "config.yaml", "credentials",
    "google_oauth.json", "google_oauth_pending.json", "google_token.json", "kanban.db",
    "known_hosts", "state.db", "webhook_subscriptions.json"))
DENIED_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".keychain", ".keychain-db")


class FilePolicyError(ValueError):
    pass


def normalized_name(value: str) -> str:
    return unicodedata.normalize("NFD", unicodedata.normalize("NFKC", value).casefold())


def credential_path(path: str, trees: bool = True) -> bool:
    text = normalized_name(path)
    parts = [p for p in re.split(r"[/\\]+", text) if p]
    if text.startswith("/private/"):
        parts = parts[1:]
    if not parts:
        return False
    normalized = "/" + "/".join(parts)
    if trees and text.startswith("/") and any(normalized == p or normalized.startswith(p + "/")
                                    for p in DENIED_TREES):
        return True
    if any(p.startswith(".") for p in parts) or DENIED_DIRECTORIES.intersection(parts):
        return True
    name = parts[-1]
    for suffix in ("-wal", "-shm", "-journal"):
        if name.endswith(suffix):
            name = name[:-len(suffix)]
            break
    return (name in DENIED_NAMES or name.startswith("id_") or name.endswith(DENIED_SUFFIXES))


def _safe(path: PurePath) -> None:
    text = str(path)
    if (credential_path(text) or (bool(path.drive) and ":" in text[len(path.drive):])
            or text.startswith("\\\\")):
        raise FilePolicyError("credential_denied")


def platform_supported(platform: Optional[str] = None) -> bool:
    # Native Windows needs a reparse-safe handle walk; don't advertise weaker pathname I/O.
    return (sys.platform if platform is None else platform) != "win32"


def _parts(path: Path) -> tuple:
    parts = tuple(normalized_name(p) for p in path.parts)
    # Darwin's /tmp and /var are trusted system aliases, not phone-selected symlinks.
    if sys.platform == "darwin" and len(parts) > 2 and parts[1] == "private" and parts[2] in ("tmp", "var"):
        parts = (parts[0],) + parts[2:]
    return parts


def _under(path: Path, root: Path) -> bool:
    parts, prefix = _parts(path), _parts(root)
    return parts[:len(prefix)] == prefix


def _directory(path: Path) -> int:
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _integer(args: Dict[str, Any], name: str, minimum: int, maximum: int) -> int:
    value = args.get(name)
    if type(value) is not int or not minimum <= value <= maximum:
        raise FilePolicyError("bad_request")
    return value


def _identity(info: os.stat_result) -> tuple:
    return info.st_dev, info.st_ino


async def _finish(task):
    cancelled = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            cancelled = True
        except BaseException:
            break
    return task.result(), cancelled


async def _disk(function, *args, cleanup=None, **kwargs):
    # A cancelled to_thread keeps running. Retain ownership through any number of cancels.
    task = asyncio.create_task(asyncio.to_thread(function, *args, **kwargs))
    result, cancelled = await _finish(task)
    if cancelled:
        if cleanup is not None:
            await _finish(asyncio.create_task(asyncio.to_thread(cleanup, result)))
        raise asyncio.CancelledError
    return result


class Upload:
    def __init__(self, handle, directory: int, inbox: int, home: int,
                 temporary: str, final: str, path: Path):
        self.handle, self.directory, self.inbox, self.home = handle, directory, inbox, home
        self.temporary, self.final, self.path = temporary, final, path
        self.committed = False

    def discard(self) -> None:
        try:
            try:
                self.handle.close()
            finally:
                # The temporary is removed even when close() raises (for instance on a full disk).
                if not self.committed:
                    try:
                        os.unlink(self.temporary, dir_fd=self.directory)
                    except FileNotFoundError:
                        pass
        finally:
            os.close(self.directory)
            os.close(self.inbox)
            os.close(self.home)

    def check_directory(self) -> None:
        for parent, name, child in ((self.home, "cozychat-inbox", self.inbox),
                                    (self.inbox, self.path.parent.name, self.directory)):
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if _identity(current) != _identity(os.fstat(child)):
                raise FilePolicyError("path_changed")


INBOX_QUOTA = 1024 * 1024 * 1024
FREE_SPACE_FLOOR = 512 * 1024 * 1024
CONCURRENT_BYTES = 2 * MAX_BYTES
PHONE_BYTES = MAX_BYTES
OPERATION_SECONDS = 60.0
UPLOAD_SECONDS = 300.0


MAX_INBOX_FILES = 10_000
BLOCK_BYTES = 4096
RECONCILE_SECONDS = 60.0
ORPHAN_SECONDS = 3600.0


def _charge(size: int, blocks: Optional[int] = None) -> int:
    """Bytes charged to the quota: allocated blocks when known, else size rounded up to a block;
    never less than one 4 KiB block per file, so sparse and empty files still cost."""
    allocated = blocks * 512 if blocks is not None else -(-max(size, 0) // BLOCK_BYTES) * BLOCK_BYTES
    return max(allocated, BLOCK_BYTES)


class Reservations:
    def __init__(self):
        self.lock = threading.Lock()
        self.bytes = 0
        self.files = 0
        self.phones = {}
        self.operations = 0
        # Incremental inbox usage; a full scan only reconciles it every RECONCILE_SECONDS.
        self.used_bytes = 0
        self.used_files = 0
        self.scanned_at = None
        self.scans = 0

    def release(self, phone: bytes, count: int) -> None:
        with self.lock:
            held, operations = self.phones[phone]
            self.bytes -= count
            if count:
                self.files -= 1
            self.operations -= 1
            if operations == 1:
                del self.phones[phone]
            else:
                self.phones[phone] = (held - count, operations - 1)

    def committed(self, charged: int) -> None:
        with self.lock:
            self.used_bytes += charged
            self.used_files += 1


_RESERVATIONS = {}
_RESERVATIONS_LOCK = threading.Lock()


def _usage(fd: int, sweep: bool = True) -> tuple:
    """(allocated bytes, file count) beneath ``fd``; unlinks `.upload-*` orphans past an hour."""
    total = files = 0
    cutoff = time.time() - ORPHAN_SECONDS
    with os.scandir(fd) as entries:
        for entry in entries:
            info = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    more, count = _usage(child, sweep)
                finally:
                    os.close(child)
                total += more
                files += count
            elif stat.S_ISREG(info.st_mode):
                if sweep and entry.name.startswith(".upload-") and info.st_mtime < cutoff:
                    try:
                        os.unlink(entry.name, dir_fd=fd)
                    except FileNotFoundError:
                        pass
                    continue
                total += _charge(info.st_size, info.st_blocks)
                files += 1
    return total, files


class FileService:
    def __init__(self, home: Path, *, user_home: Optional[Path] = None,
                 allowed_roots=None, workspace: Optional[Path] = None,
                 plugin_state: Optional[Path] = None, quota: int = INBOX_QUOTA,
                 free_floor: int = FREE_SPACE_FLOOR, concurrent_bytes: int = CONCURRENT_BYTES,
                 phone_bytes: int = PHONE_BYTES, operation_seconds: float = OPERATION_SECONDS,
                 upload_seconds: float = UPLOAD_SECONDS) -> None:
        # Only trusted host configuration is canonicalized, never a phone's pathname.
        self.home = Path(home).resolve()
        self.user_home = (Path.home() if user_home is None else Path(user_home)).resolve()
        self.inbox_home = state_root(self.home).parent.resolve()
        self.inbox = self.inbox_home / "cozychat-inbox"
        self.protected = tuple(sorted({self.inbox_home, state_root(self.home).resolve(),
            Path(plugin_state).resolve() if plugin_state is not None else state_root(self.home).resolve()},
            key=str))
        if allowed_roots is None:
            roots = [self.user_home / name for name in USER_MEDIA_DIRECTORIES
                     if (self.user_home / name).is_dir()]
        else:
            roots = [Path(p) for p in allowed_roots]
        if workspace is not None:
            roots.append(Path(workspace))
        # Hermes' own media delivery cache, beneath the otherwise private Hermes home. Everything
        # else there stays denied; the hidden/credential/link checks still run beneath each root.
        self.cache_roots = tuple(sorted({base.resolve() / "cache" / sub
                                         for base in (self.inbox_home, self.home)
                                         for sub in MEDIA_CACHE_SUBDIRS}, key=str))
        self.exempt = (self.inbox,) + self.cache_roots
        configured = {Path(p).resolve() for p in roots}
        # A configured root cannot re-open private Hermes/plugin state; only inbox and cache can.
        configured = {p for p in configured
                      if not any(_under(p, t) for t in self.protected)}
        self.roots = sorted(configured | {self.inbox} | set(self.cache_roots),
                            key=lambda p: len(p.parts), reverse=True)
        self.quota, self.free_floor = quota, free_floor
        self.concurrent_bytes, self.phone_bytes = concurrent_bytes, phone_bytes
        self.operation_seconds, self.upload_seconds = operation_seconds, upload_seconds
        self.reconcile_seconds = RECONCILE_SECONDS
        with _RESERVATIONS_LOCK:
            self.reservations = _RESERVATIONS.setdefault(_parts(self.inbox), Reservations())

    def capabilities(self) -> Optional[Dict[str, Any]]:
        if not platform_supported() or not self.home.is_dir():
            return None
        return {"put": os.access(self.inbox_home, os.W_OK | os.X_OK), "read_range": True,
                "max_bytes": MAX_BYTES, "user_home": str(self.user_home),
                "read_roots": [str(p) for p in self.roots],
                "denied_roots": [str(p) for p in self.protected], "inbox": str(self.inbox)}

    def _path(self, value: Any):
        if not isinstance(value, str) or not value or "\0" in value or len(value.encode("utf-8")) > 4096:
            raise FilePolicyError("bad_request")
        path = self.user_home / value[2:] if value.startswith("~/") else Path(value)
        if not path.is_absolute():
            raise FilePolicyError("bad_request")
        if any(normalized_name(p) in (".", "..") for p in re.split(r"[/\\]+", value)):
            raise FilePolicyError("credential_denied")
        if (not any(_under(path, e) for e in self.exempt)
                and any(_under(path, p) for p in self.protected)):
            raise FilePolicyError("credential_denied")
        root = next((p for p in self.roots if _under(path, p)), None)
        if root is None:
            raise FilePolicyError("outside_roots")
        relative = path.parts[len(path.parts) - (len(_parts(path)) - len(_parts(root))):]
        if not relative:
            raise FilePolicyError("not_regular")
        _safe(Path(*relative))
        # Deny-trees (/root, /var/lib ...) apply outside the allowed roots only, so a user home in
        # one of them still works. Hidden and credential names are checked beneath the root.
        return root, relative

    def _open(self, value: Any):
        root, parts = self._path(value)
        fd = _directory(root)
        try:
            for component in parts[:-1]:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                info = os.fstat(leaf)
                if not stat.S_ISREG(info.st_mode):
                    raise FilePolicyError("not_regular")
                if info.st_nlink != 1:
                    raise FilePolicyError("hardlink_denied")
                return os.fdopen(leaf, "rb"), info.st_size
            except BaseException:
                os.close(leaf)
                raise
        finally:
            os.close(fd)

    def _inbox_at(self, fd: int) -> int:
        try:
            os.mkdir("cozychat-inbox", mode=0o700, dir_fd=fd)
        except FileExistsError:
            pass
        return os.open("cozychat-inbox", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)

    def _inbox(self) -> int:
        fd = _directory(self.inbox_home)
        try:
            return self._inbox_at(fd)
        finally:
            os.close(fd)

    def _reserve(self, phone: bytes, count: int) -> None:
        budget = self.reservations
        with budget.lock:
            held, operations = budget.phones.get(phone, (0, 0))
            if (held + count > self.phone_bytes or budget.bytes + count > self.concurrent_bytes
                    or operations >= 4 or budget.operations >= 16):
                raise FilePolicyError("busy")
            if count:
                fd = self._inbox()
                try:
                    now = time.monotonic()
                    if budget.scanned_at is None or now - budget.scanned_at >= self.reconcile_seconds:
                        budget.used_bytes, budget.used_files = _usage(fd)
                        budget.scanned_at = now
                        budget.scans += 1
                    space = os.fstatvfs(fd)
                    free = space.f_bavail * space.f_frsize
                    if budget.used_files + budget.files + 1 > MAX_INBOX_FILES:
                        raise FilePolicyError("inbox_files")
                    if budget.used_bytes + budget.bytes + _charge(count) > self.quota:
                        raise FilePolicyError("inbox_quota")
                    if free - budget.bytes - count < self.free_floor:
                        raise FilePolicyError("free_space")
                finally:
                    os.close(fd)
                budget.files += 1
            budget.bytes += count
            budget.operations += 1
            budget.phones[phone] = (held + count, operations + 1)

    def _upload(self, name: Any):
        if (not isinstance(name, str) or not name or name in (".", "..") or
                any(c in name for c in ("/", "\\", "\0", ":")) or len(name.encode("utf-8")) > 255):
            raise FilePolicyError("bad_request")
        if credential_path(name):
            raise FilePolicyError("credential_denied")
        kept = "".join(c for c in name if c.isalnum() or c in ".-_ ").strip()[-80:]
        while len(kept.encode("utf-8")) > 180:
            kept = kept[1:]
        home = _directory(self.inbox_home)
        inbox = None
        directory = None
        try:
            inbox = self._inbox_at(home)
            day = date.today().isoformat()
            try:
                os.mkdir(day, mode=0o700, dir_fd=inbox)
            except FileExistsError:
                pass
            directory = os.open(day, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=inbox)
            temporary = ".upload-" + uuid.uuid4().hex
            final = str(uuid.uuid4()) + "-" + (kept or "attachment")
            leaf = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                           0o600, dir_fd=directory)
            try:
                handle = os.fdopen(leaf, "wb")
            except BaseException:
                os.close(leaf)
                os.unlink(temporary, dir_fd=directory)
                raise
            return Upload(handle, directory, inbox, home, temporary, final, self.inbox / day / final)
        except BaseException:
            if directory is not None:
                os.close(directory)
            if inbox is not None:
                os.close(inbox)
            os.close(home)
            raise

    async def serve(self, stream: Stream, phone: bytes = b"", publication_guard=None) -> None:
        operation = asyncio.create_task(self._operation(stream, phone, publication_guard))
        try:
            seconds = self.upload_seconds if stream.args.get("op") == "put" else self.operation_seconds
            try:
                await asyncio.wait_for(asyncio.shield(operation), seconds)
            except BaseException:
                operation.cancel()
                try:
                    await _finish(operation)
                except BaseException:
                    pass
                raise
        except FilePolicyError as exc:
            await stream.close(StreamClose.POLICY, str(exc))
        except OSError as exc:
            code = StreamClose.POLICY if exc.errno in (errno.ELOOP, errno.ENOTDIR) else StreamClose.UNREACHABLE
            await stream.close(code)
        except (RuntimeError, asyncio.TimeoutError):
            await stream.close(StreamClose.UNREACHABLE)

    async def _operation(self, stream: Stream, phone: bytes, publication_guard) -> None:
        reserved = False
        count = 0
        try:
            if not platform_supported():
                raise FilePolicyError("unsupported_platform")
            op = stream.args.get("op")
            if op == "put":
                count = _integer(stream.args, "size", 1, MAX_BYTES)
            await _disk(self._reserve, phone, count,
                        cleanup=lambda _: self.reservations.release(phone, count))
            reserved = True
            if op == "put":
                await self._put(stream, publication_guard)
            else:
                await self._read(stream, op)
        finally:
            if reserved:
                self.reservations.release(phone, count)

    async def _read(self, stream: Stream, op: str) -> None:
        if op not in ("stat", "read_range"):
            raise FilePolicyError("bad_request")
        offset, length = 0, 0
        if op == "read_range":
            offset = _integer(stream.args, "offset", 0, 2**63 - 1)
            length = _integer(stream.args, "length", 1, WINDOW_LIMIT)
        handle, total = await _disk(self._open, stream.args.get("path"), cleanup=lambda opened: opened[0].close())
        try:
            count = min(length, max(0, total - offset))
            await stream.write(_line({"ok": True, "size": total if op == "stat" else count,
                                      "total_size": total}))
            if op == "stat":
                return
            await _disk(handle.seek, offset)
            while count:
                chunk = await _disk(handle.read, min(count, MAX_DATA))
                if not chunk:
                    raise OSError("file shortened")
                count -= len(chunk)
                await stream.write(chunk)
        finally:
            await _disk(handle.close)

    async def _put(self, stream: Stream, publication_guard=None) -> None:
        count = _integer(stream.args, "size", 1, MAX_BYTES)
        digest = stream.args.get("sha256")
        if not isinstance(digest, str) or not re.fullmatch("[0-9a-f]{64}", digest):
            raise FilePolicyError("bad_request")
        upload = await _disk(self._upload, stream.args.get("name"), cleanup=lambda u: u.discard())
        try:
            await stream.write(_line({"ready": True}))
            received = 0
            hasher = hashlib.sha256()
            while received < count:
                chunk = await stream.read()
                if not chunk or received + len(chunk) > count:
                    raise FilePolicyError("size_mismatch")
                await _disk(upload.handle.write, chunk)
                hasher.update(chunk)
                received += len(chunk)
            if hasher.hexdigest() != digest:
                raise FilePolicyError("hash_mismatch")
            await _disk(upload.handle.flush)
            await _disk(os.fsync, upload.handle.fileno())
            # No await between the close/revocation check and rename/result reconciliation.
            # These bounded metadata calls linearize publication on the mux's event loop.
            with publication_guard() if publication_guard is not None else nullcontext(True) as approved:
                if not approved:
                    raise FilePolicyError("revoked")
                if (getattr(stream, "closed", False) or
                        getattr(getattr(stream, "mux", None), "_closing", False) or
                        getattr(asyncio.current_task(), "cancelling", lambda: 0)()):
                    raise asyncio.CancelledError
                self._commit(upload, count)
            await stream.write(_line({"ok": True, "path": str(upload.path), "size": count, "sha256": digest}))
        finally:
            await _disk(upload.discard)

    def _commit(self, upload: Upload, count: int) -> None:
        upload.check_directory()
        info = os.fstat(upload.handle.fileno())
        current = os.stat(upload.temporary, dir_fd=upload.directory, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != count
                or _identity(current) != _identity(info)):
            raise FilePolicyError("path_changed")
        os.rename(upload.temporary, upload.final, src_dir_fd=upload.directory, dst_dir_fd=upload.directory)
        try:
            published = os.stat(upload.final, dir_fd=upload.directory, follow_symlinks=False)
            upload.check_directory()
            if (_identity(published) != _identity(info) or published.st_nlink != 1
                    or published.st_size != count):
                raise FilePolicyError("path_changed")
        except BaseException:
            try:
                os.unlink(upload.final, dir_fd=upload.directory)
            except FileNotFoundError:
                pass
            raise
        upload.committed = True
        self.reservations.committed(_charge(count, published.st_blocks))


def _line(value: Dict[str, Any]) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8") + b"\n"
