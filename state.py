"""One directory every process of this Hermes can see, and the SQLite file inside it.

WHY THIS EXISTS. The plugin is loaded twice. Its hooks run inside ``hermes gateway`` — one process
per profile — and its HTTP routes are served by ``hermes serve``, a different process that loads its
own copy from its own profile's plugins directory. Anything the hooks write in memory is invisible
to the routes, which is what the 2026-09-15 run measured: a feed held open across a whole turn
produced nothing, an approval genuinely waiting answered the phone ``no open approval with that id``.
The cure is not a shared process; it is shared state.

WHY THE ROOT HOME AND NOT THE PROFILE. The two processes are not merely different processes, they
are usually different PROFILES: ``hermes serve`` attaches to one machine-level server that runs
``-p default`` unless ``--isolated``. A per-profile directory would therefore still be two
directories. ``get_hermes_home()`` answers ``<root>/profiles/<name>`` in a profile and ``<root>``
otherwise, so stripping ``profiles/<name>`` gives the one path both agree on, and
``<root>/cozychat/`` is it. A second Hermes home (a different ``HERMES_HOME``) is a different
computer as far as this plugin is concerned and correctly gets its own directory.

WHAT IS IN HERE AND WHAT IS BESIDE IT. ``state.sqlite`` holds the three things the two processes
have to agree about: the frames of the live feed, the open approvals and their decisions, and the
Lock Screen cards a phone has registered. ``outbox.sqlite`` keeps its own file in the same
directory — it is written several times a second by the drain thread and read by nobody else, so
sharing a WAL with a route that polls every 100 ms would buy nothing. ``devices.json`` and
``keys/`` move here as files, unchanged: the key material is deliberately not in a database.

ponytail: 0700 on the directory, not 0600. A directory with no execute bit cannot be traversed, so
0600 would lock the plugin out of its own state; 0700 is the same privacy for a thing that must be
entered. Files inside are 0600.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

logger = logging.getLogger("hermes_cli.plugins.cozychat")

# What ``/info`` reports and what CozyChat checks before it offers the feed, the phone-answered
# approval or the Lock Screen card. An older plugin answers no ``state`` at all and stays gated.
STATE_VERSION = "shared-v1"

# Frames kept behind the newest one. A long room round at delta granularity, same as the ring was.
FRAME_CAPACITY = 5000
# Pruning every append would be a DELETE per delta; this lets the table overshoot by at most this.
_PRUNE_EVERY = 100
# A feed whose newest frame is older than this is not being written by anybody.
FRESH_SECONDS = 600.0

_SCHEMA = (
    # AUTOINCREMENT, not `INTEGER PRIMARY KEY`: the seq has to keep rising after the prune deletes
    # the oldest rows, because a phone reconnects with the last seq it saw and a reused number
    # would replay as if nothing had happened.
    "CREATE TABLE IF NOT EXISTS frames ("
    " seq INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL, body TEXT NOT NULL);"
    # One row per open transport request. The waiter (gateway) inserts and deletes; the route
    # (serve) only ever writes `choice`, so the two never contend for the same column.
    "CREATE TABLE IF NOT EXISTS approvals ("
    " request_id TEXT PRIMARY KEY, opened_at REAL NOT NULL, expires_at REAL NOT NULL,"
    " card TEXT NOT NULL, choice TEXT);"
    # Registered by the route, read by every hook. The push id, never the ActivityKit token.
    "CREATE TABLE IF NOT EXISTS activities ("
    " activity_id TEXT PRIMARY KEY, push_id TEXT NOT NULL, environment TEXT NOT NULL,"
    " session_id TEXT NOT NULL, created_at REAL NOT NULL, device_id TEXT NOT NULL DEFAULT '',"
    " profile TEXT NOT NULL DEFAULT '', consent_version INTEGER NOT NULL DEFAULT 0);"
    "CREATE TABLE IF NOT EXISTS push_tombstones ("
    " push_id TEXT PRIMARY KEY, created_at REAL NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,"
    " retry_after REAL NOT NULL, device_id TEXT NOT NULL DEFAULT '', profile TEXT NOT NULL DEFAULT '',"
    " relay_url TEXT NOT NULL DEFAULT '');"
    "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);"
    "CREATE TABLE IF NOT EXISTS notify_subscriptions ("
    " subscription_id TEXT NOT NULL, device_id TEXT NOT NULL, profile TEXT NOT NULL,"
    " filters TEXT NOT NULL, start_seq INTEGER NOT NULL, expires_at REAL NOT NULL, closed_at REAL,"
    " PRIMARY KEY(subscription_id, device_id, profile));"
    "CREATE TABLE IF NOT EXISTS notify_pending ("
    " event_id TEXT NOT NULL, device_id TEXT NOT NULL, subscription_id TEXT NOT NULL,"
    " category TEXT NOT NULL, collapse_id TEXT NOT NULL, payload TEXT NOT NULL, level TEXT,"
    " deadline REAL NOT NULL, PRIMARY KEY(event_id, device_id));"
)


def state_root(home: Optional[Path] = None) -> Path:
    """``<root>/cozychat`` for this Hermes, whichever profile is asking."""
    return _hermes_root(home) / "cozychat"


def _hermes_root(home: Optional[Path] = None) -> Path:
    """The Hermes home with ``profiles/<name>`` stripped.

    Computed here rather than taken from ``hermes_constants.get_default_hermes_root``, which answers
    the NATIVE default whenever ``HERMES_HOME`` points inside it — true of every profile — and so
    cannot be exercised by a test that sets ``HERMES_HOME`` to a scratch directory.
    """
    if home is None:
        home = hermes_home()
    home = Path(home)
    return home.parent.parent if home.parent.name == "profiles" else home


def hermes_home() -> Path:
    """This process's Hermes home, profile and all. The identity of the process's configuration."""
    try:
        from hermes_constants import get_hermes_home

        return Path(get_hermes_home())
    except Exception:
        return Path(os.environ.get("HERMES_HOME") or (Path.home() / ".hermes"))


class SharedState:
    """The one SQLite file, and the directory it lives in."""

    def __init__(self, root: Path, *, capacity: int = FRAME_CAPACITY,
                 prune_every: int = _PRUNE_EVERY) -> None:
        self.root = Path(root)
        self.path = self.root / "state.sqlite"
        self.capacity = int(capacity)
        self._prune_every = int(prune_every)
        self._lock = threading.Lock()
        self._db: Optional[sqlite3.Connection] = None
        self._appends = 0
        self._noted_pid: Optional[int] = None

    # -- the connection ---------------------------------------------------

    @contextmanager
    def write(self) -> Iterator[sqlite3.Connection]:
        """A transaction. Serialised in this process; WAL handles the other one."""
        with self._lock:
            db = self._connect()
            with db:
                yield db

    @contextmanager
    def read(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            yield self._connect()

    def close(self) -> None:
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None

    def _connect(self) -> sqlite3.Connection:
        if self._db is None:
            self.root.mkdir(parents=True, exist_ok=True)
            os.chmod(self.root, 0o700)
            db = sqlite3.connect(self.path, check_same_thread=False, timeout=10.0)
            os.chmod(self.path, 0o600)
            # WAL so the route's poll never blocks the hook's append, and a 10 s busy timeout so a
            # writer that does block waits rather than raising into a turn.
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA busy_timeout=10000")
            db.execute("PRAGMA synchronous=NORMAL")
            db.executescript(_SCHEMA)
            db.execute("BEGIN IMMEDIATE")
            if "device_id" not in {row[1] for row in db.execute("PRAGMA table_info(activities)")}:
                db.execute("ALTER TABLE activities ADD COLUMN device_id TEXT NOT NULL DEFAULT ''")
            columns = {row[1] for row in db.execute("PRAGMA table_info(activities)")}
            if "profile" not in columns:
                db.execute("ALTER TABLE activities ADD COLUMN profile TEXT NOT NULL DEFAULT ''")
            if "consent_version" not in columns:
                db.execute("ALTER TABLE activities ADD COLUMN consent_version INTEGER NOT NULL DEFAULT 0")
            tombstone_columns = {row[1] for row in db.execute("PRAGMA table_info(push_tombstones)")}
            if "device_id" not in tombstone_columns:
                db.execute("ALTER TABLE push_tombstones ADD COLUMN device_id TEXT NOT NULL DEFAULT ''")
            if "profile" not in tombstone_columns:
                db.execute("ALTER TABLE push_tombstones ADD COLUMN profile TEXT NOT NULL DEFAULT ''")
            if "relay_url" not in tombstone_columns:
                db.execute("ALTER TABLE push_tombstones ADD COLUMN relay_url TEXT NOT NULL DEFAULT ''")
            db.commit()
            self._db = db
        return self._db

    # -- frames -----------------------------------------------------------

    def append_frame(self, at: float, body: str) -> int:
        """Keep one frame and return the seq it was stamped with."""
        self._note_writer_once()
        with self.write() as db:
            seq = int(db.execute("INSERT INTO frames (at, body) VALUES (?, ?)",
                                 (at, body)).lastrowid)
            self._appends += 1
            if self._appends >= self._prune_every:
                self._appends = 0
                db.execute("DELETE FROM frames WHERE seq <= ?", (seq - self.capacity,))
            return seq

    def frames_since(self, seq: int, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Retained frames after ``seq``, oldest first, optionally in a bounded batch."""
        sql = "SELECT seq, body FROM frames WHERE seq > ? ORDER BY seq"
        args: tuple = (int(seq),)
        if limit is not None:
            sql += " LIMIT ?"
            args += (max(0, int(limit)),)
        with self.read() as db:
            rows = db.execute(sql, args).fetchall()
        frames = []
        for row_seq, body in rows:
            frame = json.loads(body)
            frame["seq"] = int(row_seq)
            frames.append(frame)
        return frames

    def frame_bounds(self) -> Dict[str, float]:
        """``seq``, ``oldest`` and the newest frame's timestamp. Zeroes on an empty table."""
        with self.read() as db:
            row = db.execute("SELECT MAX(seq), MIN(seq), MAX(at) FROM frames").fetchone()
        newest, oldest, at = row if row else (None, None, None)
        return {"seq": int(newest or 0), "oldest": int(oldest or newest or 0), "at": float(at or 0.0)}

    def attached(self, now: Optional[float] = None) -> bool:
        """Whether anything is actually feeding this feed.

        Two ways to be sure, because neither alone covers both topologies. A fresh newest frame says
        SOME process is writing, which is what a route in the dashboard process can see. And a
        writer pid equal to this process's own says the hooks are here, which is the answer for a
        computer whose gateway has simply been idle. The old `attached` reported neither — it said
        a ring object existed in this process, which was true while nothing wrote to it.
        """
        bounds = self.frame_bounds()
        now = time.time() if now is None else now
        if bounds["at"] and now - bounds["at"] <= FRESH_SECONDS:
            return True
        return self.writer_pid() == os.getpid()

    # -- who is here ------------------------------------------------------

    def _note_writer_once(self) -> None:
        """Claim the writer on the first frame this process appends, and not before.

        Measured against a real Hermes on 2026-09-15: claiming it when the plugin LOADS makes the
        last process to start the writer, and both of them load it — so `hermes serve` reported
        itself as the process feeding a feed it has never written a frame to. A frame is the only
        evidence that exists, so a frame is what claims it.
        """
        pid = os.getpid()
        if self._noted_pid == pid:
            return
        self._noted_pid = pid
        self.note_writer(pid)

    def note_writer(self, pid: int) -> None:
        """Record the process whose hooks feed the frames table."""
        with self.write() as db:
            db.execute("INSERT INTO meta (key, value) VALUES ('writer_pid', ?)"
                       " ON CONFLICT(key) DO UPDATE SET value = excluded.value", (str(pid),))

    def note_transport(self, home: Path, selected: bool) -> None:
        """Record whether the profile loaded in THIS process asks a phone for approvals.

        Keyed by Hermes home, not by profile name, because `ctx.profile_name` answers `default` for
        more than one process and the two answers would overwrite each other. Measured against a
        real Hermes on 2026-09-15: `/info` served by the dashboard's profile reported `false` while
        the gateway that would actually ask was set to `cozychat`, so the phone would have been
        refused the feature on exactly the topology it was built for.
        """
        with self.write() as db:
            db.execute("INSERT INTO meta (key, value) VALUES (?, ?)"
                       " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                       ("transport:" + str(home), "1" if selected else "0"))

    def transport_selected(self) -> bool:
        """Whether ANY profile on this computer asks a phone. One is enough: it is the one whose
        gateway holds the command, and the route that answers is shared."""
        with self.read() as db:
            rows = db.execute("SELECT value FROM meta WHERE key LIKE 'transport:%'").fetchall()
        return any(row[0] == "1" for row in rows)

    def writer_pid(self) -> Optional[int]:
        with self.read() as db:
            row = db.execute("SELECT value FROM meta WHERE key = 'writer_pid'").fetchone()
        try:
            return int(row[0]) if row else None
        except (TypeError, ValueError):
            return None


# -- migration ------------------------------------------------------------

# What used to live beside ``__init__.py``, and where it goes. ``live-activities.json`` is not here:
# it becomes rows, so `activities.migrate_registrations` handles it.
_MOVED = ("devices.json", "keys", "outbox.sqlite", "outbox.sqlite-wal", "outbox.sqlite-shm")


def migrate_plugin_dir(plugin_dir: Path, root: Path) -> List[str]:
    """Move one plugin directory's state into the shared directory. Returns what moved.

    Runs on every load and does nothing after the first: a name already present in the shared
    directory is left alone, because the shared copy is the one both processes have been using and
    a stale per-profile file must never win. A move that fails is logged and skipped — the plugin
    starting with an empty device list is survivable, a plugin that will not start is not.
    """
    plugin_dir, root = Path(plugin_dir), Path(root)
    if plugin_dir == root:
        return []
    moved: List[str] = []
    for name in _MOVED:
        source, destination = plugin_dir / name, root / name
        if not source.exists() or destination.exists():
            continue
        try:
            root.mkdir(parents=True, exist_ok=True)
            os.chmod(root, 0o700)
            shutil.move(str(source), str(destination))
            moved.append(name)
        except OSError:
            logger.debug("cozychat could not move %s into the shared state", name, exc_info=True)
    return moved


# -- the process's own state ----------------------------------------------

_STATE: Optional[SharedState] = None
_STATE_LOCK = threading.Lock()


def shared_state() -> SharedState:
    """This process's handle on the shared directory. The same one for every module here."""
    global _STATE
    with _STATE_LOCK:
        if _STATE is None:
            _STATE = SharedState(state_root())
        return _STATE


def configure(root: Path) -> SharedState:
    """Point this process at a different shared directory. The tests only."""
    global _STATE
    with _STATE_LOCK:
        if _STATE is not None:
            _STATE.close()
        _STATE = SharedState(root)
        return _STATE
