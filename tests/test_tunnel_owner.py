"""Exactly one process runs the listener, and another takes over within 5 seconds (D25)."""

import subprocess
import asyncio
import json
import os
import sys
import textwrap
import time
from pathlib import Path

import pytest

from cozychat.relay import runtime
from cozychat.relay.host import Listener, ListenerConfig
from cozychat.relay.owner import TICK_SECONDS, ListenerOwner, listening_hints
from cozychat.relay.pairing import PairingStore
from cozychat.relay.services import ApiTarget

from tunnel_phone import Phone, loopback_binds

TAKEOVER_SECONDS = 5.0


def owner_for(store, **kwargs):
    def make():
        return Listener(store, ListenerConfig(port=0, interfaces=loopback_binds),
                        capabilities=lambda hints: {}, api=lambda: ApiTarget(port=1, key=None))
    return ListenerOwner(store, make, **kwargs)


def wait_until(predicate, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def test_nothing_listens_until_a_pairing_window_opens(tmp_path):
    store = PairingStore(tmp_path / "relay")
    owner = owner_for(store)
    owner.tick()
    assert not owner.owns and not (store.root / "listener.lock").exists()
    store.open_window()
    owner.tick()
    try:
        assert owner.owns and owner.listener.port
    finally:
        owner.stop()


def test_the_listener_stops_when_there_is_nothing_left_to_listen_for(tmp_path):
    store = PairingStore(tmp_path / "relay")
    window = store.open_window()
    owner = owner_for(store)
    owner.tick()
    assert owner.owns
    store.cancel_window(window.id)
    owner.tick()
    assert not owner.owns
    owner.stop()


def test_switched_off_it_never_claims(tmp_path):
    store = PairingStore(tmp_path / "relay")
    store.open_window()
    owner = owner_for(store, enabled=lambda: False)
    owner.tick()
    assert not owner.owns
    assert not runtime.lan_enabled({"lan": True}, {"COZYCHAT_LAN": "0"})
    assert not runtime.lan_enabled({"lan": False}, {})
    assert runtime.lan_enabled({}, {})


def test_one_owner_at_a_time_and_the_other_takes_over_within_5_seconds(tmp_path):
    """Two loaded copies (here two owners with their own lock handles, as two processes have)."""
    assert TICK_SECONDS <= 2.0
    store = PairingStore(tmp_path / "relay")
    store.open_window()
    first, second = owner_for(store), owner_for(store)
    first.tick()
    second.start()  # the real loop, at the real 2-second tick
    try:
        time.sleep(0.3)
        assert first.owns and not second.owns
        stopped = time.monotonic()
        first.stop()
        assert wait_until(lambda: second.owns, TAKEOVER_SECONDS)
        assert time.monotonic() - stopped < TAKEOVER_SECONDS
        assert not first.owns
    finally:
        second.stop()


def test_a_process_holding_the_lock_keeps_the_listener_until_it_exits(tmp_path):
    """The real cross-process case: the kernel releases the flock when the holder dies."""
    store = PairingStore(tmp_path / "relay")
    store.open_window()
    holder = subprocess.Popen([sys.executable, "-c", textwrap.dedent(f"""
        import sys, time
        from pathlib import Path
        sys.path.insert(0, {str(Path(__file__).resolve().parent)!r})
        import conftest
        from cozychat.locks import claim
        handle = claim(Path({str(store.root / "listener.lock")!r}))
        assert handle is not None
        print("held", flush=True)
        time.sleep(60)
    """)], stdout=subprocess.PIPE, text=True)
    owner = owner_for(store)
    try:
        assert holder.stdout.readline().strip() == "held"
        owner.start()
        time.sleep(TICK_SECONDS + 0.5)
        assert not owner.owns
        holder.kill()
        holder.wait(5)
        killed = time.monotonic()
        assert wait_until(lambda: owner.owns, TAKEOVER_SECONDS)
        assert time.monotonic() - killed < TAKEOVER_SECONDS
    finally:
        owner.stop()
        if holder.poll() is None:
            holder.kill()
            holder.wait(5)


@pytest.mark.parametrize("argv, expected", [
    (["hermes", "serve"], True),
    (["hermes", "gateway", "run"], True),
    (["hermes", "-p", "worker", "gateway", "run"], True),
    (["hermes", "gateway"], True),
    (["hermes", "gateway", "status"], False),
    (["hermes", "cozychat", "pair"], False),
    (["hermes", "chat", "-q", "please serve dinner"], False),
    # Only the first non-flag word is the subcommand, and flag values are skipped.
    (["hermes", "chat", "-q", "serve"], False),
    (["hermes", "chat", "-q", "gateway"], False),
    (["hermes", "sessions", "gateway"], False),
    (["hermes", "-p", "serve", "chat"], False),
    (["hermes", "--profile=serve", "chat"], False),
    (["hermes", "--profile", "work", "serve"], True),
    (["hermes", "gateway", "run", "--replace"], True),
    (["pytest", "cozychat/tests"], False),
])
def test_only_serve_and_gateway_run_the_listener(argv, expected):
    assert runtime.listener_process(argv, {}) is expected


def test_the_lock_file_is_created_0600(tmp_path):
    import os
    import stat

    from cozychat import locks

    old = os.umask(0o022)
    try:
        handle = locks.claim(tmp_path / "listener.lock")
    finally:
        os.umask(old)
    assert handle is not None
    handle.close()
    assert stat.S_IMODE((tmp_path / "listener.lock").stat().st_mode) == 0o600


OWNER_PROCESS = r'''
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
sys.path.insert(0, sys.argv[2])
import conftest
from cozychat.relay.host import Listener, ListenerConfig
from cozychat.relay.owner import ListenerOwner
from cozychat.relay.pairing import PairingStore
from cozychat.relay.services import ApiTarget
from tunnel_phone import loopback_binds
store = PairingStore(Path(sys.argv[3]) / "relay")
def make():
    return Listener(store, ListenerConfig(interfaces=loopback_binds, advertise_mdns=False,
                                          decision_poll_seconds=0.01),
                    capabilities=lambda hints: {}, api=lambda: ApiTarget(1, None))
owner = ListenerOwner(store, make).start()
try:
    for line in sys.stdin:
        if line.strip() == "approve":
            attempt = store.attempt()
            result = {"approved": bool(attempt and store.decide(attempt.id, True))}
        else:
            result = {"owns": owner.owns, "port": owner.listener.port if owner.listener else None}
        print(json.dumps(result), flush=True)
finally:
    owner.stop()
'''


def test_two_subprocess_listeners_share_pairing_and_handover_after_owner_death(tmp_path):
    from cozychat.relay import pairing

    store = PairingStore(tmp_path / "relay")
    window = store.open_window()
    package = Path(__file__).resolve().parents[2]
    tests = Path(__file__).resolve().parent
    processes = []

    def command(process, value="state"):
        process.stdin.write(value + "\n")
        process.stdin.flush()
        return json.loads(process.stdout.readline())

    def spawn():
        process = subprocess.Popen([sys.executable, "-c", OWNER_PROCESS, str(package), str(tests),
                                    str(tmp_path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True,
                                   env={**os.environ, "HOME": str(tmp_path / "home"),
                                        "HERMES_HOME": str(tmp_path)})
        processes.append(process)
        return process

    try:
        first = spawn()
        assert wait_until(lambda: command(first)["owns"], 5)
        port = command(first)["port"]
        assert listening_hints(store) == [f"127.0.0.1:{port}"]
        second = spawn()
        assert command(second)["owns"] is False

        async def pair():
            phone = Phone(pairing.pairing_link(store.host_public(), window, [f"127.0.0.1:{port}"]))
            await phone.connect()
            try:
                deadline = asyncio.get_running_loop().time() + 5
                while store.attempt() is None:
                    assert asyncio.get_running_loop().time() < deadline
                    await asyncio.sleep(0.01)
                assert command(second, "approve")["approved"]
                assert await phone.next_control() == {"event": "pairing.approved"}
                return phone.static_private
            finally:
                await phone.close()

        private = asyncio.run(pair())
        started = time.monotonic()
        first.kill()
        first.wait(5)
        assert wait_until(lambda: command(second)["owns"], TAKEOVER_SECONDS)
        assert time.monotonic() - started < TAKEOVER_SECONDS
        assert command(second)["port"] == port

        async def reconnect():
            phone = Phone(pairing.pairing_link(store.host_public(), window, [f"127.0.0.1:{port}"]),
                          static_private=private)
            phone.approved = True
            await phone.connect()
            try:
                assert (await phone.request("info"))["ok"]
            finally:
                await phone.close()

        asyncio.run(reconnect())
    finally:
        for process in processes:
            process.stdin.close()
            if process.poll() is None:
                try:
                    process.wait(10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(5)
            process.stdout.close()
            process.stderr.close()


def test_listener_start_failure_does_not_escape_and_releases_ownership(tmp_path, caplog):
    from cozychat import locks

    store = PairingStore(tmp_path / "relay")
    store.open_window()

    def broken():
        raise OSError("disk full")

    owner = ListenerOwner(store, broken)
    owner.tick()
    assert not owner.owns and "could not start" in caplog.text
    successor = locks.claim(owner.lock_path)
    assert successor is not None
    successor.close()
    owner.stop()


def test_listener_receipt_is_private_and_stale_owner_hints_are_rejected(tmp_path):
    import stat
    from cozychat.relay.owner import listening_hints

    store = PairingStore(tmp_path / "relay")
    store.open_window()
    owner = owner_for(store)
    owner.tick()
    hints = owner.listener.hints()
    receipt = store.root / "listener.json"
    try:
        assert listening_hints(store) == hints
        assert stat.S_IMODE(receipt.stat().st_mode) == 0o600
    finally:
        owner.stop()
    assert not receipt.exists() and listening_hints(store) == []
    receipt.write_text(json.dumps({"hints": hints}))
    assert listening_hints(store) == []


def test_isolated_host_supervises_the_same_lazy_listener():
    argv = ["/python/hermes_cli/plugin_host_child.py"]
    assert runtime.listener_process(argv, {"HERMES_PLUGIN_HOST_PROCESS": "1"})
    assert not runtime.listener_process(argv, {})
    assert not runtime.listener_process(argv, {"HERMES_PLUGIN_HOST_PROCESS": "1", "COZYCHAT_LISTENER": "0"})
