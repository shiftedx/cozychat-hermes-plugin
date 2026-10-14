"""Caps and cleanup against real TCP listeners, including independent-process RSS checks."""

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from cozychat.relay import framing, noise, pairing
from cozychat.relay.host import Listener, ListenerConfig
from cozychat.relay.limits import HandshakeLimiter
from cozychat.relay.mux import (INITIAL_WINDOW, MAX_STREAMS, Mux, ProtocolError, SessionClose,
                                Stream)
from cozychat.relay.services import ApiTarget
from tunnel_phone import Phone, loopback_binds


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, 45))


async def until(predicate):
    deadline = asyncio.get_running_loop().time() + 5
    while not predicate():
        assert asyncio.get_running_loop().time() < deadline
        await asyncio.sleep(0.01)


async def approved_phone(store, listener, private=None):
    private = private or noise.generate_private_key()
    window = store.window() or store.open_window()
    phone = Phone(pairing.pairing_link(store.host_public(), window, listener.hints()),
                  static_private=private)
    phone.approved = store.is_approved(phone.static_public)
    await phone.connect()
    if not phone.approved:
        await until(lambda: store.attempt() is not None)
        assert store.decide(store.attempt().id, True)
        assert await phone.next_control() == {"event": "pairing.approved"}
    return phone


def test_token_buckets_limit_repeated_attempts_and_keep_bounded_source_state():
    now = [0.0]
    limiter = HandshakeLimiter(per_minute=60, burst=2, global_per_minute=600,
                               global_burst=10, max_sources=3, clock=lambda: now[0])
    assert limiter.admits("phone") and limiter.admits("phone")
    assert not limiter.admits("phone")
    now[0] = 1.0
    assert limiter.admits("phone")
    for index in range(5):
        assert limiter.admits(str(index))
    assert len(limiter._sources) == 3
    fixed = HandshakeLimiter(global_burst=2, clock=lambda: 0.0)
    assert fixed.admits("a") and fixed.admits("b")
    assert not fixed.admits("c")


def test_tiny_data_frames_coalesce_inside_one_credit_window():
    class DummyMux:
        def _forget(self, stream):
            pass

    stream = Stream(DummyMux(), 1, "api", {})
    for _ in range(INITIAL_WINDOW):
        assert stream._on_data(b"x")
    assert not stream._on_data(b"x")
    assert len(stream._inbound) <= 17
    assert sum(map(len, stream._inbound)) == INITIAL_WINDOW
    with pytest.raises(ProtocolError):
        stream._on_window(1)  # no outbound data was consumed


def test_handshake_rate_limit_silently_drops_new_connections(tmp_path):
    store = pairing.PairingStore(tmp_path / "relay")
    store.open_window()

    async def scenario():
        listener = Listener(store, ListenerConfig(port=0, interfaces=loopback_binds,
                                                  handshake_burst=2, handshakes_per_minute=0),
                            capabilities=lambda hints: {}, api=lambda: ApiTarget(1, None))
        await listener.start()
        try:
            for _ in range(3):
                reader, writer = await asyncio.open_connection("127.0.0.1", listener.port)
                writer.write(framing.encode(b"garbage"))
                await writer.drain()
                try:
                    assert await asyncio.wait_for(reader.read(), 2) == b""
                except ConnectionResetError:
                    pass  # closing with unread TCP bytes may reset; it still sends no reply
                writer.close()
            assert listener._half_open == 0 and store.window() is not None
        finally:
            await listener.stop()

    run(scenario())


def test_idle_session_closes_and_recovers_its_slot(tmp_path):
    store = pairing.PairingStore(tmp_path / "relay")

    async def scenario():
        listener = Listener(store, ListenerConfig(port=0, interfaces=loopback_binds,
                                                  idle_seconds=0.3, decision_poll_seconds=0.01),
                            capabilities=lambda hints: {}, api=lambda: ApiTarget(1, None))
        await listener.start()
        phone = await approved_phone(store, listener)
        try:
            await asyncio.wait_for(phone.mux.done.wait(), 3)
            assert phone.mux.remote_close_code == SessionClose.NORMAL
            await until(lambda: not listener._sessions and not listener._handlers)
        finally:
            await phone.close()
            await listener.stop()

    run(scenario())


def test_sixteen_half_open_handshakes_expire_and_the_seventeenth_is_silent(tmp_path):
    store = pairing.PairingStore(tmp_path / "relay")
    store.open_window()

    async def scenario():
        # The test's one loopback source substitutes for four LAN sources. All other P4 caps
        # and the actual 10-second expiry are unchanged.
        listener = Listener(store, ListenerConfig(port=0, interfaces=loopback_binds,
                                                  max_half_open_per_source=16),
                            capabilities=lambda hints: {}, api=lambda: ApiTarget(1, None))
        await listener.start()
        held = []
        try:
            for _ in range(16):
                phone = Phone(pairing.pairing_link(store.host_public(), store.window(), listener.hints()))
                await phone.handshake()  # do not prove the PSK with a transport frame
                held.append(phone)
            assert listener._half_open == 16
            reader, writer = await asyncio.open_connection("127.0.0.1", listener.port)
            assert await asyncio.wait_for(reader.read(), 2) == b""
            writer.close()
            for phone in held:
                assert await asyncio.wait_for(phone.reader.read(), 12) == b""
            await until(lambda: listener._half_open == 0 and not listener._handlers)
            assert not listener._half_open_by_source
        finally:
            await asyncio.gather(*(phone.close() for phone in held))
            await listener.stop()

    run(scenario())


def test_ninth_session_is_closed_and_the_eight_live_sessions_survive(tmp_path):
    store = pairing.PairingStore(tmp_path / "relay")

    async def scenario():
        listener = Listener(store, ListenerConfig(port=0, interfaces=loopback_binds,
                                                  decision_poll_seconds=0.01),
                            capabilities=lambda hints: {}, api=lambda: ApiTarget(1, None))
        await listener.start()
        phones = []
        try:
            first = await approved_phone(store, listener)
            phones.append(first)
            for _ in range(8):
                phone = await approved_phone(store, listener, first.static_private)
                phones.append(phone)
            await asyncio.wait_for(phones[-1].mux.done.wait(), 3)
            assert phones[-1].mux.remote_close_code == SessionClose.OVERLOADED
            assert len(listener._sessions) == 8
            assert all(not p.mux.done.is_set() for p in phones[:-1])
        finally:
            await asyncio.gather(*(phone.close() for phone in phones))
            await listener.stop()

    run(scenario())


def test_rapid_open_close_cancels_old_service_tasks(tmp_path):
    store = pairing.PairingStore(tmp_path / "relay")

    async def scenario():
        listener = Listener(store, ListenerConfig(port=0, interfaces=loopback_binds),
                            capabilities=lambda hints: {}, api=lambda: ApiTarget(1, None))
        await listener.start()
        phone = await approved_phone(store, listener)
        host = next(iter(listener._sessions))
        try:
            for _ in range(100):
                stream = await phone.mux.open("control")
                await stream.close()
                await asyncio.sleep(0)
                assert len(host._tasks) <= MAX_STREAMS
            await until(lambda: host.open_streams == 1 and len(host._tasks) == 1)
            assert (await phone.request("info"))["ok"]
        finally:
            await phone.close()
            await listener.stop()
        assert not host._tasks and not listener._handlers

    run(scenario())


def test_stalled_socket_write_times_out_without_growing_the_buffer():
    from test_tunnel_mux import sessions

    class Transport:
        def set_write_buffer_limits(self, **kwargs):
            self.limits = kwargs

    class Writer:
        transport = Transport()
        size = 0
        closed = False

        def write(self, data):
            self.size += len(data)

        async def drain(self):
            await asyncio.Event().wait()

        def close(self):
            self.closed = True

    async def scenario():
        writer = Writer()
        session, _ = sessions()
        mux = Mux(session, asyncio.StreamReader(), writer, initiator=True, write_seconds=0.05)
        with pytest.raises(ConnectionError, match="timed out"):
            await mux.send(2, 1, b"hello")
        assert writer.closed and mux.done.is_set()
        assert writer.size <= framing.TRANSPORT_MAX + 4

    run(scenario())


RESOURCE_HOST = r'''
import asyncio, json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
sys.path.insert(0, sys.argv[2])
import conftest
from cozychat.relay.host import Listener, ListenerConfig
from cozychat.relay.pairing import PairingStore
from cozychat.relay import pairing
from cozychat.relay.services import ApiTarget
from tunnel_phone import loopback_binds

async def main():
    api_tasks = set()
    async def api(reader, writer):
        task = asyncio.current_task()
        api_tasks.add(task)
        try:
            request = await reader.readuntil(b"\r\n\r\n")
            bulk = b"/bulk" in request.split(b"\r\n", 1)[0]
            size = 50 * 1024 * 1024 if bulk else 2
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % size)
            if bulk:
                chunk = b"x" * 16384
                for _ in range(size // len(chunk)):
                    writer.write(chunk)
                    await writer.drain()
            else:
                writer.write(b"ok")
                await writer.drain()
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            api_tasks.discard(task)
    server = await asyncio.start_server(api, "127.0.0.1", 0)
    store = PairingStore(Path(sys.argv[3]) / "relay")
    window = store.open_window()
    config = ListenerConfig(port=0, interfaces=loopback_binds, advertise_mdns=False,
                            handshake_burst=200, global_handshake_burst=200,
                            decision_poll_seconds=0.01)
    listener = Listener(store, config, capabilities=lambda hints: {},
                        api=lambda: ApiTarget(server.sockets[0].getsockname()[1], "key"))
    await listener.start()
    print(json.dumps({"link": pairing.pairing_link(store.host_public(), window, listener.hints())}), flush=True)
    try:
        while await asyncio.to_thread(sys.stdin.readline):
            print(json.dumps({"sessions": len(listener._sessions), "handlers": len(listener._handlers)}), flush=True)
    finally:
        await listener.stop()
        server.close()
        await server.wait_closed()
        for task in list(api_tasks):
            task.cancel()
        await asyncio.gather(*list(api_tasks), return_exceptions=True)
asyncio.run(main())
'''


def test_stalled_50_mib_response_and_100_reconnects_stay_within_rss_caps(tmp_path):
    import psutil

    package = Path(__file__).resolve().parents[2]
    tests = Path(__file__).resolve().parent
    process = subprocess.Popen([sys.executable, "-c", RESOURCE_HOST, str(package), str(tests),
                                str(tmp_path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True,
                               env={**os.environ, "HOME": str(tmp_path / "home"),
                                    "HERMES_HOME": str(tmp_path)})
    try:
        ready = json.loads(process.stdout.readline())
        store = pairing.PairingStore(tmp_path / "relay")
        monitor = psutil.Process(process.pid)

        async def scenario():
            phone = Phone(ready["link"])
            await phone.connect()
            await until(lambda: store.attempt() is not None)
            assert store.decide(store.attempt().id, True)
            await phone.next_control()
            baseline = monitor.memory_info().rss
            stalled = await phone.mux.open("api")
            await stalled.write(b"GET /bulk HTTP/1.1\r\nHost: test\r\n\r\n")
            await asyncio.sleep(0.3)
            growth = monitor.memory_info().rss - baseline
            stalled_growth = growth
            assert growth < 64 * 1024 * 1024, f"stalled response RSS growth {growth}"
            fast = await phone.mux.open("api")
            await fast.write(b"GET /health HTTP/1.1\r\nHost: test\r\n\r\n")
            response = b""
            while chunk := await asyncio.wait_for(fast.read(), 3):
                response += chunk
            assert response.endswith(b"ok")
            # Drain the entire response to prove the producer really offered 50 MiB.
            received = 0
            while chunk := await asyncio.wait_for(stalled.read(), 5):
                received += len(chunk)
            assert received > 50 * 1024 * 1024
            private = phone.static_private
            await phone.close()
            await asyncio.sleep(0.1)
            baseline = monitor.memory_info().rss
            for _ in range(100):
                reconnect = Phone(ready["link"], static_private=private)
                reconnect.approved = True
                await reconnect.connect()
                assert (await reconnect.request("info"))["ok"]
                await reconnect.close()
            await asyncio.sleep(0.2)
            growth = monitor.memory_info().rss - baseline
            assert growth < 16 * 1024 * 1024, f"reconnect RSS growth {growth}"
            process.stdin.write("snapshot\n")
            process.stdin.flush()
            assert json.loads(await asyncio.to_thread(process.stdout.readline)) == {
                "sessions": 0, "handlers": 0}
            print(f"stalled 50 MiB RSS growth: {stalled_growth} bytes; "
                  f"100 reconnects RSS growth: {growth} bytes")

        run(scenario())
    finally:
        process.stdin.close()
        try:
            process.wait(10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(5)
        errors = process.stderr.read()
        process.stdout.close()
        process.stderr.close()
        assert process.returncode == 0, errors
