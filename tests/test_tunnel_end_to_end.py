"""A stand-in phone pairs over the real listener, the test approves, and HTTP crosses the tunnel.

Two API Servers sit behind the ``api`` service:

- a small loopback fake, always, so CI exercises the whole path (pairing, approval, bootstrap,
  ``GET /health``, one run's SSE stream larger than a credit window);
- Hermes's real API Server routes and agent, through ``Scripts/hermes-direct-test-server.py``, opt
  in: ``COZY_HERMES_CHECKOUT`` names a Hermes source tree and ``COZY_HERMES_PYTHON`` an interpreter
  that already has Hermes's dependencies. The fixture runs under a throwaway ``HERMES_HOME`` in a
  short ``/tmp`` directory, with a deterministic local model: no real profile, provider key or
  gateway.

  Not auto-detected, and not pointed at ``~/.hermes/hermes-agent`` itself: importing Hermes from an
  installed, self-updating checkout runs its launch bootstrap, which syncs dependencies for the new
  data root and leases environments in ``~/.hermes/installs``. Use a copy of the source without
  ``.git`` (the bootstrap then leaves dependencies to the interpreter)::

      rsync -a --exclude .git --exclude venv --exclude node_modules --exclude apps \
          ~/.hermes/hermes-agent/ /tmp/czh/hermes-agent/
      COZY_HERMES_CHECKOUT=/tmp/czh/hermes-agent \
      COZY_HERMES_PYTHON=<a venv with Hermes's dependencies>/bin/python \
          python -m pytest cozychat/tests/test_tunnel_end_to_end.py
"""

import asyncio
import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from cozychat.relay import pairing
from cozychat.relay.host import Listener, ListenerConfig
from cozychat.relay.pairing import PairingStore
from cozychat.relay.services import ApiTarget

from tunnel_phone import Phone, loopback_binds

REPO = Path(__file__).resolve().parents[4]
FIXTURE_SCRIPT = REPO / "Scripts" / "hermes-direct-test-server.py"
CHECKOUT = Path(os.environ.get("COZY_HERMES_CHECKOUT") or "/nonexistent")
HERMES_PYTHON = Path(os.environ.get("COZY_HERMES_PYTHON") or "/nonexistent")


def run(coro, timeout=90):
    return asyncio.run(asyncio.wait_for(coro, timeout))


async def http(port, request: bytes, *, until: bytes = b"", timeout=60.0):
    """One request on a fresh connection through the phone's loopback port. Returns (status, body)."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(request)
    await writer.drain()
    raw = b""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        chunk = await asyncio.wait_for(reader.read(65536), max(0.1, deadline - loop.time()))
        if not chunk:
            break
        raw += chunk
        if until and until in raw:
            break
    writer.close()
    head, _, body = raw.partition(b"\r\n\r\n")
    status = int(head.split(b" ", 2)[1])
    if b"transfer-encoding: chunked" in head.lower():
        body = _dechunk(body)
    return status, body


def _dechunk(body: bytes) -> bytes:
    out = b""
    while body:
        size_line, sep, rest = body.partition(b"\r\n")
        if not sep:
            break
        try:
            size = int(size_line.split(b";")[0], 16)
        except ValueError:
            break
        if size == 0:
            break
        out += rest[:size]
        body = rest[size + 2:]
    return out


def get(path, key=None):
    auth = f"Authorization: Bearer {key}\r\n" if key else ""
    return (f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{auth}Connection: close\r\n\r\n").encode()


def post(path, body: dict, key):
    data = json.dumps(body).encode()
    return (f"POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {key}\r\n"
            f"Content-Type: application/json\r\nIdempotency-Key: tunnel-e2e-{time.time_ns()}\r\n"
            f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n").encode() + data


async def pair_and_tunnel(store, api_target):
    """Pair a new phone over the real listener, approve it as the person would, open the api port."""
    window = store.open_window()
    listener = Listener(store, ListenerConfig(port=0, interfaces=loopback_binds),
                        capabilities=lambda hints: {"relay_proto": 1, "reach": hints},
                        api=lambda: api_target)
    await listener.start()
    phone = Phone(pairing.pairing_link(store.host_public(), window, listener.hints()))
    await phone.connect()
    while store.attempt() is None:
        await asyncio.sleep(0.05)
    attempt = store.attempt()
    assert attempt.code == phone.code
    assert store.decide(attempt.id, approve=True)  # the person presses Enter
    assert await phone.next_control() == {"event": "pairing.approved"}
    bootstrap = await phone.request("bootstrap")
    assert bootstrap["ok"] and bootstrap["api_key"] == api_target.key
    return listener, phone, await phone.expose_api(), bootstrap["api_key"]


# -- a loopback fake of the API Server -----------------------------------------------------------

DELTA = "x" * 4000
DELTAS = 150  # 600 KB of SSE, more than two credit windows


async def fake_api(key):
    async def handle(reader, writer):
        request = await reader.readuntil(b"\r\n\r\n")
        line, *headers = request.decode().split("\r\n")
        method, path, _ = line.split(" ")
        fields = {h.split(":", 1)[0].lower(): h.split(":", 1)[1].strip() for h in headers if ":" in h}
        if int(fields.get("content-length", 0)):
            await reader.readexactly(int(fields["content-length"]))
        authorized = fields.get("authorization") == f"Bearer {key() if callable(key) else key}"
        if path == "/health":
            body = b'{"status": "ok", "platform": "fake"}'
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d"
                         b"\r\nConnection: close\r\n\r\n%s" % (len(body), body))
        elif not authorized:
            writer.write(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        elif path == "/v1/models":
            body = b'{"data":[]}'
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d"
                         b"\r\nConnection: close\r\n\r\n%s" % (len(body), body))
        elif method == "POST" and path == "/v1/runs":
            body = b'{"run_id": "run_fake", "status": "started"}'
            writer.write(b"HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\n"
                         b"Content-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(body), body))
        elif path == "/v1/runs/run_fake/events":
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                         b"Connection: close\r\n\r\n")
            for seq in range(DELTAS):
                event = {"event": "message.delta", "seq": seq, "delta": DELTA}
                writer.write(f"id: {seq}\ndata: {json.dumps(event)}\n\n".encode())
                await writer.drain()
            done = {"event": "run.completed", "output": "fake reply through the tunnel"}
            writer.write(f"data: {json.dumps(done)}\n\n".encode())
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


def test_pair_approve_then_health_and_an_sse_run_through_the_tunnel(tmp_path):
    store = PairingStore(tmp_path / "relay")

    async def scenario():
        server, port = await fake_api("fake-key")
        listener, phone, local, key = await pair_and_tunnel(store, ApiTarget(port=port, key="fake-key"))
        try:
            status, body = await http(local, get("/health"))
            assert status == 200 and json.loads(body)["status"] == "ok"
            status, _ = await http(local, post("/v1/runs", {"input": "hi"}, "wrong"))
            assert status == 401  # the API Server's own auth still applies inside the tunnel
            status, body = await http(local, post("/v1/runs", {"input": "hi"}, key))
            assert status == 202 and json.loads(body)["run_id"] == "run_fake"
            status, body = await http(local, get("/v1/runs/run_fake/events", key))
            assert status == 200
            events = [json.loads(line[6:]) for line in body.decode().splitlines()
                      if line.startswith("data: ")]
            assert len(events) == DELTAS + 1
            assert "".join(e.get("delta", "") for e in events) == DELTA * DELTAS
            assert events[-1] == {"event": "run.completed",
                                  "output": "fake reply through the tunnel"}
        finally:
            await phone.close()
            await listener.stop()
            server.close()

    run(scenario())
    assert len(store.phones()) == 1


@pytest.mark.skipif(not (HERMES_PYTHON.is_file() and (CHECKOUT / "gateway").is_dir()),
                    reason="opt in with COZY_HERMES_CHECKOUT and COZY_HERMES_PYTHON")
def test_against_hermes_real_api_server_routes(tmp_path):
    """Scripts/hermes-direct-test-server.py: Hermes's own API Server and agent, a fixture model."""
    short = Path(tempfile.mkdtemp(prefix="czt", dir="/tmp"))  # AF_UNIX paths under HERMES_HOME
    fixture = short / "fixture.json"
    env = {k: v for k, v in os.environ.items() if not k.startswith(("HERMES_", "API_SERVER_"))}
    env["TMPDIR"] = str(short)
    env["HERMES_DISABLE_LAZY_INSTALLS"] = "1"  # never sync or install dependencies from here
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    server = subprocess.Popen([str(HERMES_PYTHON), "-B", str(FIXTURE_SCRIPT), str(CHECKOUT), str(fixture)],
                              env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                              cwd=str(short))
    try:
        deadline = time.monotonic() + 120
        while not fixture.exists():
            assert server.poll() is None, server.stdout.read()
            assert time.monotonic() < deadline, "the Hermes fixture did not start"
            time.sleep(0.2)
        time.sleep(0.2)
        config = json.loads(fixture.read_text())
        target = ApiTarget(port=int(config["url"].rsplit(":", 1)[1]), key=config["key"])
        store = PairingStore(tmp_path / "relay")

        async def scenario():
            listener, phone, local, key = await pair_and_tunnel(store, target)
            try:
                status, body = await http(local, get("/health"))
                assert status == 200 and json.loads(body)["status"] == "ok"
                status, body = await http(local, post("/v1/runs", {"input": "Repeat this phrase"}, key))
                assert status in (200, 202), body
                run_id = json.loads(body)["run_id"]
                status, body = await http(local, get(f"/v1/runs/{run_id}/events", key),
                                          until=b"run.completed", timeout=90)
                assert status == 200
                text = body.decode()
                assert "run.completed" in text
                assert "Hermes direct reply" in text
            finally:
                await phone.close()
                await listener.stop()

        run(scenario(), timeout=150)
    finally:
        if server.poll() is None:
            server.send_signal(signal.SIGTERM)
            try:
                server.wait(20)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(5)
        shutil.rmtree(short, ignore_errors=True)
