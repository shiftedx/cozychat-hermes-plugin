"""A real Hermes plugin-host child pairs through its ASGI routes and serves the Noise tunnel."""

import asyncio
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import pytest

from tunnel_phone import Phone

SOURCE = Path(os.environ.get("HERMES_SERVICE_SOURCE", "/nonexistent"))
PLUGIN = Path(__file__).resolve().parents[1]


@pytest.fixture
def host_scratch():
    with tempfile.TemporaryDirectory(prefix="cozychat-host-test-",
                                    dir="/private/tmp" if Path("/private/tmp").is_dir() else None) as path:
        yield Path(path)


@pytest.mark.skipif(not SOURCE.is_dir(), reason="set HERMES_SERVICE_SOURCE to a read-only Hermes checkout")
def test_isolated_host_pairs_approves_and_bootstraps_over_real_listener(host_scratch):
    tmp_path = host_scratch
    # Only the test copy receives a loopback bind override and a stand-in gateway startup. The
    # shipped config, environment and CLI have no loopback override. All host/RPC/ASGI/Noise
    # machinery below is real, including registration's unsupported-context handling.
    plugin = tmp_path / "plugins/cozychat"
    shutil.copytree(PLUGIN, plugin, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    with (plugin / "__init__.py").open("a") as source:
        source.write('''
from ipaddress import ip_address, ip_network
from .relay.lan import BindAddress
from .relay.desktop import Gateway
from .relay.reachable import HermesService
_original_init = tunnel_runtime.Tunnel.__init__
def _test_init(self, *args, **kwargs):
    kwargs["interfaces"] = lambda: [BindAddress("test-only", ip_address("127.0.0.1"), ip_network("127.0.0.0/8"))]
    _original_init(self, *args, **kwargs)
tunnel_runtime.Tunnel.__init__ = _test_init
Gateway.ensure = lambda self, before_start=lambda: None: before_start()
HermesService.installed = lambda self: False
HermesService.hermes_installed = lambda self: False
''')
    # Bypass only upstream's installation bootstrap: it can repair/write its checkout even
    # under a throwaway home. The real plugin_host_child runtime and wire module stay read-only.
    (tmp_path / "hermes_bootstrap.py").write_text("# Test-only: no installation mutation.\n")
    home = tmp_path / "hermes"
    relay = home / "cozychat/relay"
    relay.mkdir(parents=True)
    (relay / "reachable.json").write_text('{"enabled": false}')
    (tmp_path / "home").mkdir()
    # Load just the stdlib-only wire module, not Hermes's application or service bootstrap.
    spec = importlib.util.spec_from_file_location("isolation_test_wire", SOURCE / "hermes_cli/plugin_host_wire.py")
    wire = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(wire)
    registrations = []

    def respond(method, params, origin):
        assert method == "ctx"
        name = params["method"]
        args = wire.decode(params.get("args"))
        if name == "get_config":
            return False if args[0] == "lan_advertise" else args[1]
        assert name == "register_hook"
        registrations.append(args[0])
        return None

    # The sealed test interpreter lacks Hermes's optional dependencies, so the real agent package
    # cannot import here; a stub scope (reading the scratch .env, as Hermes does) stands in for it.
    stub = tmp_path / "stub" / "agent"
    stub.mkdir(parents=True)
    (stub / "__init__.py").write_text("")
    (stub / "secret_scope.py").write_text(
        "from pathlib import Path\n"
        "def build_profile_secret_scope(home):\n"
        "    out = {}\n"
        "    try:\n"
        "        lines = (Path(home) / '.env').read_text().splitlines()\n"
        "    except OSError:\n"
        "        lines = []\n"
        "    for line in lines:\n"
        "        if '=' in line and not line.startswith('#'):\n"
        "            name, _, value = line.partition('=')\n"
        "            out[name.strip()] = value.strip()\n"
        "    return out\n")
    log = (tmp_path / "host.log").open("w+b")
    process = subprocess.Popen([sys.executable, "-m", "hermes_cli.plugin_host_child"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, cwd=tmp_path, bufsize=0,
        env={**os.environ, "HOME": str(tmp_path / "home"), "HERMES_HOME": str(home),
             "PYTHONPATH": os.pathsep.join([str(tmp_path / "stub"), str(SOURCE)]), "PYTHONDONTWRITEBYTECODE": "1",
             "HERMES_PLUGIN_HOST_PROCESS": "1"})
    channel = wire.Channel(process.stdout, process.stdin, respond, name="isolation-test").start()

    def request(path, method="GET", body=None):
        result = wire.decode(channel.call("asgi", {"plugin": "cozychat", "dashboard_dir": str(plugin / "dashboard"),
            "api_file": "plugin_api.py", "method": method, "path": path, "query": "",
            "headers": [["content-type", "application/json"]],
            "body": wire.encode(json.dumps(body).encode() if body is not None else b"")}, timeout=15))
        assert result["status"] == 200, result
        return json.loads(result["body"])

    async def scenario():
        requests = []
        key = "isolated-api-key-0123456789"

        async def echo(reader, writer):
            data = await reader.readuntil(b"\r\n\r\n")
            requests.append(data)
            authorized = f"Authorization: Bearer {key}\r\n".encode() in data
            writer.write(b"HTTP/1.1 " + (b"200 OK" if authorized else b"401 Unauthorized") + b"\r\nContent-Length: 2\r\n\r\nok")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(echo, "127.0.0.1", 0)
        (home / ".env").write_text(f"API_SERVER_KEY={key}\nAPI_SERVER_PORT={server.sockets[0].getsockname()[1]}\n")
        phone = None
        try:
            assert (await asyncio.to_thread(request, "/pair/state"))["first_visit"]
            assert not (relay / "listener.lock").exists()
            await asyncio.to_thread(request, "/pair/open", "POST", {})
            qr = await asyncio.to_thread(request, "/pair/qr")
            phone = Phone(qr["link"])
            await phone.connect()
            for _ in range(100):
                state = await asyncio.to_thread(request, "/pair/state")
                if state["pending"]:
                    break
                await asyncio.sleep(0.02)
            assert state["pending"]["code"] == phone.code
            assert (await phone.request("bootstrap"))["ok"] is False
            await asyncio.to_thread(request, "/pair/approve", "POST", {"id": state["pending"]["id"]})
            assert await phone.next_control() == {"event": "pairing.approved"}
            bootstrap = await phone.request("bootstrap")
            assert bootstrap["api_key"] == key
            stream = await phone.mux.open("api")
            await stream.write(f"GET /v1/sessions HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer {bootstrap['api_key']}\r\n\r\n".encode())
            assert (await stream.read()).startswith(b"HTTP/1.1 200 OK")
            assert requests and (await asyncio.to_thread(request, "/phones"))["phones"]
        finally:
            if phone:
                await phone.close()
            server.close()
            await server.wait_closed()

    try:
        assert channel.call("hello", {}, timeout=20)["protocol"] == 1
        channel.call("load", {"plugin_key": "cozychat", "plugin_id": "cozychat", "name": "cozychat",
            "path": str(plugin), "module_name": "hermes_plugins.cozychat", "profile_name": "default",
            "manifest": {"name": "cozychat", "path": str(plugin)},
            "ctx_methods": ["get_config", "register_hook", "register_cli_command"]}, timeout=15)
        assert registrations
        asyncio.run(asyncio.wait_for(scenario(), 30))
    finally:
        try:
            channel.call("shutdown", {}, timeout=5)
        except (TimeoutError, wire.PluginHostUnavailable):
            pass
        finally:
            process.stdin.close()
            try:
                process.wait(10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(5)
            channel.close("test finished")
            log.close()
