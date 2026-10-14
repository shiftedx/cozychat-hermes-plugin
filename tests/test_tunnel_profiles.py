"""Independent Hermes roots stay isolated; multiplexed profiles use Hermes's HTTP base paths."""

import asyncio
from contextvars import ContextVar
import json
import os
import re
import sys
from pathlib import Path
from types import ModuleType

import pytest
import yaml

from cozychat import locks, state
from cozychat.relay import mdns, noise, pairing, runtime, services
from tunnel_phone import loopback_binds
from test_tunnel_hardening import approved_phone, run


@pytest.fixture(autouse=True)
def upstream_profiles(tmp_path, monkeypatch):
    """Hermes's selector with only its filesystem/config dependencies doubled.

    When a read-only checkout is supplied, run its actual selector and directory iterator.
    The fallback has the same identity/standalone/parked gates for standalone plugin tests.
    """
    root = tmp_path / "hermes"
    module = ModuleType("hermes_cli.profiles")
    identity = lambda path: any((path / name).is_file() for name in
        ("config.yaml", ".env", "SOUL.md", "profile.yaml", "auth.json", "state.db"))
    deleted = lambda path: (root / "profiles/.deleted" / path.name).exists()
    def standalone(path):
        data = yaml.safe_load((path / "config.yaml").read_text()) if (path / "config.yaml").exists() else {}
        value = (data or {}).get("gateway", {}).get("standalone", False)
        return value.strip().lower() in ("1", "true", "yes", "on") if isinstance(value, str) else bool(value)
    def entries():
        profiles = root / "profiles"
        return [p for p in sorted(profiles.iterdir()) if p.is_dir() and p.name != "default"
                and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", p.name) and identity(p) and not deleted(p)] \
            if profiles.is_dir() else []
    module.profiles_to_serve = lambda multiplex: [("default", root)] + [
        (p.name, p) for p in entries() if not standalone(p) and not (p / "gateway.parked").exists()]
    source = Path(os.environ.get("HERMES_SERVICE_SOURCE", "/nonexistent"))
    if source.is_dir():
        import ast
        tree = ast.parse((source / "hermes_cli/profiles.py").read_text())
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name in ("profiles_to_serve", "_iter_named_profile_dirs")]
        namespace = {"Path": Path, "get_active_profile_name": lambda: "default",
            "_get_default_hermes_home": lambda: root, "_get_profiles_root": lambda: root / "profiles",
            "profile_is_parked": lambda p: (p / "gateway.parked").exists(),
            "profile_is_standalone": standalone, "named_profile_has_identity": identity,
            "named_profile_is_deleted": deleted, "_parked_default_warned": set(),
            "_PROFILE_ID_RE": re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")}
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(source / "hermes_cli/profiles.py"), "exec"), namespace)
        module.profiles_to_serve = namespace["profiles_to_serve"]
    monkeypatch.setitem(sys.modules, "hermes_cli.profiles", module)
    status = ModuleType("gateway.status")
    def read_status(path):
        if path.exists():
            return json.loads(path.read_text())
        return {"pid": 7, "hermes_home": str(path.parent),
                "served_profiles": ["default"] + [p.name for p in entries()]}
    status.read_runtime_status = read_status
    status.get_runtime_status_running_pid = lambda data, expected_home: data.get("pid") \
        if data.get("hermes_home") == str(expected_home) and data.get("live", True) else None
    monkeypatch.setitem(sys.modules, "gateway.status", status)
    return module


def tunnel_for(home):
    return runtime.Tunnel(runtime.store_for(state.state_root(home)), config={},
                          plugin_version="0.6.0", state_version="shared-v1", home=home,
                          environ={}, interfaces=loopback_binds)


def test_two_independent_homes_have_separate_keys_ports_instances_and_locks(tmp_path):
    first = tunnel_for(tmp_path / "personal")
    second = tunnel_for(tmp_path / "work")
    for tunnel in (first, second):
        tunnel.store.open_window()
    assert first.store.host_public() != second.store.host_public()
    assert mdns.instance_name(first.store.host_public()) != mdns.instance_name(second.store.host_public())
    assert first.owner().lock_path != second.owner().lock_path
    handles = [locks.claim(tunnel.owner().lock_path) for tunnel in (first, second)]
    assert all(handle is not None for handle in handles)
    for handle in handles:
        handle.close()

    async def scenario():
        listeners = [t.make_listener(port=0) for t in (first, second)]
        await asyncio.gather(*(listener.start() for listener in listeners))
        try:
            assert listeners[0].port != listeners[1].port
            phone = await approved_phone(first.store, listeners[0])
            try:
                assert first.store.is_approved(phone.static_public)
                assert not second.store.is_approved(phone.static_public)
                assert second.store.window() is not None
            finally:
                await phone.close()
        finally:
            await asyncio.gather(*(listener.stop() for listener in listeners))

    run(scenario())


def test_multiplexed_profiles_share_the_computers_tunnel_identity(tmp_path):
    default = tunnel_for(tmp_path / "hermes")
    worker = tunnel_for(tmp_path / "hermes" / "profiles" / "worker")
    assert default.store.root == worker.store.root
    assert default.store.host_public() == worker.store.host_public()
    assert default.store.port() == worker.store.port()
    assert default.owner().lock_path == worker.owner().lock_path


def test_api_credentials_use_hermes_scope_and_restore_the_callers_profile(tmp_path, monkeypatch):
    home = tmp_path / "worker"
    home.mkdir()
    (home / ".env").write_text("API_SERVER_KEY=must-not-read\n")
    monkeypatch.setenv("API_SERVER_KEY", "wrong-profile")
    current = ContextVar("profile", default={"API_SERVER_KEY": "caller"})
    module = ModuleType("agent.secret_scope")
    calls = []

    def build(path):
        assert path == home
        return {"API_SERVER_KEY": "worker-key-0123456789", "API_SERVER_PORT": "18642"}

    def bind(scope, *, profile_home):
        assert profile_home == str(home)
        return current.set(scope)

    def secret(name):
        calls.append(name)
        return current.get().get(name)

    module.build_profile_secret_scope = build
    module.set_secret_scope = bind
    module.reset_secret_scope = current.reset
    module.get_secret = secret
    monkeypatch.setitem(sys.modules, "agent", ModuleType("agent"))
    monkeypatch.setitem(sys.modules, "agent.secret_scope", module)
    target = services.discover_api(home)
    assert (target.key, target.port, target.host) == ("worker-key-0123456789", 18642, "127.0.0.1")
    assert calls == ["API_SERVER_KEY"]
    assert current.get()["API_SERVER_KEY"] == "caller"

    module.get_secret = lambda name: (_ for _ in ()).throw(RuntimeError("scope failed"))
    with pytest.raises(RuntimeError, match="scope failed"):
        services.discover_api(home)
    assert current.get()["API_SERVER_KEY"] == "caller"


def test_missing_hermes_secret_api_never_falls_back_to_a_file_or_ambient_key(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("API_SERVER_KEY=must-not-read\n")
    monkeypatch.setenv("API_SERVER_KEY", "wrong-profile")
    monkeypatch.setitem(sys.modules, "agent.secret_scope", None)
    assert services.discover_api(tmp_path).key is None


def test_two_profile_base_paths_cross_the_real_listener_without_rewriting_http(tmp_path):
    home = tmp_path / "hermes"
    profile = home / "profiles" / "worker"
    profile.mkdir(parents=True)
    (profile / "config.yaml").write_text("", encoding="utf-8")
    root_key, worker_key = "root-key-0123456789", "worker-key-9876543210"
    (profile / ".env").write_text(f"API_SERVER_KEY={worker_key}\n")
    tunnel = tunnel_for(home)
    assert tunnel.api().profiles == ("default", "worker")
    assert tunnel.capabilities([])["services"]["api"]["profiles"] == [
        {"name": "default", "base_path": ""}, {"name": "worker", "base_path": "/p/worker"}]

    async def scenario():
        requests = []

        async def handle(reader, writer):
            request = await reader.readuntil(b"\r\n\r\n")
            requests.append(request)
            body = request.split(b" ")[1]
            expected = worker_key if body.startswith(b"/p/worker/") else root_key
            authorized = f"Authorization: Bearer {expected}\r\n".encode() in request
            status = b"200 OK" if authorized else b"401 Unauthorized"
            writer.write(b"HTTP/1.1 " + status + b"\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        (home / ".env").write_text(f"API_SERVER_PORT={port}\nAPI_SERVER_KEY={root_key}\n")
        listener = tunnel.make_listener(port=0)
        await listener.start()
        phone = await approved_phone(tunnel.store, listener)
        try:
            for name, path in (("default", "/v1/sessions"), ("worker", "/p/worker/v1/sessions")):
                bootstrap = await phone.request("bootstrap", profile=name)
                assert bootstrap["api_key"] == (worker_key if name == "worker" else root_key)
                stream = await phone.mux.open("api", {"profile": name})
                request = (f"GET {path} HTTP/1.1\r\nHost: test\r\n"
                           f"Authorization: Bearer {bootstrap['api_key']}\r\n\r\n").encode()
                await stream.write(request)
                response = b""
                while chunk := await asyncio.wait_for(stream.read(), 5):
                    response += chunk
                assert response.startswith(b"HTTP/1.1 200 OK") and response.endswith(path.encode())
                assert requests[-1] == request
            # The server enforces scope: a root credential on the worker path must fail.
            stream = await phone.mux.open("api", {"profile": "worker"})
            await stream.write(f"GET /p/worker/v1/sessions HTTP/1.1\r\nHost: test\r\nAuthorization: Bearer {root_key}\r\n\r\n".encode())
            assert (await stream.read()).startswith(b"HTTP/1.1 401 Unauthorized")
            assert (await phone.request("bootstrap", profile="unknown"))["ok"] is False
        finally:
            await phone.close()
            await listener.stop()
            server.close()
            await server.wait_closed()

    run(scenario())


def test_profiles_without_scoped_credentials_are_hidden_and_cannot_bootstrap(tmp_path):
    home = tmp_path / "hermes"
    for name in ("missing", "weak", "yaml-only"):
        profile = home / "profiles" / name
        profile.mkdir(parents=True)
        (profile / "config.yaml").write_text("platforms:\n  api_server:\n    extra:\n      key: yaml-key-0123456789\n")
    (home / "profiles/weak/.env").write_text("API_SERVER_KEY=short\n")
    (home / ".env").write_text("API_SERVER_KEY=root-key-0123456789\n")
    target = tunnel_for(home).api()
    assert target.profiles == ("default",)
    context = services.SessionContext(approved=True, capabilities=lambda: {}, api=lambda: target)
    for name in ("missing", "weak", "yaml-only"):
        answer = services._answer(json.dumps({"id": 1, "op": "bootstrap", "profile": name}).encode(), context)
        assert answer == {"id": 1, "ok": False, "error": "unknown_profile"}


def test_worker_loaded_copy_uses_root_listener_and_scoped_profile_keys(tmp_path):
    home = tmp_path / "hermes"
    worker = home / "profiles/worker"
    worker.mkdir(parents=True)
    (worker / "config.yaml").write_text("")
    (home / ".env").write_text("API_SERVER_KEY=root-key-0123456789\nAPI_SERVER_PORT=8642\n")
    (worker / ".env").write_text("API_SERVER_KEY=worker-key-0123456789\nAPI_SERVER_PORT=9123\n")
    target = services.discover_api(worker, {"API_SERVER_KEY": "worker-key-0123456789", "API_SERVER_PORT": "9123"})
    assert target.port == 8642 and target.key == "root-key-0123456789"
    assert target.key_for("worker") == "worker-key-0123456789"


def test_only_root_gateway_served_profiles_are_advertised_and_bootstrapped(tmp_path, monkeypatch, upstream_profiles):
    home = tmp_path / "hermes"
    for name in ("live", "standalone", "parked", "deleted", "markerless"):
        profile = home / "profiles" / name
        profile.mkdir(parents=True)
        if name != "markerless":
            (profile / "config.yaml").write_text("gateway:\n  standalone: true\n" if name == "standalone" else "")
    (home / "profiles/parked/gateway.parked").touch()
    (home / "profiles/.deleted").mkdir()
    (home / "profiles/.deleted/deleted").touch()
    # Secret providers can supply a scoped key without a .env/config identity marker. A key
    # does not make a ghost directory a gateway-served profile.
    monkeypatch.setattr(services, "_profile_secrets", lambda path: {"API_SERVER_KEY": "scoped-key-0123456789"})
    assert [name for name, _ in upstream_profiles.profiles_to_serve(True)] == ["default", "live"]
    tunnel = tunnel_for(home)
    assert tunnel.api().profiles == ("default", "live")
    assert [p["name"] for p in tunnel.capabilities([])["services"]["api"]["profiles"]] == ["default", "live"]
    context = services.SessionContext(approved=True, capabilities=lambda: {}, api=tunnel.api)
    for name in ("standalone", "parked", "deleted", "markerless"):
        assert services._answer(json.dumps({"op": "bootstrap", "profile": name}).encode(), context)["error"] == "unknown_profile"


def test_upstream_selector_for_another_root_cannot_advertise_its_profiles(tmp_path, upstream_profiles):
    home = tmp_path / "hermes"
    worker = home / "profiles/worker"
    worker.mkdir(parents=True)
    (worker / "config.yaml").write_text("")
    (worker / ".env").write_text("API_SERVER_KEY=worker-key-0123456789\n")
    upstream_profiles.profiles_to_serve = lambda multiplex: [("default", tmp_path / "other"), ("worker", tmp_path / "other/profiles/worker")]
    assert tunnel_for(home).api().profiles == ("default",)


@pytest.mark.parametrize("record", [
    {"served_profiles": []}, {"served_profiles": ["default"]},
    {"served_profiles": ["default", "worker"], "live": False},
    {"served_profiles": ["default", "worker"], "hermes_home": "/another/home"},
    {"served_profiles": "worker"},
])
def test_workers_hidden_when_live_root_does_not_serve_them(tmp_path, record):
    home = tmp_path / "hermes"
    worker = home / "profiles/worker"
    worker.mkdir(parents=True)
    (worker / ".env").write_text("API_SERVER_KEY=worker-key-0123456789\n")
    data = {"pid": 7, "hermes_home": str(home), **record}
    (home / "gateway_state.json").write_text(json.dumps(data))
    tunnel = tunnel_for(home)
    assert tunnel.api().profiles == ("default",)
    assert [profile["name"] for profile in tunnel.capabilities([])["services"]["api"]["profiles"]] == ["default"]
    context = services.SessionContext(approved=True, capabilities=lambda: {}, api=tunnel.api)
    assert services._answer(b'{"op":"bootstrap","profile":"worker"}', context)["error"] == "unknown_profile"


def test_live_roster_intersects_selector_and_refreshes_without_restart(tmp_path):
    home = tmp_path / "hermes"
    for name in ("first", "second"):
        worker = home / "profiles" / name
        worker.mkdir(parents=True)
        (worker / ".env").write_text("API_SERVER_KEY=worker-key-0123456789\n")
    path = home / "gateway_state.json"
    for names in (["default", "first", "ghost"], ["default", "second"], []):
        path.write_text(json.dumps({"pid": 7, "hermes_home": str(home), "served_profiles": names}))
        assert tunnel_for(home).api().profiles == tuple(["default"] + [n for n in names if n in ("first", "second")])


@pytest.mark.parametrize("key", ["your_api_key_here", "your_very_long_secret_here",
    "sk-xxxxxxxxxxxxxxxx", "ghp_xxxxxxxxxxxxxxxxxxxx", "hf_xxxxxxxxxxxxxxxxx", "x" * 32])
def test_placeholder_worker_keys_are_not_advertised_or_bootstrapped(tmp_path, key):
    home = tmp_path / "hermes"
    worker = home / "profiles/worker"
    worker.mkdir(parents=True)
    (worker / ".env").write_text(f"API_SERVER_KEY={key}\n")
    assert tunnel_for(home).api().profiles == ("default",)
    context = services.SessionContext(approved=True, capabilities=lambda: {}, api=tunnel_for(home).api)
    assert services._answer(b'{"op":"bootstrap","profile":"worker"}', context)["error"] == "unknown_profile"
