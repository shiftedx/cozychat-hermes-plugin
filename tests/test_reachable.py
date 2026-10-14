"""Service adapters and receipts: no installer runs, no real user label/unit/task is touched."""

import ast
import os
import plistlib
from pathlib import Path
from types import SimpleNamespace
from xml.etree import ElementTree

import pytest

from cozychat.relay.desktop import Gateway, PageError
from cozychat.relay.pairing import PairingStore
from cozychat.relay.reachable import HermesService, Reachable
from cozychat.relay.platform import is_wsl, service_platform
from cozychat.relay.runtime import Tunnel
from test_desktop_pairing import FakeService


@pytest.mark.parametrize("system, expected", [("darwin", "launchd"), ("linux", "systemd"),
                                             ("linux2", "systemd"), ("win32", "windows")])
def test_selects_native_service_backend(system, expected):
    assert service_platform(system) == expected


def test_unknown_platform_fails_clearly():
    with pytest.raises(RuntimeError):
        service_platform("freebsd")


@pytest.mark.parametrize("release, env, expected", [
    ("6.6.0-microsoft-standard-WSL2", {}, True), ("4.4.0-Microsoft", {}, True),
    ("6.6.0", {"WSL_DISTRO_NAME": "Ubuntu"}, True), ("Darwin", {}, False),
    ("6.6.0", {"WSL_INTEROP": "/run/WSL/1_interop"}, True), ("6.6.0", {}, False),
])
def test_detects_wsl_without_platform_specific_imports(release, env, expected):
    assert is_wsl(system="Linux", release=release, environ=env) is expected


def adapter(tmp_path, system):
    calls = []
    home = tmp_path / "hermes"
    home.mkdir(exist_ok=True)
    upstream = tmp_path / "login" / "hermes-gateway.service"
    module = SimpleNamespace(
        get_hermes_home=lambda: home, get_launchd_plist_path=lambda: upstream,
        get_systemd_unit_path=lambda **kw: upstream.with_name("system-hermes.service") if kw.get("system") else upstream,
        has_legacy_hermes_units=lambda: False, supports_systemd_services=lambda: True,
        _preflight_user_systemd=lambda: None, is_installed=lambda: upstream.exists(),
        PROJECT_ROOT=tmp_path, get_python_path=lambda: "python",
        _build_service_path_dirs=lambda: ["/bin"], _append_node_dir_for_service=lambda paths: None,
        launchd_program_arguments=lambda command, *args: command,
        runtime_command=lambda root, args, **kw: ["python", "-c", "import runpy; runpy.run_module('hermes_cli.main')", *args],
    )
    def forbidden(*args, **kwargs):
        pytest.fail("CozyChat called an upstream service mutation")
    for name in ("launchd_install", "launchd_uninstall", "systemd_install", "systemd_uninstall",
                 "install", "uninstall", "start", "refresh_launchd_plist_if_needed", "_prepare_service_launcher"):
        setattr(module, name, forbidden)
    service = HermesService(home, system=system, load=lambda name: module)
    task = {"definition": None}
    loaded = {"value": False}
    service.loaded = loaded

    def native(command, **kwargs):
        calls.append(command)
        if "bootstrap" in command or "enable" in command and command[0] != "launchctl":
            loaded["value"] = True  # launchctl enable only lifts the disabled override
        elif "bootout" in command or "disable" in command:
            loaded["value"] = False
        elif "print" in command or "is-enabled" in command:
            return SimpleNamespace(returncode=0 if loaded["value"] else 1)
        return SimpleNamespace(returncode=0)
    service._run = native
    def scheduled(action, expected=None):
        calls.append(["task", action, service.name])
        if action == "create":
            task["definition"] = {"sha256": service.path().read_text()}
            return dict(task["definition"])
        if action == "query":
            return task["definition"]
        if action == "remove":
            if task["definition"]["sha256"] != expected:
                return False
            task["definition"] = None
            return True
        return True
    service._task = scheduled
    return service, calls, upstream, module, task


@pytest.mark.parametrize("system", ["darwin", "linux", "win32"])
def test_own_definition_command_and_unique_name_per_home(tmp_path, system):
    service, calls, upstream, module, _ = adapter(tmp_path, system)
    other = HermesService(tmp_path / "other-home", system=system, load=lambda name: module)
    assert other.name != service.name
    assert HermesService(service.home / ".", system=system, load=lambda name: module).name == service.name
    assert service.path() != upstream
    created = service.install()
    assert service.matches(created) and not upstream.exists()
    content = service.path().read_bytes()
    if system == "darwin":
        data = plistlib.loads(content)
        assert data["Label"].startswith("ai.cozylabs.cozychat.gateway.")
        assert data["EnvironmentVariables"]["HERMES_HOME"] == str(service.home)
        assert data["ProgramArguments"][-3:] == ["gateway", "run", "--external-supervisor"]
        assert data["EnvironmentVariables"]["HERMES_SUPERVISED_CHILD"] == "1"
    elif system == "linux":
        assert service.name.startswith("cozychat-gateway-") and service.name.endswith(".service")
        assert 'Environment="HERMES_HOME=' in content.decode() and "gateway" in content.decode()
        assert "WantedBy=default.target" in content.decode()
        assert all(command[:2] == ["systemctl", "--user"] for command in calls)
    else:
        assert service.name.startswith("\\CozyChat\\Gateway-")
        data = ElementTree.fromstring(content)
        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        args = data.find("t:Actions/t:Exec/t:Arguments", ns).text
        assert "gateway run" in args and "HERMES_HOME" in args and str(service.home) in args
    service.start()
    assert service.uninstall(created)
    assert not service.installed()


@pytest.mark.parametrize("system", ["darwin", "linux", "win32"])
@pytest.mark.parametrize("enabled", [True, False])
def test_existing_hermes_service_is_read_only_and_switch_locked_on(tmp_path, system, enabled):
    service, calls, upstream, _, _ = adapter(tmp_path, system)
    upstream.parent.mkdir()
    upstream.write_text("Person's Hermes service")
    reachable = Reachable(PairingStore(service.home / "cozychat/relay"), service)
    result = reachable.set(enabled)
    assert result == {"enabled": True, "installed": True, "owned": False,
        "editable": False, "note": "Already kept running by your Hermes service"}
    assert not reachable.path.exists() and not service.path().exists()
    assert upstream.read_text() == "Person's Hermes service" and calls == []


@pytest.mark.parametrize("scope", ["system", "legacy"])
def test_linux_detects_existing_system_and_legacy_hermes_services(tmp_path, scope):
    service, calls, upstream, module, _ = adapter(tmp_path, "linux")
    upstream.parent.mkdir()
    if scope == "system":
        module.get_systemd_unit_path(system=True).write_text("existing")
    else:
        module.has_legacy_hermes_units = lambda: True
    assert Reachable(PairingStore(service.home / "cozychat/relay"), service).set(True)["editable"] is False
    assert calls == []


def test_linux_without_user_systemd_falls_back_to_clear_note(tmp_path):
    store, service = PairingStore(tmp_path / "relay"), FakeService()
    service.available = lambda: False
    result = Reachable(store, service).set(True)
    assert not result["enabled"] and not result["installed"] and service.calls == []
    assert "Keep Hermes running" in result["note"]


@pytest.mark.parametrize("system", ["darwin", "linux", "win32"])
def test_concurrent_create_neither_overwrites_nor_claims_definition(tmp_path, system):
    service, calls, _, _, _ = adapter(tmp_path, system)
    original = service.definition
    def interleave():
        content = original()
        service.path().parent.mkdir(parents=True, exist_ok=True)
        service.path().write_text("user-created")
        return content
    service.definition = interleave
    reachable = Reachable(PairingStore(service.home / "cozychat/relay"), service)
    assert not reachable.set(True)["owned"]
    assert service.path().read_text() == "user-created"
    reachable.set(False)
    assert service.path().read_text() == "user-created"
    assert not any(command[0] in ("launchctl", "systemctl") or command[1] in ("create", "remove") for command in calls)


@pytest.mark.parametrize("system", ["darwin", "linux", "win32"])
@pytest.mark.parametrize("identical", [False, True])
def test_replacement_during_native_registration_is_not_claimed(tmp_path, system, identical):
    service, _, _, _, _ = adapter(tmp_path, system)
    original_run, original_task = service._run, service._task
    def replace():
        replacement = tmp_path / "replacement"
        replacement.write_bytes(service.path().read_bytes() if identical else b"Person's replacement")
        replacement.replace(service.path())
    def native(command, **kw):
        result = original_run(command, **kw)
        if command[1] in ("bootstrap", "--user"):
            replace()
        return result
    def scheduled(action, expected=None):
        result = original_task(action, expected)
        if action == "create":
            replace()
        return result
    service._run, service._task = native, scheduled
    reachable = Reachable(PairingStore(service.home / "cozychat/relay"), service)
    result = reachable.set(True)
    assert not result["owned"] and "definition" not in reachable.read()
    before = service.path().read_bytes()
    reachable.set(False)
    assert service.path().read_bytes() == before


@pytest.mark.parametrize("system", ["darwin", "linux", "win32"])
@pytest.mark.parametrize("identical", [False, True])
def test_replacement_during_native_stop_is_preserved(tmp_path, system, identical):
    service, _, _, _, _ = adapter(tmp_path, system)
    reachable = Reachable(PairingStore(service.home / "cozychat/relay"), service)
    assert reachable.set(True)["owned"]
    original_run, original_task = service._run, service._task
    def replace():
        replacement = tmp_path / "replacement"
        replacement.write_bytes(service.path().read_bytes() if identical else b"Person's replacement")
        replacement.replace(service.path())
    def native(command, **kw):
        result = original_run(command, **kw)
        if "bootout" in command or "disable" in command:
            replace()
        return result
    def scheduled(action, expected=None):
        result = original_task(action, expected)
        if action == "remove":
            replace()
        return result
    service._run, service._task = native, scheduled
    result = reachable.set(False)
    assert service.path().exists() and "was kept" in result["note"]


@pytest.mark.parametrize("system", ["darwin", "linux", "win32"])
def test_definition_edited_before_off_is_preserved(tmp_path, system):
    service, calls, _, _, _ = adapter(tmp_path, system)
    reachable = Reachable(PairingStore(service.home / "cozychat/relay"), service)
    reachable.set(True)
    service.path().write_text("Person changed automatic startup")
    calls.clear()
    assert not reachable.state()["owned"]
    assert "was kept" in reachable.set(False)["note"]
    assert service.path().read_text() == "Person changed automatic startup"
    assert not any("bootout" in command or "disable" in command or "remove" in command for command in calls)


def test_windows_task_replacement_and_unrelated_startup_launchers_are_preserved(tmp_path):
    service, calls, _, _, task = adapter(tmp_path, "win32")
    reachable = Reachable(PairingStore(service.home / "cozychat/relay"), service)
    reachable.set(True)
    startup = service.home / "Startup/hermes.vbs"
    startup.parent.mkdir()
    startup.write_text("Person's Startup launcher")
    legacy = service.home / "gateway-service/hermes.cmd"
    legacy.parent.mkdir()
    legacy.write_text("Person's legacy launcher")
    task["definition"] = {"sha256": "Person's replacement task"}
    calls.clear()
    assert "was kept" in reachable.set(False)["note"]
    assert task["definition"]["sha256"] == "Person's replacement task"
    assert not any("remove" in command for command in calls)
    assert startup.read_text() == "Person's Startup launcher" and legacy.read_text() == "Person's legacy launcher"


def test_uninstall_failure_keeps_the_receipt_for_a_retry(tmp_path):
    service = FakeService()
    reachable = Reachable(PairingStore(tmp_path / "relay"), service)
    reachable.set(True)
    def fail(expected):
        raise RuntimeError("native service error")
    service.uninstall = fail
    with pytest.raises(RuntimeError):
        reachable.set(False)
    assert reachable.read()["definition"] == service.content


def gateway(tmp_path, monkeypatch, *, pids=()):
    home = tmp_path / "hermes"
    home.mkdir()
    tunnel = Tunnel(PairingStore(home / "cozychat" / "relay"), config={},
                    plugin_version="0.6.0", state_version="shared-v1", home=home, environ={})
    service = FakeService()
    calls = []
    service.start = lambda: calls.append("start")
    state = {"platforms": {"telegram": {"enabled": True}, "api_server": {"extra": {"port": 8642}}}}
    config = SimpleNamespace(
        get_hermes_home=lambda: home,
        get_env_value_prefer_dotenv=lambda key: None,
        require_env_writable=lambda *args: calls.append(("writable", args)),
        save_env_value=lambda key, value: calls.append((key, value)),
        require_readable_config_before_write=lambda path: state,
        atomic_config_write=lambda path, data: calls.append(("config", data)),
    )
    modules = {"hermes_cli.config": config, "hermes_cli.gateway": SimpleNamespace(find_gateway_pids=lambda: list(pids))}
    controller = Gateway(tunnel, service, load=lambda name: modules[name])
    return controller, calls, state, service


def test_ready_gateway_is_kept_and_service_prestart_runs(tmp_path, monkeypatch):
    controller, calls, _, _ = gateway(tmp_path, monkeypatch, pids=[7])
    monkeypatch.setattr(controller, "ready", lambda: True)
    controller.ensure(lambda: calls.append("login-service"))
    assert calls == ["login-service"]


def test_running_gateway_without_api_requires_explicit_restart(tmp_path, monkeypatch):
    controller, calls, _, _ = gateway(tmp_path, monkeypatch, pids=[7])
    monkeypatch.setattr(controller, "ready", lambda: False)
    with pytest.raises(PageError, match="Restart Hermes after your current chat"):
        controller.ensure()
    assert any(call[0] == "API_SERVER_HOST" for call in calls)
    assert "start" not in calls


def test_stopped_gateway_is_configured_on_loopback_then_started(tmp_path, monkeypatch):
    controller, calls, state, service = gateway(tmp_path, monkeypatch)
    ready = iter([False, True])
    monkeypatch.setattr(controller, "ready", lambda: next(ready))
    controller.ensure(lambda: setattr(service, "exists", True))
    env = {call[0]: call[1] for call in calls if isinstance(call, tuple) and call[0].startswith("API_SERVER")}
    assert len(env["API_SERVER_KEY"]) == 64 and env["API_SERVER_HOST"] == "127.0.0.1"
    assert state["platforms"]["api_server"] == {"enabled": True, "extra": {
        "port": 8642, "host": "127.0.0.1", "key": env["API_SERVER_KEY"]}}
    assert state["platforms"]["telegram"] == {"enabled": True} and calls[-1] == "start"


def test_gateway_timeout_does_not_show_a_qr(tmp_path, monkeypatch):
    controller, _, _, service = gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(controller, "ready", lambda: False)
    times = iter([0, 31])
    controller._clock = lambda: next(times)
    with pytest.raises(PageError, match="still starting"):
        controller.ensure(lambda: setattr(service, "exists", True))
    assert controller.tunnel.store.window() is None


def test_configure_preserves_custom_port_and_publishes_it_for_bootstrap(tmp_path, monkeypatch):
    controller, calls, state, _ = gateway(tmp_path, monkeypatch)
    state["platforms"]["api_server"]["extra"]["port"] = 9123
    controller.configure()
    assert ("API_SERVER_PORT", "9123") in calls
    assert state["platforms"]["api_server"]["extra"]["port"] == 9123


def test_configure_preserves_yaml_key_and_bootstrap_uses_the_same_key(tmp_path, monkeypatch):
    import yaml

    controller, calls, state, _ = gateway(tmp_path, monkeypatch)
    key = "existing-yaml-key-0123456789"
    state["platforms"]["api_server"]["extra"]["key"] = key
    # The key in force is what discovery reads from disk: YAML-only here.
    (controller.tunnel.home / "config.yaml").write_text(yaml.safe_dump(state))
    config = controller._load("hermes_cli.config")
    values = {}

    def save(name, value):
        values[name] = value
        (controller.tunnel.home / ".env").write_text("\n".join(f"{k}={v}" for k, v in values.items()))

    config.save_env_value = save
    config.atomic_config_write = lambda path, data: path.write_text(yaml.safe_dump(data))
    controller.configure()
    assert values["API_SERVER_KEY"] == key
    assert controller.tunnel.api().key == state["platforms"]["api_server"]["extra"]["key"] == key


@pytest.mark.parametrize("oversized", [False, True])
def test_ready_requires_complete_authenticated_capabilities_not_public_health(tmp_path, monkeypatch, oversized):
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    controller, _, _, _ = gateway(tmp_path, monkeypatch)
    expected = "actual-key-0123456789"
    paths = []
    # Frozen from Hermes 0.21.6's _handle_capabilities with its endpoint/feature tables and
    # browser-control constants, rather than padding a tiny response with irrelevant bytes.
    payload = Path(__file__).with_name("hermes_capabilities.json").read_bytes().strip()
    assert len(payload) > 4096
    if oversized:
        payload = b' ' * (1024 * 1024) + payload

    class API(BaseHTTPRequestHandler):
        def do_GET(self):
            paths.append(self.path)
            authenticated = self.headers.get("Authorization") == f"Bearer {expected}"
            status = 200 if self.path == "/health" or authenticated else 401
            self.send_response(status)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), API)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        env = controller.tunnel.home / ".env"
        env.write_text(f"API_SERVER_PORT={server.server_port}\nAPI_SERVER_KEY=wrong-key-0123456789\n")
        assert not controller.ready()
        env.write_text(f"API_SERVER_PORT={server.server_port}\nAPI_SERVER_KEY={expected}\n")
        assert controller.ready() is (not oversized)
        assert paths == ["/v1/capabilities", "/v1/capabilities"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


@pytest.mark.parametrize("state_name", ["stopped", "healthy", "running-unready", "start-unready", "wildcard-yaml", "wildcard-env", "wildcard-live"])
def test_cli_requires_authenticated_gateway_readiness_before_publishing_qr(tmp_path, monkeypatch, state_name):
    import io
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from cozychat.relay import cli, pairing

    controller, calls, config_data, service = gateway(tmp_path, monkeypatch,
        pids=[7] if state_name in ("healthy", "running-unready") or state_name.startswith("wildcard") else [])
    service.exists = True
    active = {"ready": state_name == "healthy" or state_name.startswith("wildcard")}
    values = {}
    requests, published = [], []
    payload = Path(__file__).with_name("hermes_capabilities.json").read_bytes()

    class API(BaseHTTPRequestHandler):
        def do_GET(self):
            expected = config_data["platforms"]["api_server"]["extra"].get("key")
            authorized = bool(expected) and self.headers.get("Authorization") == f"Bearer {expected}"
            ready = active["ready"] and authorized and self.path == "/v1/capabilities"
            requests.append(ready)
            self.send_response(200 if ready else 503)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), API)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        config_data["platforms"]["api_server"]["extra"]["port"] = server.server_port
        def save(name, value):
            values[name] = value
            (controller.tunnel.home / ".env").write_text("\n".join(f"{k}={v}" for k, v in values.items()))
        config = controller._load("hermes_cli.config")
        config.save_env_value = save
        if state_name == "healthy" or state_name.startswith("wildcard"):
            config_data["platforms"]["api_server"]["extra"]["key"] = "healthy-key-0123456789"
            save("API_SERVER_KEY", "healthy-key-0123456789")
            save("API_SERVER_PORT", str(server.server_port))
        if state_name.startswith("wildcard"):
            import yaml
            if state_name == "wildcard-yaml":
                config_data["platforms"]["api_server"]["extra"]["host"] = "0.0.0.0"
            elif state_name == "wildcard-env":
                save("API_SERVER_HOST", "0.0.0.0")
            else:
                monkeypatch.setattr("cozychat.relay.services.live_gateway_status", lambda root: {
                    "platforms": {"api_server": {"metrics": {"host": "0.0.0.0"}}}})
            (controller.tunnel.home / "config.yaml").write_text(yaml.safe_dump(config_data))
            config.atomic_config_write = lambda path, data: path.write_text(yaml.safe_dump(data))
        def start():
            calls.append("start")
            active["ready"] = state_name == "stopped"
        service.start = start
        if state_name == "start-unready":
            times = iter([0, 31])
            controller._clock = lambda: next(times)
        monkeypatch.setattr(cli, "Gateway", lambda tunnel, service: controller, raising=False)
        monkeypatch.setattr(controller.tunnel, "listening_hints", lambda: ["192.168.1.20:49321"])
        def show(link, out):
            assert controller.ready(), "CLI published a QR before authenticated chat readiness"
            assert controller.tunnel.api().key == config_data["platforms"]["api_server"]["extra"]["key"]
            published.append(pairing.decode_link(link))
            raise EOFError  # End the command after its real publication boundary.
        monkeypatch.setattr(cli, "_print_qr", show)
        out = io.StringIO()
        status = cli.pair(controller.tunnel, advertise=[], push=True, relay=None, out=out, run_listener=False)
        if state_name in ("stopped", "healthy"):
            assert status == 130 and len(published) == 1 and requests[-1] is True
        else:
            assert status == 1 and not published
            assert "Restart Hermes" in out.getvalue() if state_name == "running-unready" or state_name.startswith("wildcard") else "still starting" in out.getvalue()
            if state_name.startswith("wildcard"):
                assert ("API_SERVER_HOST", "127.0.0.1") not in calls  # save is doubled above
                assert values["API_SERVER_HOST"] == "127.0.0.1" and not requests
        assert ("start" in calls) is (state_name in ("stopped", "start-unready"))
        assert controller.tunnel.store.window() is None
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


@pytest.mark.parametrize("kind", ["systemd", "windows"])
def test_no_login_service_starts_a_detached_gateway_without_replacing_one(tmp_path, monkeypatch, kind):
    controller, calls, _, service = gateway(tmp_path, monkeypatch)
    service.kind = kind
    service.module = lambda: SimpleNamespace(_spawn_detached=lambda **kwargs: calls.append(("detached", kwargs)))
    upstream = controller._load("hermes_cli.gateway")
    upstream.PROJECT_ROOT, upstream.get_python_path = tmp_path, lambda: "python"
    launchers = SimpleNamespace(runtime_command=lambda root, args, **kwargs: ["python", *args])
    original_load = controller._load
    controller._load = lambda name: launchers if name == "hermes_cli._launchers" else original_load(name)
    ready = iter([False, True])
    monkeypatch.setattr(controller, "ready", lambda: next(ready))
    monkeypatch.setattr("cozychat.relay.desktop.subprocess.Popen", lambda command, **kwargs: calls.append((command, kwargs)))
    controller.ensure()
    if kind == "windows":
        assert calls[-1] == ("detached", {"home": controller.tunnel.home})
    else:
        assert calls[-1][0] == ["python", "gateway", "run"]
        assert calls[-1][1]["start_new_session"] and calls[-1][1]["cwd"] == controller.tunnel.home


def test_windows_scheduler_uses_exclusive_create_and_created_com_object(tmp_path):
    import base64
    service, _, _, _, _ = adapter(tmp_path, "win32")
    calls = []
    service._run = lambda command, **kw: calls.append((command, kw)) or SimpleNamespace(stdout='{"sha256":"created"}')
    from cozychat.relay.reachable import HermesService
    assert HermesService._task(service, "create") == {"sha256": "created"}
    script = base64.b64decode(calls[-1][0][-1]).decode("utf-16le")
    assert ",2," in script and "Fingerprint $t" in script and "GetTask" not in script
    HermesService._task(service, "remove", "expected")
    script = base64.b64decode(calls[-1][0][-1]).decode("utf-16le")
    assert "Stop(" not in script and script.rindex("Fingerprint $t") < script.index("DeleteTask")
    assert "Startup" not in script and "gateway-service" not in script


def test_native_commands_have_closed_stdin(tmp_path, monkeypatch):
    import subprocess
    service, _, _, _, _ = adapter(tmp_path, "win32")
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda command, **kw: calls.append(kw) or SimpleNamespace(returncode=0))
    HermesService._run(service, ["powershell.exe", "-NonInteractive"])
    assert calls[0]["stdin"] == subprocess.DEVNULL and calls[0]["timeout"] == 30


SOURCE = Path(os.environ.get("HERMES_SERVICE_SOURCE", "/nonexistent"))


@pytest.mark.skipif(not SOURCE.is_dir(), reason="set HERMES_SERVICE_SOURCE for read-only credential parity")
def test_credential_check_matches_actual_upstream_without_import_side_effects():
    from cozychat.relay.services import usable_api_key
    tree = ast.parse((SOURCE / "hermes_cli/auth.py").read_text())
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef)
             and node.name in ("has_usable_secret", "_is_placeholder_shape")
             or isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
             and target.id in ("_PLACEHOLDER_SECRET_VALUES", "_PLACEHOLDER_KEY_PREFIXES") for target in node.targets)]
    namespace = {"Any": object}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "upstream-secret-check", "exec"), namespace)
    for value in (None, 123, "", "short", "your_api_key_here", "Your_Long_Credential_Here",
                  "sk-xxxxxxxxxxxxxxxx", "ghp_xxxxxxxxxxxxxxxxxxxx", "hf_xxxxxxxxxxxxxxxxx",
                  "x_x_x_x_x_x_x_x_x_x_x_x_x_x_x_x", "valid-key-0123456789", " valid-key-0123456789 "):
        assert usable_api_key(value) == namespace["has_usable_secret"](value, min_length=16)


@pytest.mark.parametrize("key", ["your_api_key_here", "your_long_secret_here", "sk-xxxxxxxxxxxxxxxx", "x" * 32])
def test_configure_regenerates_invalid_root_secret_in_both_authorities(tmp_path, monkeypatch, key):
    controller, calls, state, _ = gateway(tmp_path, monkeypatch)
    state["platforms"]["api_server"]["extra"]["key"] = key
    controller.configure()
    values = {call[0]: call[1] for call in calls if isinstance(call, tuple) and call[0].startswith("API_SERVER")}
    assert len(values["API_SERVER_KEY"]) == 64 and values["API_SERVER_KEY"] != key
    assert state["platforms"]["api_server"]["extra"]["key"] == values["API_SERVER_KEY"]


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.2", "203.0.113.1"])
def test_configured_non_loopback_bind_cannot_pass_authenticated_readiness(tmp_path, monkeypatch, host):
    controller, _, _, _ = gateway(tmp_path, monkeypatch)
    (controller.tunnel.home / ".env").write_text(f"API_SERVER_KEY=valid-key-0123456789\nAPI_SERVER_HOST={host}\n")
    def forbidden(*args, **kw):
        pytest.fail("readiness attempted HTTP before checking the effective bind")
    monkeypatch.setattr("cozychat.relay.desktop.build_opener", forbidden)
    assert controller.ready() is False


def test_windows_replacement_task_after_register_is_not_adopted(tmp_path):
    service, _, _, _, task = adapter(tmp_path, "win32")
    original = service._task
    def scheduled(action, expected=None):
        created = original(action, expected)
        if action == "create":
            task["definition"] = {"sha256": "Person's replacement after creation"}
        return created
    service._task = scheduled
    reachable = Reachable(PairingStore(service.home / "cozychat/relay"), service)
    assert not reachable.set(True)["owned"] and "definition" not in reachable.read()
    reachable.set(False)
    assert task["definition"]["sha256"] == "Person's replacement after creation"


def test_windows_replacement_task_during_stop_is_preserved(tmp_path):
    service, _, _, _, task = adapter(tmp_path, "win32")
    reachable = Reachable(PairingStore(service.home / "cozychat/relay"), service)
    assert reachable.set(True)["owned"]
    original = service._task
    def scheduled(action, expected=None):
        if action == "remove":
            task["definition"] = {"sha256": "Person's replacement during Stop"}
        return original(action, expected)
    service._task = scheduled
    assert "was kept" in reachable.set(False)["note"]
    assert task["definition"]["sha256"] == "Person's replacement during Stop"


@pytest.mark.parametrize("system", ["darwin", "linux"])
def test_pinned_hermes_definition_for_another_home_does_not_lock_switch(tmp_path, system):
    service, _, upstream, _, _ = adapter(tmp_path, system)
    upstream.parent.mkdir()
    if system == "darwin":
        upstream.write_bytes(plistlib.dumps({"EnvironmentVariables": {"HERMES_HOME": str(tmp_path / "another-home")}}))
    else:
        upstream.write_text(f'Environment="HERMES_HOME={tmp_path / "another-home"}"\n')
    result = Reachable(PairingStore(service.home / "cozychat/relay"), service).set(True)
    assert result["editable"] and result["owned"]
    assert upstream.exists()


@pytest.mark.parametrize("system", ["darwin", "linux", "win32"])
def test_hermes_service_created_between_detection_and_install_is_left_alone(tmp_path, system):
    service, calls, upstream, _, _ = adapter(tmp_path, system)
    def available():
        upstream.parent.mkdir()
        upstream.write_text("Concurrent Hermes install")
        return True
    service.available = available
    reachable = Reachable(PairingStore(service.home / "cozychat/relay"), service)
    assert reachable.set(True)["editable"] is False
    assert not service.path().exists() and not reachable.path.exists()
    assert all(command[:2] == ["task", "query"] for command in calls)
    assert upstream.read_text() == "Concurrent Hermes install"


def test_failed_install_does_not_claim_success_or_a_receipt(tmp_path):
    service = FakeService()
    service.install = lambda: None
    reachable = Reachable(PairingStore(tmp_path / "relay"), service)
    result = reachable.set(True)  # never raises: pairing must not be blocked
    assert "Pairing still works" in result["note"]
    assert "definition" not in reachable.read()


# ---- Round 4 -------------------------------------------------------------------------------

def fail_native(service, *words, times=1):
    """Make the first native commands containing one of the words fail like a real error."""
    original, remaining = service._run, {"count": times}

    def run(command, **kwargs):
        if any(word in command for word in words) and remaining["count"] > 0:
            remaining["count"] -= 1
            raise RuntimeError("native registration failed")
        return original(command, **kwargs)
    service._run = run


def fail_task_create(service, times=1):
    original, remaining = service._task, {"count": times}

    def task(action, expected=None):
        if action == "create" and remaining["count"] > 0:
            remaining["count"] -= 1
            raise RuntimeError("native registration failed")
        return original(action, expected)
    service._task = task


def fail_registration(service, system, times=1):
    if system == "win32":
        fail_task_create(service, times)
    else:
        fail_native(service, "bootstrap", "enable", times=times)


@pytest.mark.parametrize("system", ["darwin", "linux", "win32"])
def test_registration_failure_is_a_note_leaves_no_orphan_and_retry_registers(tmp_path, system):
    service, calls, _, _, _ = adapter(tmp_path, system)
    fail_registration(service, system)
    reachable = Reachable(PairingStore(service.home / "cozychat/relay"), service)
    result = reachable.set(True)
    assert result["enabled"] and "Pairing still works" in result["note"] and not result["owned"]
    assert not service.path().exists() and not service.installed()
    retried = reachable.set(True)
    assert retried["owned"] and retried["note"] is None and service.registered()


@pytest.mark.parametrize("system", ["darwin", "linux", "win32"])
def test_installed_but_unregistered_definition_is_registered_on_retry(tmp_path, system):
    service, calls, _, _, task = adapter(tmp_path, system)
    reachable = Reachable(PairingStore(service.home / "cozychat/relay"), service)
    assert reachable.set(True)["owned"]
    # The crash window: definition and receipt exist, the job is not registered.
    service.loaded["value"], task["definition"] = False, None
    assert service.installed()
    calls.clear()
    result = reachable.set(True)
    assert result["owned"] and service.registered()
    registering = [command for command in calls if command[:2] == ["task", "create"]
                   or "bootstrap" in command or "enable" in command]
    assert registering


@pytest.mark.parametrize("system", ["darwin", "linux", "win32"])
def test_failed_retry_removes_our_orphan_definition(tmp_path, system):
    service, _, _, _, task = adapter(tmp_path, system)
    reachable = Reachable(PairingStore(service.home / "cozychat/relay"), service)
    assert reachable.set(True)["owned"]
    service.loaded["value"], task["definition"] = False, None
    fail_registration(service, system)
    result = reachable.set(True)
    assert "Pairing still works" in result["note"]
    assert not service.path().exists() and "definition" not in reachable.read()


@pytest.mark.parametrize("system", ["darwin", "linux", "win32"])
def test_failed_retry_keeps_a_definition_that_is_not_ours(tmp_path, system):
    service, _, _, _, task = adapter(tmp_path, system)
    reachable = Reachable(PairingStore(service.home / "cozychat/relay"), service)
    assert reachable.set(True)["owned"]
    service.loaded["value"], task["definition"] = False, None
    service.path().write_text("Person's edited definition")
    fail_registration(service, system, times=5)
    reachable.set(True)
    assert service.path().read_text() == "Person's edited definition"


@pytest.mark.parametrize("system", ["darwin", "linux", "win32"])
def test_definition_replaced_between_link_and_registration_is_not_registered(tmp_path, system, monkeypatch):
    service, calls, _, _, _ = adapter(tmp_path, system)
    real_link = os.link

    def link_then_replace(source, destination, *args, **kwargs):
        real_link(source, destination, *args, **kwargs)
        replacement = tmp_path / "replacement"
        replacement.write_bytes(b"Person's replacement")
        replacement.replace(destination)
    monkeypatch.setattr(os, "link", link_then_replace)
    reachable = Reachable(PairingStore(service.home / "cozychat/relay"), service)
    result = reachable.set(True)
    assert not result["owned"] and "definition" not in reachable.read()
    assert service.path().read_bytes() == b"Person's replacement"
    assert not any("bootstrap" in command or "enable" in command or command[:2] == ["task", "create"]
                   for command in calls)


@pytest.mark.parametrize("system", ["darwin", "linux", "win32"])
def test_turning_off_never_stops_a_running_gateway(tmp_path, system):
    service, calls, _, _, _ = adapter(tmp_path, system)
    reachable = Reachable(PairingStore(service.home / "cozychat/relay"), service)
    assert reachable.set(True)["owned"]
    calls.clear()
    assert not reachable.set(False)["installed"]
    flat = [word for command in calls for word in command]
    assert not {"bootout", "stop", "kill", "--now"} & set(flat)
    assert "disable" in flat or system == "win32"


def test_windows_remove_script_never_stops_the_task(tmp_path):
    import base64
    service = HermesService(tmp_path / "hermes", system="win32", load=lambda name: None)
    scripts = []
    def run(command, **kwargs):
        scripts.append(base64.b64decode(command[-1]).decode("utf-16le"))
        return SimpleNamespace(stdout="true", returncode=0)
    service._run = run
    assert service._task("remove", "abc") is True
    assert "DeleteTask" in scripts[0] and "Stop(" not in scripts[0]


@pytest.mark.parametrize("system", ["darwin", "linux", "win32"])
def test_metadata_touch_does_not_make_the_definition_look_changed(tmp_path, system):
    service, _, _, _, _ = adapter(tmp_path, system)
    reachable = Reachable(PairingStore(service.home / "cozychat/relay"), service)
    assert reachable.set(True)["owned"]
    assert "ctime_ns" not in reachable.read()["definition"]["file"]
    os.chmod(service.path(), 0o640)  # changes ctime, not the definition
    reachable._cached = None
    assert reachable.state()["owned"]
    assert not reachable.set(False)["installed"] and not service.path().exists()


def test_legacy_receipt_with_ctime_still_matches(tmp_path):
    service, _, _, _, _ = adapter(tmp_path, "darwin")
    reachable = Reachable(PairingStore(service.home / "cozychat/relay"), service)
    created = service.install()
    legacy = {"file": {**created["file"], "ctime_ns": 1}}
    assert service.matches(legacy) and service.uninstall(legacy)


def test_state_is_cached_for_a_few_seconds_then_refreshed(tmp_path):
    now = {"t": 100.0}
    service, _, _, _, _ = adapter(tmp_path, "darwin")
    reachable = Reachable(PairingStore(service.home / "cozychat/relay"), service, clock=lambda: now["t"])
    assert not reachable.state()["installed"]
    service.install()
    assert not reachable.state()["installed"]
    now["t"] += 4
    assert reachable.state()["installed"]


def test_start_failure_falls_back_to_the_normal_gateway_start(tmp_path):
    controller, calls, _, service = gateway(tmp_path, None)
    service.exists = True
    def broken():
        raise RuntimeError("Could not find service")
    service.start = broken
    spawned = []
    modules = {"hermes_cli.config": controller._load("hermes_cli.config"),
               "hermes_cli.gateway": SimpleNamespace(find_gateway_pids=lambda: [], PROJECT_ROOT=tmp_path,
                                                     get_python_path=lambda: "python"),
               "hermes_cli._launchers": SimpleNamespace(runtime_command=lambda *a, **k: ["true"])}
    controller._load = lambda name: modules[name]
    import subprocess
    original = subprocess.Popen
    subprocess.Popen = lambda *a, **k: spawned.append(a[0])
    try:
        ready = iter([False, True])
        controller.ready = lambda: next(ready)
        controller.ensure()
    finally:
        subprocess.Popen = original
    assert spawned == [["true"]]


def test_configure_never_rotates_the_key_in_force_when_yaml_and_env_differ(tmp_path):
    controller, calls, state, _ = gateway(tmp_path, None)
    env_key, yaml_key = "e" * 32, "y" * 32
    controller.tunnel.api = lambda: SimpleNamespace(key=env_key, port=8642)
    state["platforms"]["api_server"]["extra"]["key"] = yaml_key
    controller.configure()
    assert ("API_SERVER_KEY", env_key) in calls
    assert state["platforms"]["api_server"]["extra"]["key"] == env_key


def test_turning_back_on_while_the_gateway_still_runs_does_not_fail_on_the_loaded_label(tmp_path):
    # launchd keeps the label loaded after `disable` (D32: the running gateway is never stopped),
    # and `launchctl bootstrap` of a loaded label fails. Found on a real Mac.
    service, calls, _, _, _ = adapter(tmp_path, "darwin")
    loaded = service.loaded

    def launchd(command, **kwargs):
        calls.append(command)
        if "bootstrap" in command:
            if loaded["value"]:
                raise RuntimeError("Bootstrap failed: 5: Input/output error")
            loaded["value"] = True
        elif "bootout" in command:
            loaded["value"] = False
        elif "print" in command:
            return SimpleNamespace(returncode=0 if loaded["value"] else 1)
        return SimpleNamespace(returncode=0)  # enable and disable leave a running job loaded
    service._run = launchd
    reachable = Reachable(PairingStore(service.home / "cozychat/relay"), service)
    assert reachable.set(True)["owned"]
    assert not reachable.set(False)["installed"] and loaded["value"]
    result = reachable.set(True)
    assert result["owned"] and result["installed"] and result["note"] is None
    assert service.path().exists() and loaded["value"]
