"""What ``register(ctx)`` puts into Hermes, and that it touches nothing on the way in."""

import shutil
import subprocess
from pathlib import Path

import pytest

import cozychat

PLUGIN_DIR = Path(cozychat.__file__).parent
HERMES = shutil.which("hermes")


class RecordingContext:
    """The registration surface Hermes' own admission probe offers a plugin, and no more."""

    profile_name = "luna"

    def __init__(self):
        self.hooks = []
        self.platforms = []
        self.approval_transports = []
        self.cli_commands = []
        self.unloads = []

    def get_config(self, key, default=None):
        return default

    def register_hook(self, name, callback):
        self.hooks.append((name, callback))

    def register_platform(self, **kwargs):
        self.platforms.append(kwargs)

    def register_approval_transport(self, name, present_fn):
        self.approval_transports.append((name, present_fn))

    def register_cli_command(self, name, help, setup_fn, handler_fn=None, description=""):
        self.cli_commands.append({"name": name, "setup_fn": setup_fn, "handler_fn": handler_fn})

    def on_unload(self, callback):
        self.unloads.append(callback)


@pytest.fixture
def registered():
    ctx = RecordingContext()
    cozychat.register(ctx)
    yield ctx
    for stop in ctx.unloads:
        stop()


def test_it_registers_exactly_the_hooks_the_manifest_declares(registered):
    declared = _manifest()["provides_hooks"]
    assert [name for name, _ in registered.hooks] == declared


def test_a_failing_hook_never_reaches_the_turn(registered):
    hooks = dict(registered.hooks)
    hooks["on_session_end"](session_id=object(), platform=None, interrupted="not a bool")
    hooks["on_room_member_activity"](kind="request.opened", payload="not a mapping")


def test_it_registers_the_delivery_only_platform(registered):
    (platform,) = registered.platforms
    assert platform["name"] == "cozychat"
    assert platform["check_fn"]() is True
    assert callable(platform["standalone_sender_fn"])
    with pytest.raises(RuntimeError):
        platform["adapter_factory"](None)
    # And it says so BEFORE the gateway asks: an entry that offers no `is_connected` is
    # auto-enabled as an inbound platform, and the adapter above is then demanded — and logged as
    # an ERROR with a traceback — on every gateway start.
    assert platform["is_connected"](None) is False


def test_it_registers_the_approval_transport_under_its_own_name(registered):
    """Registered always; the HOST keeps it inactive until the owner's config selects it."""
    (name, present) = registered.approval_transports[0]
    assert name == "cozychat"
    assert callable(present)


def test_the_registered_stores_live_in_the_shared_state_not_the_plugin_directory(
        registered, shared_state):
    """A cron delivery reads the phones and writes the outbox where the shared root says."""
    import asyncio
    from cozychat.devices import DeviceStore

    DeviceStore(shared_state.root).add(
            {"device_id": "phone-1", "push_id": "push-abc", "key_hex": b"test-push-key".hex(),
             "profile": "luna", "consent_version": 1})
    send = registered.platforms[0]["standalone_sender_fn"]
    assert asyncio.run(send(None, "chat", "hello"))["success"] is True
    assert (shared_state.root / "outbox.sqlite").is_file()
    assert not (PLUGIN_DIR / "devices.json").exists()
    assert not (PLUGIN_DIR / "outbox.sqlite").exists()
    assert not (PLUGIN_DIR / "keys").exists()


def test_cron_delivery_with_no_phone_paired_is_an_error_not_a_crash(registered):
    import asyncio
    send = registered.platforms[0]["standalone_sender_fn"]
    assert "error" in asyncio.run(send(None, "chat", "hello"))


def test_the_manifest_declares_the_documented_configuration():
    manifest = _manifest()
    assert manifest["kind"] == "platform" and manifest["name"] == "cozychat"
    assert manifest["manifest_version"] == 2
    from packaging.requirements import Requirement
    dependencies = {Requirement(value).name for value in manifest["python_dependencies"]}
    assert dependencies == {"cryptography", "psutil", "zeroconf", "qrcode", "pypng"}
    assert set(manifest["config_schema"]) == {
        "relay_url", "push_replies", "push_approvals", "push_rooms", "mute_subagents",
        "preview_mode", "lan", "lan_port", "lan_bind", "lan_advertise",
        "files_allowed_roots", "files_workspace"}
    assert manifest["version"] == cozychat.VERSION


def test_it_registers_the_pair_command_and_starts_no_listener_in_a_cli_process(registered):
    """`hermes cozychat pair` exists; loading the plugin outside serve or gateway listens on nothing."""
    import argparse

    (command,) = registered.cli_commands
    assert command["name"] == "cozychat"
    parser = argparse.ArgumentParser()
    command["setup_fn"](parser)
    args = parser.parse_args(["pair", "--advertise", "100.101.102.103:49321", "--no-push",
                              "--relay", "wss://relay.example.net"])
    assert args.cozychat_command == "pair" and args.no_push is True
    assert args.advertise == ["100.101.102.103:49321"]
    assert args.relay == "wss://relay.example.net"
    # The drain stopper and the pairing-surface cleanup; no listener starts in this process.
    assert len(registered.unloads) == 2


def test_backend_workers_have_pairing_surface_even_without_listener_argv(registered, shared_state):
    """A plugin API host worker is enabled Python code, but its argv is not `hermes serve`."""
    assert cozychat.pairing_page().store.root == shared_state.root / "relay"
    assert not cozychat.pairing_page().store.exists()


def test_listener_start_failure_does_not_escape_plugin_registration(monkeypatch, caplog):
    monkeypatch.setattr(cozychat.tunnel_runtime, "listener_process", lambda: True)

    def broken(tunnel, **kwargs):
        raise OSError("listener failed")

    monkeypatch.setattr(cozychat.tunnel_runtime.Tunnel, "owner", broken)
    ctx = RecordingContext()
    try:
        cozychat.register(ctx)
        assert ctx.hooks and ctx.cli_commands
        assert "Hermes will keep running" in caplog.text
    finally:
        for stop in ctx.unloads:
            stop()


@pytest.mark.skipif(HERMES is None, reason="Hermes is not installed on this machine")
def test_hermes_admits_the_plugin():
    result = subprocess.run([HERMES, "plugins", "validate", str(PLUGIN_DIR)],
                            capture_output=True, text=True, timeout=180)
    assert result.returncode == 0, result.stdout + result.stderr


def _manifest():
    import yaml
    return yaml.safe_load((PLUGIN_DIR / "plugin.yaml").read_text("utf-8"))
