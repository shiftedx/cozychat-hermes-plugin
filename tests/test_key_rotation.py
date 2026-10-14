"""Rotate through the real listener with a loopback API fixture; Hermes lifecycle is injected."""

import asyncio
import json
import types

import pytest

from cozychat.relay.control import ControlError
from cozychat.relay.rotation import APIKeyRotation, spawn_options
from cozychat.relay.services import discover_api
from test_phone_management import paired_phone, run, tunnel_at
from test_tunnel_end_to_end import get, http


def rotation_for(tunnel, restart, *, managed=False, home=None, **kwargs):
    config = types.SimpleNamespace(
        get_hermes_home=lambda: home or tunnel.home,
        require_readable_config_before_write=lambda path: {"platforms": {"api_server": {
            "extra": {"key": "managed"} if managed else {}}}},
        require_env_writable=lambda *args: None,
        save_env_value=lambda name, value: (tunnel.home / ".env").write_text(
            f"API_SERVER_KEY={value}\nAPI_SERVER_PORT={tunnel.api().port}\n"))
    gateway = types.SimpleNamespace(PROJECT_ROOT=tunnel.home, get_python_path=lambda: "python")
    launchers = types.SimpleNamespace(runtime_command=lambda project, args, **kw: ["hermes", *args])
    modules = {"hermes_cli.config": config, "hermes_cli.gateway": gateway,
               "hermes_cli._launchers": launchers}
    return APIKeyRotation(tunnel.home, load=modules.__getitem__, spawn=restart, **kwargs)


def test_after_full_revoke_old_api_key_gets_401_through_surviving_phone(tmp_path):
    async def scenario():
        tunnel = tunnel_at(tmp_path / "hermes")
        key = ["old-api-key-0123456789"]
        async def api(reader, writer):
            request = await reader.readuntil(b"\r\n\r\n")
            accepted = f"Authorization: Bearer {key[0]}\r\n".encode() in request
            status = b"200 OK" if accepted else b"401 Unauthorized"
            writer.write(b"HTTP/1.1 " + status + b"\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            writer.close()
        server = await asyncio.start_server(api, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        (tunnel.home / ".env").write_text(f"API_SERVER_KEY={key[0]}\nAPI_SERVER_PORT={port}\n")
        def restart(argv, **kwargs):
            assert argv == ["hermes", "gateway", "restart"]
            assert kwargs["stdin"] is not None
            # The injected lifecycle reloads exactly what a restarted Hermes adapter snapshots.
            key[0] = tunnel.api().key
        rotation = rotation_for(tunnel, restart)
        tunnel.rotation = rotation
        tunnel.management._rotate = rotation.start
        listener = tunnel.make_listener(port=0)
        await listener.start()
        a = await paired_phone(tunnel, listener, "A")
        b = await paired_phone(tunnel, listener, "B")
        try:
            local = await b.expose_api()
            old = (await a.request("bootstrap"))["api_key"]
            assert (await http(local, get("/v1/models", old)))[0] == 200
            result = await asyncio.to_thread(tunnel.management.revoke, a.static_public.hex(), rotate=True)
            assert result["removed"] and result["rotation_pending"] and not result["rotated"]
            assert await asyncio.to_thread(rotation.wait, 2)
            assert await b.next_control() == {"event": "credentials.rotated"}
            assert (await http(local, get("/v1/models", old)))[0] == 401
            fresh = (await b.request("bootstrap"))["api_key"]
            assert fresh != old and len(fresh) == 64
            assert (await http(local, get("/v1/models", fresh)))[0] == 200
            await asyncio.wait_for(a.mux.done.wait(), 1)
            assert not b.mux.done.is_set()
        finally:
            await a.close()
            await b.close()
            await listener.stop()
            server.close()
            await server.wait_closed()
    run(scenario())


@pytest.mark.parametrize("platform,expected", [
    ("posix", {"start_new_session": True}), ("nt", {"creationflags": 0x208})])
def test_restart_process_detaches_on_posix_and_windows(platform, expected):
    assert spawn_options(platform) == expected


@pytest.mark.parametrize("managed,wrong_home", [(True, False), (False, True)])
def test_managed_key_or_wrong_profile_refuses_before_writing(tmp_path, managed, wrong_home):
    tunnel = tunnel_at(tmp_path / "hermes")
    path = tunnel.home / ".env"
    path.write_text("API_SERVER_KEY=old-api-key-0123456789\n")
    rotation = rotation_for(tunnel, lambda *a, **kw: pytest.fail("must not restart"),
                            managed=managed, home=tmp_path if wrong_home else None)
    with pytest.raises(ControlError):
        rotation.start()
    assert path.read_text() == "API_SERVER_KEY=old-api-key-0123456789\n"


def test_wait_does_not_claim_success_until_old_key_rejected(tmp_path):
    tunnel = tunnel_at(tmp_path / "hermes")
    (tunnel.home / ".env").write_text("API_SERVER_KEY=old-api-key-0123456789\n")
    ticks = [0]
    def clock():
        ticks[0] += 1
        return ticks[0]
    rotation = rotation_for(tunnel, lambda *a, **kw: None, probe=lambda *a: 200,
                            clock=clock, sleep=lambda _: None)
    assert rotation.start()["rotation_pending"]
    assert not rotation.wait(timeout=2)


def test_configuration_refusal_is_reported_without_operator_exception_text(tmp_path):
    tunnel = tunnel_at(tmp_path / "hermes")
    rotation = APIKeyRotation(tunnel.home, load=lambda _: (_ for _ in ()).throw(
        ValueError("operator credential details")))
    with pytest.raises(ControlError, match="^rotation_key_managed$"):
        rotation.start()


def test_stale_scope_never_advertises_a_retired_key_and_new_operator_authority_wins(tmp_path, monkeypatch):
    from cozychat.relay import services
    tunnel = tunnel_at(tmp_path / "hermes")
    (tunnel.home / ".env").write_text("API_SERVER_KEY=old-api-key-0123456789\n")
    rotation = rotation_for(tunnel, lambda *a, **kw: None)
    rotation.start()
    current = tunnel.api().key
    # A long-lived copy whose scope still holds the retired key must not advertise it.
    monkeypatch.setattr(services, "_profile_secrets", lambda home: {"API_SERVER_KEY": "old-api-key-0123456789"})
    assert discover_api(tunnel.home).key is None
    monkeypatch.setattr(services, "_profile_secrets", lambda home: {"API_SERVER_KEY": "new-operator-authority"})
    assert discover_api(tunnel.home).key == "new-operator-authority"
    assert current != "old-api-key-0123456789"


def test_missing_secret_scope_fails_closed_for_rotation_and_discovery(tmp_path, monkeypatch):
    import sys
    tunnel = tunnel_at(tmp_path / "hermes")
    (tunnel.home / ".env").write_text("API_SERVER_KEY=old-api-key-0123456789\n")
    monkeypatch.setenv("API_SERVER_KEY", "ambient-api-key-0123456789")
    monkeypatch.setitem(sys.modules, "agent.secret_scope", None)
    target = discover_api(tunnel.home)
    assert target.key is None and target.secret_scope_missing
    with pytest.raises(ControlError, match="^rotation_unavailable$"):
        rotation_for(tunnel, lambda *a, **kw: None).start()


def test_rotation_probe_does_not_follow_a_redirect_with_the_key():
    async def scenario():
        seen = []
        async def sink(reader, writer):
            seen.append(await reader.readuntil(b"\r\n\r\n"))
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            writer.close()
        receiver = await asyncio.start_server(sink, "127.0.0.1", 0)
        sink_port = receiver.sockets[0].getsockname()[1]
        async def redirect(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            writer.write(f"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{sink_port}/\r\n"
                         "Content-Length: 0\r\n\r\n".encode())
            await writer.drain()
            writer.close()
        sender = await asyncio.start_server(redirect, "127.0.0.1", 0)
        try:
            assert await asyncio.to_thread(APIKeyRotation._status,
                sender.sockets[0].getsockname()[1], "test-key") == 302
            assert seen == []
        finally:
            for server in (sender, receiver):
                server.close()
                await server.wait_closed()
    run(scenario())


def test_restart_does_not_inherit_the_cached_key(tmp_path, monkeypatch):
    tunnel = tunnel_at(tmp_path / "hermes")
    (tunnel.home / ".env").write_text("API_SERVER_KEY=old-api-key-0123456789\n")
    monkeypatch.setenv("API_SERVER_KEY", "old-api-key-0123456789")
    spawned = []
    rotation = rotation_for(tunnel, lambda argv, **kw: spawned.append(kw["env"]))
    rotation.start()
    assert "API_SERVER_KEY" not in spawned[0]
    assert discover_api(tunnel.home, {"API_SERVER_KEY": "old-api-key-0123456789"}).key == rotation._new


def test_long_lived_copy_refreshes_even_after_more_than_sixteen_rotations(tmp_path):
    tunnel = tunnel_at(tmp_path / "hermes")
    (tunnel.home / ".env").write_text("API_SERVER_KEY=old-api-key-0123456789\n")
    rotation = rotation_for(tunnel, lambda *a, **kw: None, probe=lambda *a: 200)
    for _ in range(18):
        rotation.start()
        assert rotation.ready_generation() is not None
    assert discover_api(tunnel.home, {"API_SERVER_KEY": "old-api-key-0123456789"}).key == rotation._new


def test_failed_restart_spawn_can_be_retried(tmp_path):
    tunnel = tunnel_at(tmp_path / "hermes")
    (tunnel.home / ".env").write_text("API_SERVER_KEY=old-api-key-0123456789\n")
    def fail(*args, **kwargs):
        raise OSError("spawn failed")
    with pytest.raises(OSError):
        rotation_for(tunnel, fail).start()
    spawned = []
    rotation = rotation_for(tunnel, lambda *a, **kw: spawned.append(True))
    assert rotation.start()["rotation_pending"]
    assert spawned == [True]
