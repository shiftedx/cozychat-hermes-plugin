"""Phone management through real Noise sessions; no Hermes gateway or user home."""

import argparse
import asyncio

import pytest

from cozychat.relay import cli, noise, pairing
from cozychat.relay.control import ControlError, PhoneManagement
from cozychat.relay.desktop import PairingPage
from cozychat.relay.mux import SessionClose
from cozychat.relay.pairing import PairingStore
from cozychat.relay.runtime import Tunnel
from tunnel_phone import Phone, loopback_binds


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, 20))


def approve(store, key, name):
    window = store.open_window()
    attempt = store.begin_attempt(window.id, key, name, "123456")
    assert store.decide(attempt, True)
    assert store.settle(attempt) == "approved"


def tunnel_at(home):
    home.mkdir(exist_ok=True)
    return Tunnel(PairingStore(home / "cozychat" / "relay"),
                  config={"relay_url": "https://push.cozylabs.ai"}, home=home,
                  plugin_version="0.6.0", state_version="shared-v1", environ={},
                  interfaces=loopback_binds)


async def paired_phone(tunnel, listener, name):
    private = noise.generate_private_key()
    approve(tunnel.store, noise.public_key(private), name)
    window = tunnel.store.open_window()
    link = pairing.pairing_link(tunnel.store.host_public(), window, listener.hints())
    tunnel.store.cancel_window()
    phone = Phone(link, static_private=private, name=name)
    phone.approved = True
    await phone.connect()
    return phone


def test_desktop_revoke_closes_all_a_live_streams_within_one_second_b_stays_open(tmp_path):
    async def scenario():
        tunnel = tunnel_at(tmp_path / "hermes")
        # An echo stream stays open until revocation; no HTTP response completing the test for us.
        async def echo(reader, writer):
            try:
                while chunk := await reader.read(1024):
                    writer.write(chunk)
                    await writer.drain()
            finally:
                writer.close()
        server = await asyncio.start_server(echo, "127.0.0.1", 0)
        from cozychat.relay.services import ApiTarget
        tunnel.api = lambda: ApiTarget(server.sockets[0].getsockname()[1], "test-key")
        listener = tunnel.make_listener(port=0)
        await listener.start()
        a = await paired_phone(tunnel, listener, "Phone A")
        b = await paired_phone(tunnel, listener, "Phone B")
        a2 = Phone(pairing.pairing_link(tunnel.store.host_public(), tunnel.store.open_window(),
                                      listener.hints()), static_private=a.static_private)
        tunnel.store.cancel_window()
        a2.approved = True
        await a2.connect()
        try:
            streams = [await p.mux.open("api") for p in (a, a2, b)]
            for stream in streams:
                await stream.write(b"still alive")
                assert await stream.read() == b"still alive"
            started = asyncio.get_running_loop().time()
            # Desktop in another process has only the store, no reference to these sessions.
            page = PairingPage(tunnel_at(tunnel.home))
            result = await asyncio.to_thread(page.remove, a.static_public.hex())
            assert result["ok"]
            await asyncio.wait_for(asyncio.gather(a.mux.done.wait(), a2.mux.done.wait()), 1)
            assert asyncio.get_running_loop().time() - started < 1
            assert a.mux.remote_close_code == a2.mux.remote_close_code == SessionClose.REVOKED
            assert streams[0].closed and streams[1].closed
            assert not b.mux.done.is_set() and not streams[2].closed
            await streams[2].write(b"B remains open")
            assert await streams[2].read() == b"B remains open"
            await a.close()
            with pytest.raises((EOFError, ConnectionError)):
                await a.handshake()
        finally:
            await asyncio.gather(*(p.close() for p in (a, a2, b)))
            await listener.stop()
            server.close()
            await server.wait_closed()
    run(scenario())


def test_control_list_push_binding_and_self_revoke(tmp_path):
    async def scenario():
        tunnel = tunnel_at(tmp_path / "hermes")
        listener = tunnel.make_listener(port=0)
        await listener.start()
        a = await paired_phone(tunnel, listener, "Phone A")
        b = await paired_phone(tunnel, listener, "Phone B")
        try:
            phones = (await a.request("phones.list"))["phones"]
            assert [(p["name"], p["is_this_phone"]) for p in phones] == [
                ("Phone A", True), ("Phone B", False)]
            assert all(set(phone) == {"name", "is_this_phone"} for phone in phones)
            device = {"device_id": "push-a", "push_id": "opaque-id", "key_hex": b"push-key".hex()}
            assert (await a.request("device.add", **device))["ok"]
            assert not (await b.request("device.add", **device))["ok"]
            assert not (await b.request("device.remove", device_id="push-a"))["ok"]
            assert (await b.request("device.list"))["devices"] == []
            devices = (await a.request("device.list"))["devices"]
            assert len(devices) == 1 and "key_hex" not in devices[0]
            assert tunnel.management.devices.key("push-a") == b"push-key"
            assert (await a.request("revoke"))["ok"]  # omitted id means this Noise phone
            await asyncio.wait_for(a.mux.done.wait(), 1)
            assert a.mux.remote_close_code == SessionClose.REVOKED
            assert tunnel.management.devices.list() == []
            assert not (tunnel.management.devices.keys_path / "push-a").exists()
            assert (await b.request("phones.list"))["phones"][0]["is_this_phone"]
        finally:
            await a.close()
            await b.close()
            await listener.stop()
    run(scenario())


def test_device_management_honors_no_push_and_rechecks_allowlist(tmp_path):
    tunnel = tunnel_at(tmp_path / "hermes")
    key = noise.public_key(noise.generate_private_key())
    approve(tunnel.store, key, "Phone")
    window = tunnel.store.open_window({"push": False})
    tunnel.store.cancel_window(window.id)
    assert tunnel.capabilities([])["services"]["control"]["device_management"] is True
    assert not tunnel.capabilities([])["features"]["push"]["available"]
    with pytest.raises(ControlError, match="push_unavailable"):
        tunnel.management.answer({"op": "device.add"}, key)
    tunnel.management.revoke(key.hex())
    with pytest.raises(ControlError, match="not_approved"):
        tunnel.management.answer({"op": "phones.list"}, key)


def test_cli_list_revoke_and_rotate_share_management(tmp_path, capsys):
    tunnel = tunnel_at(tmp_path / "hermes")
    key = noise.public_key(noise.generate_private_key())
    approve(tunnel.store, key, "Phone")
    rotations = []
    tunnel.management._rotate = lambda: rotations.append(True)
    parser = argparse.ArgumentParser()
    cli.setup(parser)
    handle = cli.handler(lambda: tunnel)
    assert handle(parser.parse_args(["list"])) == 0
    assert key.hex() in capsys.readouterr().out
    assert handle(parser.parse_args(["revoke", key.hex(), "--rotate"])) == 0
    assert not tunnel.store.is_approved(key) and rotations == [True]
    assert handle(parser.parse_args(["rotate"])) == 0
    assert rotations == [True, True]
    assert handle(parser.parse_args(["revoke", "invalid"])) == 1


@pytest.mark.parametrize("value", [None, "", "00", "GG" * 32, "AA" * 32, 1, []])
def test_invalid_phone_id_is_rejected_without_removing_a_phone(tmp_path, value):
    tunnel = tunnel_at(tmp_path / "hermes")
    key = noise.public_key(noise.generate_private_key())
    approve(tunnel.store, key, "Phone")
    with pytest.raises(ControlError):
        tunnel.management.revoke(value)
    assert tunnel.store.is_approved(key)
