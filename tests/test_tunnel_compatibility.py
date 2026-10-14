"""T13's host half through a real listener, with the tests-only loopback bind seam."""

import asyncio
import json
from pathlib import Path
import re

import pytest

import cozychat
from cozychat.relay import compatibility, framing, pairing, services
from cozychat.relay.host import Listener, ListenerConfig
from cozychat.relay.mux import CLOSE, OPEN, SessionClose, close_payload, decode_frame, encode_frame
from cozychat.relay.pairing import PairingStore

from tunnel_phone import Phone, loopback_binds


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, 10))


async def started(store, monkeypatch, version="0.6.0"):
    dispatched = []

    async def serve(mux, stream, context):
        dispatched.append(stream.service)

    monkeypatch.setattr(services, "serve", serve)
    listener = Listener(store, ListenerConfig(port=0, interfaces=loopback_binds),
                        capabilities=lambda hints: services.capability_document(
                            plugin_version=version, state_version="shared-v1", lan_addresses=hints,
                            push_available=False, push_paired=False),
                        api=lambda: services.ApiTarget(port=1, key="must-not-be-released"))
    await listener.start()
    return listener, dispatched


def hello(versions):
    return json.dumps({"phone_name": "iPhone", "app": "1.0.5", "relay_proto": versions,
                       "future_field": True}).encode()


def phone_for(store, listener, window):
    return Phone(pairing.pairing_link(store.host_public(), window, listener.hints()))


@pytest.mark.parametrize("versions", [[1, 1], [1, 2], [1, 99]])
def test_supported_inclusive_ranges_and_unknown_fields(versions):
    assert compatibility.peer_protocol_range(hello(versions)) == tuple(versions)


@pytest.mark.parametrize("versions", [None, 1, "1", [], [1], [1, 1, 1], [2, 1], [0, 1],
                                      [-1, 1], [True, 1], [1, False], [1.0, 1], ["1", 1]])
def test_malformed_protocol_range_is_silent_and_keeps_the_window(tmp_path, monkeypatch, versions):
    store = PairingStore(tmp_path / "relay")
    window = store.open_window()

    async def scenario():
        listener, dispatched = await started(store, monkeypatch)
        phone = phone_for(store, listener, window)
        try:
            with pytest.raises(EOFError):
                await phone.handshake(hello=hello(versions))
            assert dispatched == []
        finally:
            phone.writer.close()
            await listener.stop()

    run(scenario())
    assert store.window() == window and store.attempt() is None and store.phones() == []


@pytest.mark.parametrize("approved", [False, True])
def test_incompatible_peer_gets_encrypted_close_3_and_opens_no_stream(tmp_path, monkeypatch, approved):
    store = PairingStore(tmp_path / "relay")
    window = store.open_window()

    async def scenario():
        listener, dispatched = await started(store, monkeypatch)
        phone = phone_for(store, listener, window)
        if approved:
            attempt = store.begin_attempt(window.id, phone.static_public, phone.name, "000000")
            assert store.decide(attempt, True) and store.settle(attempt) == "approved"
            phone.approved = True
        before = (store.root / "pairing.json").read_bytes()
        try:
            payload = await phone.handshake(hello=hello([2, 2]))
            if approved:
                assert payload["relay_proto"] == 1 and payload["plugin_version"] == "0.6.0"
            else:
                assert payload == {"relay_proto": 1, "pairing": True}
            # Even a peer that ignores the advertisement and tries API cannot dispatch a service.
            phone.writer.write(framing.encode(phone.session.encrypt(encode_frame(OPEN, 1, b"api"))))
            await phone.writer.drain()
            response = await framing.read_message(phone.reader, framing.TRANSPORT_MAX)
            assert decode_frame(phone.session.decrypt(response)) == (
                CLOSE, 0, close_payload(SessionClose.PROTO_UNSUPPORTED))
            assert await phone.reader.read() == b""
            assert dispatched == [] and store.attempt() is None
            assert (store.root / "pairing.json").read_bytes() == before
        finally:
            await phone.close()
            await listener.stop()

    run(scenario())


def test_unknown_incompatible_peer_outside_window_gets_no_version_oracle(tmp_path, monkeypatch):
    store = PairingStore(tmp_path / "relay")
    window = store.open_window()
    store.cancel_window()

    async def scenario():
        listener, dispatched = await started(store, monkeypatch)
        phone = phone_for(store, listener, window)
        try:
            with pytest.raises(EOFError):
                await phone.handshake(hello=hello([2, 2]))
            assert dispatched == []
        finally:
            phone.writer.close()
            await listener.stop()

    run(scenario())
    assert store.phones() == [] and store.attempt() is None


@pytest.mark.parametrize("code", [SessionClose.PROTO_UNSUPPORTED, SessionClose.PLUGIN_TOO_OLD])
@pytest.mark.parametrize("approved", [False, True])
def test_phone_version_rejection_before_open_keeps_pairing_state(tmp_path, monkeypatch, code, approved):
    store = PairingStore(tmp_path / "relay")
    window = store.open_window()

    async def scenario():
        listener, dispatched = await started(store, monkeypatch, version="0.5.6")
        phone = phone_for(store, listener, window)
        if approved:
            attempt = store.begin_attempt(window.id, phone.static_public, phone.name, "000000")
            assert store.decide(attempt, True) and store.settle(attempt) == "approved"
            phone.approved = True
        before = (store.root / "pairing.json").read_bytes()
        try:
            payload = await phone.handshake()
            if approved:
                assert payload["plugin_version"] == "0.5.6"
            else:
                assert payload == {"relay_proto": 1, "pairing": True}
            phone.writer.write(framing.encode(phone.session.encrypt(
                encode_frame(CLOSE, 0, close_payload(code)))))
            await phone.writer.drain()
            assert await phone.reader.read() == b""
            assert dispatched == [] and store.attempt() is None
            assert (store.root / "pairing.json").read_bytes() == before
        finally:
            await phone.close()
            await listener.stop()

    run(scenario())


def test_capability_and_dashboard_advertise_actual_manifest_version(plugin_app):
    capabilities = services.capability_document(
        plugin_version=cozychat.VERSION, state_version="shared-v1", lan_addresses=[],
        push_available=False, push_paired=False)
    assert capabilities["relay_proto"] == cozychat.RELAY_PROTO == 1
    manifest = (Path(cozychat.__file__).parent / "plugin.yaml").read_text()
    assert capabilities["plugin_version"] == re.search(r"^version: (.+)$", manifest, re.M)[1]
    client, package, _ = plugin_app
    package.VERSION, package.RELAY_PROTO = cozychat.VERSION, cozychat.RELAY_PROTO
    payload = client.get("/api/plugins/cozychat/info").json()
    assert payload["plugin_version"] == payload["version"] == cozychat.VERSION
    assert payload["relay_proto"] == 1
