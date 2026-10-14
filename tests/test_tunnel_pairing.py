"""Pairing over the real listener: rules P1 to P5, the code, and approval on the computer."""

import asyncio
import io
import json
import stat
import threading
from types import SimpleNamespace

import pytest

from cozychat.relay import cli, noise, pairing
from cozychat.relay.host import Listener, ListenerConfig
from cozychat.relay.mux import SessionClose, StreamClose
from cozychat.relay.pairing import PairingStore
from cozychat.relay.runtime import Tunnel
from cozychat.relay.services import ApiTarget

from tunnel_phone import PHONE_NAME, Phone, loopback_binds


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, 30))


def capabilities(hints):
    return {"relay_proto": 1, "plugin_version": "0.6.0", "reach": {"lan": {"addresses": hints}}}


async def started(store, **overrides):
    listener = Listener(store, ListenerConfig(port=0, interfaces=loopback_binds, **overrides),
                        capabilities=capabilities, api=lambda: ApiTarget(port=1, key="api-key"))
    await listener.start()
    return listener


def link_for(store, listener, window):
    return pairing.pairing_link(store.host_public(), window, listener.hints())


async def wait_for(predicate, timeout=5.0):
    deadline = asyncio.get_running_loop().time() + timeout
    while not await asyncio.to_thread(predicate):
        assert asyncio.get_running_loop().time() < deadline, "timed out"
        await asyncio.sleep(0.05)


def test_the_store_keeps_secrets_0600_in_a_0700_directory(tmp_path):
    """P5, host side."""
    store = PairingStore(tmp_path / "cozychat" / "relay")
    store.open_window({"push": True})
    for name in ("host.key", "pairing.json"):
        assert stat.S_IMODE((store.root / name).stat().st_mode) == 0o600
    assert stat.S_IMODE(store.root.stat().st_mode) == 0o700
    assert stat.S_IMODE(store.root.parent.stat().st_mode) == 0o700


def test_the_window_lasts_ten_minutes_on_the_hosts_clock(tmp_path):
    now = [1_000_000.0]
    store = PairingStore(tmp_path / "relay", clock=lambda: now[0])
    window = store.open_window()
    assert window.exp == 1_000_600
    now[0] = 1_000_599.0
    assert store.window() == window
    now[0] = 1_000_600.0
    assert store.window() is None


def test_the_link_carries_the_pin_the_secret_and_the_hints_and_never_a_credential(tmp_path):
    store = PairingStore(tmp_path / "relay")
    window = store.open_window()
    link = pairing.pairing_link(store.host_public(), window, ["192.168.1.20:49321"])
    body = pairing.decode_link(link)
    assert link.startswith("cozychat://pair-relay?d=") and "=" not in link.split("?d=")[1]
    assert body == {"v": 1, "host": store.host_public().hex(), "psk": window.psk.hex(),
                    "exp": window.exp, "lan": ["192.168.1.20:49321"]}
    with pytest.raises(ValueError):
        pairing.pairing_link(store.host_public(), window, [])
    with_relay = pairing.decode_link(pairing.pairing_link(
        store.host_public(), window, ["192.168.1.20:49321"], "wss://relay.example.net"))
    assert with_relay["relay"] == "wss://relay.example.net"


@pytest.mark.parametrize("sent, shown", [
    pytest.param("", "Phone", id="empty"),
    pytest.param("   ", "Phone", id="whitespace"),
    pytest.param("Kim\x1b[2K\rPhone", "Kim[2K Phone", id="terminal_escape"),
    pytest.param("\u202eenohP s'miK", "enohP s'miK", id="bidi_override"),
    pytest.param("\u00e9" * 32, "\u00e9" * 32, id="exactly_64_bytes"),
    pytest.param(" Kyle\u2019s iPhone ", "Kyle\u2019s iPhone", id="padded"),
])
def test_the_code_covers_the_exact_name_sent_and_only_the_display_is_cleaned(tmp_path, sent, shown):
    """R1: the code is over the phone's exact bytes; fallback, trimming and stripping are display
    only, so a phone sending an empty, 64-byte or odd name still sees the computer's code."""
    store = PairingStore(tmp_path / "relay")
    window = store.open_window()

    async def scenario():
        listener = await started(store)
        phone = Phone(link_for(store, listener, window), name=sent)
        try:
            await phone.handshake()
            await phone.open_control()
            await wait_for(lambda: store.attempt() is not None)
            attempt = store.attempt()
            assert attempt.code == phone.code
            assert attempt.code == noise.pairing_code(phone.session.handshake_hash,
                                                      sent.encode("utf-8"))
            assert attempt.phone_name == shown
        finally:
            await phone.close()
            await listener.stop()

    run(scenario())


@pytest.mark.parametrize("hello", [
    pytest.param({"phone_name": "\u00e9" * 32 + "a", "app": "1.0.5", "relay_proto": [1, 1]},
                 id="65_bytes"),
    pytest.param({"phone_name": "x" * 200, "app": "1.0.5", "relay_proto": [1, 1]}, id="200_bytes"),
    pytest.param({"app": "1.0.5", "relay_proto": [1, 1]}, id="missing"),
    pytest.param({"phone_name": 7, "app": "1.0.5", "relay_proto": [1, 1]}, id="not_a_string"),
    pytest.param({"phone_name": None, "app": "1.0.5", "relay_proto": [1, 1]}, id="null"),
    pytest.param(b'{"phone_name": "\\ud800", "app": "1.0.5", "relay_proto": [1, 1]}',
                 id="lone_surrogate"),
    pytest.param(b"not json", id="not_json"),
])
def test_a_message_1_with_a_bad_phone_name_is_dropped_silently(tmp_path, hello):
    """Contract section 2: over 64 UTF-8 bytes, missing or not a string, message 1 gets no message 2
    and the window is untouched (P2, P3). The host never truncates a name for the phone."""
    store = PairingStore(tmp_path / "relay")
    window = store.open_window()
    before = json.loads((store.root / "pairing.json").read_text())
    payload = hello if isinstance(hello, bytes) else json.dumps(hello).encode("utf-8")

    async def scenario():
        listener = await started(store)
        phone = Phone(link_for(store, listener, window))
        try:
            with pytest.raises(EOFError):
                await phone.handshake(hello=payload)
        finally:
            phone.writer.close()
            await listener.stop()

    run(scenario())
    assert store.window() == window
    assert json.loads((store.root / "pairing.json").read_text()) == before
    assert store.attempt() is None and store.phones() == []


def test_an_approved_phone_with_an_overlong_name_is_dropped_too(tmp_path):
    store = PairingStore(tmp_path / "relay")
    window = store.open_window()

    async def scenario():
        listener = await started(store)
        phone = Phone(link_for(store, listener, window))
        try:
            await phone.connect()
            await wait_for(lambda: store.attempt() is not None)
            store.decide(store.attempt().id, approve=True)
            await phone.next_control()
            await phone.close()
            assert store.is_approved(phone.static_public)
            phone.name = "x" * 65
            with pytest.raises(EOFError):
                await phone.handshake()
        finally:
            await phone.close()
            await listener.stop()

    run(scenario())


def test_approval_waits_for_a_valid_frame_and_for_the_person(tmp_path):
    """P1: nothing is offered on message 1; the key joins only after a frame AND approval."""
    store = PairingStore(tmp_path / "relay")
    window = store.open_window()

    async def scenario():
        listener = await started(store)
        phone = Phone(link_for(store, listener, window))
        try:
            payload = await phone.handshake()
            assert payload == {"relay_proto": 1, "pairing": True}  # P3: minimal, inside a window
            await asyncio.sleep(0.3)
            assert store.attempt() is None  # message 1 alone proves nothing (P1 a)

            await phone.open_control()
            await wait_for(lambda: store.attempt() is not None)
            attempt = store.attempt()
            assert attempt.code == phone.code and len(attempt.code) == 6
            assert attempt.phone_name == phone.name
            assert not store.is_approved(phone.static_public)  # not without the person (P1 b)

            # Before approval only control exists, and it will not hand out anything.
            assert (await phone.request("info"))["error"] == "not_approved"
            assert (await phone.request("bootstrap"))["error"] == "not_approved"
            api = await phone.mux.open("api")
            assert await api.read() == b"" and api.close_code == StreamClose.POLICY

            assert store.decide(attempt.id, approve=True)
            assert await phone.next_control() == {"event": "pairing.approved"}
            assert phone.approved
            assert store.is_approved(phone.static_public)
            assert store.window() is None  # the psk is consumed with the window

            info = await phone.request("info")
            assert info["ok"] and info["capabilities"]["relay_proto"] == 1
            bootstrap = await phone.request("bootstrap")
            assert bootstrap["ok"] and bootstrap["api_key"] == "api-key"
        finally:
            await phone.close()
            await listener.stop()

    run(scenario())


def test_a_wrong_psk_fails_quietly_and_leaves_the_window_as_it_was(tmp_path):
    """P2: the attempt is dropped; the window's psk and expiry are unchanged."""
    store = PairingStore(tmp_path / "relay")
    window = store.open_window()
    before = json.loads((store.root / "pairing.json").read_text())

    async def scenario():
        listener = await started(store)
        intruder = Phone(link_for(store, listener, window), name="Intruder")
        try:
            with pytest.raises(noise.NoiseError):
                await intruder.handshake(psk=bytes(range(32)))
            # Its first frame cannot decrypt either: the host drops it without a word.
            intruder.writer.write(b"\x00\x00\x00\x20" + bytes(32))
            await intruder.writer.drain()
            assert await asyncio.wait_for(intruder.reader.read(), 3) == b""
        finally:
            intruder.writer.close()
            await listener.stop()

    run(scenario())
    assert store.window() == window
    assert json.loads((store.root / "pairing.json").read_text()) == before
    assert store.attempt() is None and store.phones() == []


def test_refusing_ends_the_session_with_code_7(tmp_path):
    store = PairingStore(tmp_path / "relay")
    window = store.open_window()

    async def scenario():
        listener = await started(store)
        phone = Phone(link_for(store, listener, window))
        try:
            await phone.connect()
            await wait_for(lambda: store.attempt() is not None)
            store.decide(store.attempt().id, approve=False)
            await asyncio.wait_for(phone.mux.done.wait(), 5)
            assert phone.mux.remote_close_code == SessionClose.PAIRING_ENDED
            assert not phone.approved
        finally:
            await phone.close()
            await listener.stop()

    run(scenario())
    assert store.phones() == []


def test_one_phone_waits_at_a_time(tmp_path):
    store = PairingStore(tmp_path / "relay")
    window = store.open_window()

    async def scenario():
        listener = await started(store)
        first = Phone(link_for(store, listener, window), name="First")
        second = Phone(link_for(store, listener, window), name="Second")
        try:
            await first.connect()
            await wait_for(lambda: store.attempt() is not None)
            await second.connect()
            await asyncio.wait_for(second.mux.done.wait(), 5)
            assert second.mux.remote_close_code == SessionClose.PAIRING_ENDED
            assert store.attempt().phone_name == "First"
        finally:
            await first.close()
            await second.close()
            await listener.stop()

    run(scenario())


def test_removing_a_phone_ends_its_live_session_with_code_2(tmp_path):
    """Contract section 8: an open session does not outlive the phone's allowlist entry."""
    store = PairingStore(tmp_path / "relay")
    window = store.open_window()

    async def scenario():
        listener = await started(store, allowlist_poll_seconds=0.05)
        phone = Phone(link_for(store, listener, window))
        try:
            await phone.handshake()
            await phone.open_control()
            await wait_for(lambda: store.attempt() is not None)
            store.decide(store.attempt().id, approve=True)
            assert await phone.next_control() == {"event": "pairing.approved"}
            assert (await phone.request("bootstrap"))["ok"]

            store.remove_phone(phone.static_public)
            await asyncio.wait_for(phone.mux.done.wait(), 5)
            assert phone.mux.remote_close_code == SessionClose.REVOKED
        finally:
            await phone.close()
            await listener.stop()

    run(scenario())


def test_a_phone_that_leaves_before_approval_does_not_burn_the_window(tmp_path):
    store = PairingStore(tmp_path / "relay")
    window = store.open_window()

    async def scenario():
        listener = await started(store)
        phone = Phone(link_for(store, listener, window))
        try:
            await phone.connect()
            await wait_for(lambda: store.attempt() is not None)
            await phone.close()
            await wait_for(lambda: store.attempt() is None)
        finally:
            await listener.stop()

    run(scenario())
    assert store.window() == window


def test_an_approved_phone_reconnects_with_the_zero_psk_and_gets_the_capabilities(tmp_path):
    store = PairingStore(tmp_path / "relay")
    window = store.open_window()

    async def scenario():
        listener = await started(store)
        phone = Phone(link_for(store, listener, window))
        try:
            await phone.connect()
            await wait_for(lambda: store.attempt() is not None)
            store.decide(store.attempt().id, approve=True)
            await phone.next_control()
            await phone.close()

            assert store.window() is None  # a reconnect needs no window
            payload = await phone.handshake()
            assert payload["relay_proto"] == 1
            assert payload["reach"]["lan"]["addresses"] == listener.hints()
            await phone.open_control()
            assert (await phone.request("info"))["ok"]

            # Removed from the allowlist, it is a stranger again: silence (P3).
            store.remove_phone(phone.static_public)
            with pytest.raises(EOFError):
                await phone.handshake()
        finally:
            await phone.close()
            await listener.stop()

    run(scenario())


def test_the_pair_command_prints_the_link_and_approves_with_enter(tmp_path, monkeypatch):
    """`hermes cozychat pair`, driven end to end with a stand-in phone and a scripted Enter."""
    store = PairingStore(tmp_path / "cozychat" / "relay")
    tunnel = Tunnel(store, config={"lan": True, "lan_port": 0,
                                   "relay_url": "https://push.cozylabs.ai"},
                    plugin_version="0.6.0", state_version="shared-v1", home=tmp_path,
                    environ={"API_SERVER_KEY": "api-key", "API_SERVER_PORT": "18642"},
                    interfaces=loopback_binds)
    out = io.StringIO()
    prompts = []
    result = {}
    # Gateway setup/readiness is exercised with authenticated HTTP in test_reachable; this
    # scenario owns the real listener/phone/Enter exchange without starting a Hermes process.
    monkeypatch.setattr(cli, "Gateway", lambda *args: SimpleNamespace(ensure=lambda: None))

    def answer(question):
        prompts.append(question)
        return ""

    def command():
        result["status"] = cli.pair(tunnel, advertise=["100.101.102.103:49321"], push=False,
                                    relay=None, prompt=answer, out=out, owner_tick=0.1)

    thread = threading.Thread(target=command)
    thread.start()

    async def phone_side():
        await wait_for(lambda: "cozychat://pair-relay?d=" in out.getvalue())
        link = next(line for line in out.getvalue().splitlines()
                    if line.startswith("cozychat://pair-relay?d="))
        body = pairing.decode_link(link)
        assert body["lan"][0] == "100.101.102.103:49321"  # --advertise leads the hints
        phone = Phone(link)
        phone.link["lan"] = body["lan"][1:]  # the stand-in reaches the listener on loopback
        try:
            await phone.connect()
            assert await phone.next_control(10) == {"event": "pairing.approved"}
            info = await phone.request("info")
            assert info["capabilities"]["features"]["push"]["available"] is False  # no push-device service in this transport-only fixture
            return phone.code
        finally:
            await phone.close()

    code = run(phone_side())
    thread.join(15)
    assert result["status"] == 0
    assert prompts == [f'Pair "{PHONE_NAME}"? code {code[:3]} {code[3:]}. '
                       "Press Enter to approve, anything else to refuse. "]
    assert "Paired" in out.getvalue()
    assert len(store.phones()) == 1


def test_the_pair_command_refuses_bad_flags_and_a_disabled_listener(tmp_path):
    store = PairingStore(tmp_path / "relay")
    out = io.StringIO()
    tunnel = Tunnel(store, config={"lan": True}, plugin_version="x", state_version="y",
                    home=tmp_path, environ={})
    assert cli.pair(tunnel, advertise=["no-port"], push=True, relay=None, out=out) == 2
    assert cli.pair(tunnel, advertise=[], push=True, relay="ws://relay.example.net",
                    out=out) == 2
    off = Tunnel(store, config={"lan": True}, plugin_version="x", state_version="y",
                 home=tmp_path, environ={"COZYCHAT_LAN": "0"})
    assert cli.pair(off, advertise=[], push=True, relay=None, out=out) == 1
    assert store.window() is None
