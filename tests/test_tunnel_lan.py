"""The LAN listener's front door: which addresses it binds, and what a stranger gets (T-7, P3, P4)."""

import asyncio
import socket
from collections import namedtuple

import pytest

from cozychat.relay import framing, lan, noise
from cozychat.relay.host import Listener, ListenerConfig
from cozychat.relay.pairing import PairingStore
from cozychat.relay.services import ApiTarget

from tunnel_phone import loopback_binds

Addr = namedtuple("snicaddr", "family address netmask broadcast ptp")
Stats = namedtuple("snicstats", "isup duplex speed mtu flags")
AF_LINK = getattr(socket, "AF_LINK", 18)


def v4(address, netmask="255.255.255.0"):
    return Addr(socket.AF_INET, address, netmask, None, None)


def v6(address, netmask="ffff:ffff:ffff:ffff::"):
    return Addr(socket.AF_INET6, address, netmask, None, None)


def up(isup=True):
    return Stats(isup, 0, 0, 1500, "")


SYNTHETIC = {
    "lo0": [v4("127.0.0.1", "255.0.0.0"), v6("::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            v6("fe80::1%lo0")],
    "en0": [Addr(AF_LINK, "aa:bb:cc:dd:ee:ff", None, None, None), v4("192.168.1.20"),
            v6("fe80::1c2d:3e4f:5a6b:7c8d%en0"), v6("fd12:3456:789a:1::20"),
            v6("2001:db8:1::20")],
    "en1": [v4("203.0.113.5")],                      # a public address on a wired port
    "en5": [v4("100.72.10.4", "255.192.0.0")],       # CGNAT from an LTE modem: shared with strangers
    "utun4": [v4("100.101.102.103", "255.255.255.255")],  # a VPN interface, point to point
    "en9": [v4("100.88.1.2", "255.255.255.255"), v6("fd7a:115c:a1e0::2", "ffff:ffff:ffff:ffff::")],
    "bridge0": [v4("10.0.5.1", "255.255.255.0")],    # down: never bound
    "en7": [v4("0.0.0.0", "0.0.0.0"), v4("172.20.0.9", "255.255.0.0")],
}
STATS = {name: up() for name in SYNTHETIC}
STATS["bridge0"] = up(False)


def chosen():
    return {(b.interface, str(b.address)): b for b in lan.select_bind_addresses(SYNTHETIC, STATS)}


def test_it_binds_private_link_local_and_ula_addresses_on_up_interfaces():
    binds = chosen()
    assert set(binds) == {
        ("en0", "192.168.1.20"), ("en0", "fe80::1c2d:3e4f:5a6b:7c8d"), ("en0", "fd12:3456:789a:1::20"),
        ("utun4", "100.101.102.103"), ("en9", "100.88.1.2"), ("en9", "fd7a:115c:a1e0::2"),
        ("en7", "172.20.0.9"),
    }


def test_it_never_binds_loopback_unspecified_public_or_a_down_interface():
    addresses = {address for _, address in chosen()}
    for refused in ("127.0.0.1", "::1", "0.0.0.0", "203.0.113.5", "2001:db8:1::20", "10.0.5.1"):
        assert refused not in addresses


def test_cgnat_is_bound_only_on_a_vpn_interface():
    addresses = {address for _, address in chosen()}
    assert "100.72.10.4" not in addresses  # en5: an LTE modem's CGNAT, not a VPN
    assert "100.101.102.103" in addresses  # utun4, by name
    assert "100.88.1.2" in addresses       # en9, because it also holds a Tailscale v6 address
    overridden = lan.select_bind_addresses({"en5": SYNTHETIC["en5"]}, {"en5": up()},
                                           vpn_interfaces=["en5"])
    assert [str(b.address) for b in overridden] == ["100.72.10.4"]


def test_a_peer_must_be_inside_the_subnet_of_the_address_it_arrived_on():
    binds = chosen()
    home = binds[("en0", "192.168.1.20")]
    assert home.admits("192.168.1.77")
    assert not home.admits("192.168.2.77")
    assert not home.admits("8.8.8.8")
    assert not home.admits("fd12:3456:789a:1::77")
    vpn = binds[("utun4", "100.101.102.103")]
    # A point-to-point VPN address answers its own range, never the whole world.
    assert vpn.admits("100.64.0.9") and not vpn.admits("100.128.0.1")
    link_local = binds[("en0", "fe80::1c2d:3e4f:5a6b:7c8d")]
    assert link_local.host == "fe80::1c2d:3e4f:5a6b:7c8d%en0"
    assert link_local.admits("fe80::99%en0")


def test_lan_bind_only_narrows_and_never_reaches_loopback_public_or_non_vpn_cgnat():
    """Contract 5.1 holds through ``lan_bind`` too: it picks among the allowed addresses."""
    refused = ["127.0.0.1", "::1", "0.0.0.0", "::", "8.8.8.8", "203.0.113.5", "2001:db8:1::20",
               "100.72.10.4",   # en5's CGNAT, not a VPN interface
               "100.100.1.1",   # CGNAT on no interface at all
               "10.0.5.1",      # private, but its interface is down
               "192.168.1.99",  # private, but not this computer's
               "not an address"]
    assert lan.explicit_bind_addresses(refused, SYNTHETIC, STATS) == []
    picked = lan.explicit_bind_addresses(["192.168.1.20", "100.101.102.103"] + refused,
                                         SYNTHETIC, STATS)
    assert [(b.interface, str(b.address)) for b in picked] == [
        ("en0", "192.168.1.20"), ("utun4", "100.101.102.103")]
    # Same subnet rule as the scan, not a widened one.
    assert picked[0].network == chosen()[("en0", "192.168.1.20")].network


def test_a_netmask_wider_than_the_private_range_is_clamped_to_it():
    wide = {"en0": [v4("10.0.0.5", "0.0.0.0")], "en1": [v4("172.16.0.5", "255.0.0.0")],
            "en2": [v6("fd12::5", "::")]}
    binds = {b.interface: b for b in lan.select_bind_addresses(wide, {n: up() for n in wide})}
    assert binds["en0"].admits("10.9.9.9") and not binds["en0"].admits("8.8.8.8")
    assert binds["en1"].admits("172.31.0.1") and not binds["en1"].admits("172.200.1.1")
    assert binds["en2"].admits("fd99::1") and not binds["en2"].admits("2001:db8::1")


def test_hints_are_ip_port_and_never_link_local_v6():
    binds = chosen()
    assert binds[("en0", "192.168.1.20")].hint(49321) == "192.168.1.20:49321"
    assert binds[("en0", "fd12:3456:789a:1::20")].hint(49321) == "[fd12:3456:789a:1::20]:49321"


@pytest.mark.parametrize("system, release, env, detected", [
    ("Darwin", "24.0.0", {}, False),
    ("Windows", "11", {}, False),
    ("Linux", "6.8.0", {}, False),
    ("Linux", "5.15.153.1-microsoft-standard-WSL2", {}, True),
    ("Linux", "6.6.0", {"WSL_INTEROP": "/run/WSL/1_interop"}, True),
])
def test_wsl_detection_is_platform_specific(system, release, env, detected, monkeypatch):
    from cozychat.relay.platform import is_wsl, pairing_network_note
    assert is_wsl(system=system, release=release, environ=env) is detected
    monkeypatch.setattr("cozychat.relay.platform.is_wsl", lambda: detected)
    notice = pairing_network_note()
    assert bool(notice) is detected
    if notice:
        assert "NAT" in notice and "not reachable" in notice


# -- the front door, live on loopback (ListenerConfig.interfaces is the tests' way in) -----------------------


def run(coro):
    return asyncio.run(coro)


async def started(store, **overrides):
    config = ListenerConfig(port=0, interfaces=loopback_binds, **overrides)
    listener = Listener(store, config, capabilities=lambda hints: {"relay_proto": 1, "reach": hints},
                        api=lambda: ApiTarget(port=1, key="k"))
    await listener.start()
    return listener


async def silent(reader, timeout=3.0):
    """True when the host closed the connection without sending a byte."""
    data = await asyncio.wait_for(reader.read(), timeout)
    return data == b""


def message_1(store, phone_private=None, psk=None):
    phone_private = phone_private or noise.generate_private_key()
    initiator = noise.Initiator(phone_private, store.host_public(), psk or noise.ZERO_PSK)
    return framing.encode(initiator.write_message_1(b'{"phone_name":"Stranger"}'))


def test_with_no_window_an_unknown_key_gets_silence_like_garbage_does(tmp_path):
    """P3: no message 2, no error; the same answer a random message 1 gets."""
    store = PairingStore(tmp_path / "relay")
    store.host_private()

    async def scenario():
        listener = await started(store)
        try:
            for payload in (message_1(store), framing.encode(bytes(96))):
                reader, writer = await asyncio.open_connection("127.0.0.1", listener.port)
                writer.write(payload)
                await writer.drain()
                assert await silent(reader)
                writer.close()
        finally:
            await listener.stop()

    run(scenario())
    assert store.attempt() is None and store.phones() == []


def test_message_1_must_arrive_in_time_and_fit_in_one_kibibyte(tmp_path):
    store = PairingStore(tmp_path / "relay")
    store.open_window()

    async def scenario():
        listener = await started(store, message_1_seconds=0.3)
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", listener.port)
            assert await silent(reader, 2.0)  # said nothing: closed after the deadline
            reader, writer = await asyncio.open_connection("127.0.0.1", listener.port)
            writer.write(framing.LENGTH.pack(framing.PRE_HANDSHAKE_MAX + 1) + bytes(64))
            await writer.drain()
            assert await silent(reader, 2.0)
        finally:
            await listener.stop()

    run(scenario())


def test_half_open_connections_are_capped_per_source(tmp_path):
    """P4: a fifth idle connection from one address is closed at once, while four wait."""
    store = PairingStore(tmp_path / "relay")
    store.open_window()

    async def scenario():
        listener = await started(store, message_1_seconds=3.0)
        held = []
        try:
            for _ in range(4):
                held.append(await asyncio.open_connection("127.0.0.1", listener.port))
            await asyncio.sleep(0.2)
            reader, _ = await asyncio.open_connection("127.0.0.1", listener.port)
            assert await silent(reader, 1.0)
            for held_reader, _ in held:
                with pytest.raises(asyncio.TimeoutError):
                    await asyncio.wait_for(held_reader.read(1), 0.05)
        finally:
            for _, writer in held:
                writer.close()
            await listener.stop()

    run(scenario())


def test_half_open_connections_are_capped_globally(tmp_path):
    store = PairingStore(tmp_path / "relay")
    store.open_window()

    async def scenario():
        listener = await started(store, message_1_seconds=3.0, max_half_open=2,
                                 max_half_open_per_source=10)
        held = []
        try:
            for _ in range(2):
                held.append(await asyncio.open_connection("127.0.0.1", listener.port))
            await asyncio.sleep(0.2)
            reader, _ = await asyncio.open_connection("127.0.0.1", listener.port)
            assert await silent(reader, 1.0)
        finally:
            for _, writer in held:
                writer.close()
            await listener.stop()

    run(scenario())


def test_the_port_is_chosen_once_and_kept(tmp_path):
    store = PairingStore(tmp_path / "relay")
    first = store.port()
    assert 49152 <= first <= 65535
    assert PairingStore(tmp_path / "relay").port() == first
    assert oct((tmp_path / "relay" / "lan.json").stat().st_mode & 0o777) == "0o600"
