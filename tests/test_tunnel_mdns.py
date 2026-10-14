"""Discovery discloses only the contract tag and listens only on bound interfaces."""

import asyncio
import hashlib
import hmac
import ipaddress
import sys
from types import SimpleNamespace

import pytest

from cozychat.relay import lan, mdns, noise, pairing, runtime
from cozychat.relay.desktop import PairingPage
from cozychat.relay.reachable import Reachable
from test_desktop_pairing import FakeGateway, FakeService
from tunnel_phone import Phone, loopback_binds


def binds():
    return [lan.BindAddress("Ethernet", ipaddress.ip_address("192.168.1.20"),
                            ipaddress.ip_network("192.168.1.0/24")),
            lan.BindAddress("Ethernet", ipaddress.ip_address("fe80::20"),
                            ipaddress.ip_network("fe80::/64"), "Ethernet"),
            lan.BindAddress("tailscale0", ipaddress.ip_address("100.64.0.2"),
                            ipaddress.ip_network("100.64.0.0/10"))]


@pytest.fixture
def stacks(monkeypatch):
    created = []

    class Stack:
        def __init__(self, **kwargs):
            self.interfaces = kwargs["interfaces"]
            self.info = None
            self.closed = False
            created.append(self)

        async def async_register_service(self, info, **kwargs):
            self.info = info

            async def announced():
                pass
            return announced()

        async def async_close(self):
            self.closed = True

    monkeypatch.setitem(sys.modules, "zeroconf", SimpleNamespace(
        ServiceInfo=lambda type_, name, **kwargs: SimpleNamespace(type=type_, name=name, **kwargs)))
    monkeypatch.setitem(sys.modules, "zeroconf.asyncio", SimpleNamespace(AsyncZeroconf=Stack))
    monkeypatch.setattr(mdns.socket, "if_nametoindex", lambda name: 7)
    return created


def test_tag_and_instance_match_the_contract_and_disclose_no_friendly_name():
    public = noise.public_key(bytes(range(32)))
    expected = hmac.new(public, b"cozychat-mdns-v1", hashlib.sha256).digest()[:8].hex()
    assert mdns.tag(public) == expected
    assert mdns.instance_name(public) == f"CozyChat-{expected[:4]}._cozychat._tcp.local."
    assert expected != hashlib.sha256(public).digest()[:8].hex()


def test_only_bound_addresses_are_announced_on_their_own_interfaces(stacks):
    public = noise.public_key(bytes(range(32)))

    async def scenario():
        advertiser = mdns.Advertiser(public)
        await advertiser.update(binds(), 49321)
        assert advertiser.advertising
        assert len(stacks) == 2
        assert stacks[0].interfaces == ["192.168.1.20", (("fe80::20", 0, 7), 7)]
        assert stacks[1].interfaces == ["100.64.0.2"]
        for stack, addresses in zip(stacks, (binds()[:2], binds()[2:])):
            assert stack.info.addresses == [b.address.packed for b in addresses]
            assert stack.info.port == 49321
            assert stack.info.properties == {"v": "1", "h": mdns.tag(public)}
        await advertiser.update(binds(), 49321)
        assert len(stacks) == 2  # no repeated registration
        await advertiser.update(binds()[2:], 49321)
        assert stacks[0].closed and not stacks[1].closed
        await advertiser.stop()
        assert all(stack.closed for stack in stacks) and not advertiser.advertising

    asyncio.run(scenario())


def test_opt_out_and_failed_multicast_keep_the_listener_and_hints(monkeypatch, tmp_path):
    monkeypatch.setitem(sys.modules, "zeroconf", None)
    store = pairing.PairingStore(tmp_path / "relay")
    window = store.open_window()
    tunnel = runtime.Tunnel(store, config={"lan_advertise": False}, plugin_version="0.6.0",
                            state_version="shared-v1", home=tmp_path, interfaces=loopback_binds)
    assert not tunnel.listener_config().advertise_mdns

    async def scenario():
        # Check the optional import on private synthetic interfaces without sending multicast.
        advertiser = mdns.Advertiser(store.host_public())
        await advertiser.update(binds(), 49321)
        assert not advertiser.advertising
        listener = tunnel.make_listener(port=0)
        await listener.start()
        phone = Phone(pairing.pairing_link(store.host_public(), window, listener.hints()))
        try:
            await phone.connect()
            while store.attempt() is None:
                await asyncio.sleep(0.01)
            assert store.decide(store.attempt().id, True)
            assert await phone.next_control() == {"event": "pairing.approved"}
            info = await phone.request("info")
            assert info["capabilities"]["reach"]["lan"] == {
                "addresses": listener.hints(), "advertising": False}
        finally:
            await phone.close()
            await listener.stop()

    asyncio.run(scenario())


def test_advertiser_failure_is_contained(monkeypatch, stacks):
    async def broken(self, *args, **kwargs):
        raise OSError("multicast blocked")

    # Obtain the test backend without creating an actual zeroconf socket.
    monkeypatch.setattr(sys.modules["zeroconf.asyncio"].AsyncZeroconf,
                        "async_register_service", broken)

    async def scenario():
        advertiser = mdns.Advertiser(bytes(32))
        await advertiser.update(binds(), 49321)
        assert not advertiser.advertising
        assert len(stacks) == 2 and all(stack.closed for stack in stacks)

    asyncio.run(scenario())


def test_cancelled_registration_closes_its_multicast_stack(monkeypatch, stacks):
    entered = asyncio.Event()

    async def waiting(self, *args, **kwargs):
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(sys.modules["zeroconf.asyncio"].AsyncZeroconf,
                        "async_register_service", waiting)

    async def scenario():
        advertiser = mdns.Advertiser(bytes(32))
        update = asyncio.ensure_future(advertiser.update(binds(), 49321))
        await entered.wait()
        update.cancel()
        await asyncio.gather(update, return_exceptions=True)
        assert len(stacks) == 2 and all(stack.closed for stack in stacks)
        assert not advertiser.advertising

    asyncio.run(scenario())


def test_interface_registration_and_withdrawal_run_concurrently(monkeypatch, stacks):
    entered = set()

    async def register(self, info, **kwargs):
        self.info = info
        entered.add(tuple(self.interfaces))
        # Neither registration can complete until the other has started.
        while len(entered) < 2:
            await asyncio.sleep(0)

        async def announced():
            pass
        return announced()

    closing = set()

    async def close(self):
        closing.add(tuple(self.interfaces))
        while len(closing) < 2:
            await asyncio.sleep(0)
        self.closed = True

    backend = sys.modules["zeroconf.asyncio"].AsyncZeroconf
    monkeypatch.setattr(backend, "async_register_service", register)
    monkeypatch.setattr(backend, "async_close", close)

    async def scenario():
        advertiser = mdns.Advertiser(bytes(32))
        await asyncio.wait_for(advertiser.update(binds(), 49321), 2)
        assert len(stacks) == 2 and advertiser.advertising
        await asyncio.wait_for(advertiser.stop(), 2)
        assert all(stack.closed for stack in stacks)

    asyncio.run(scenario())


def test_disabled_lan_has_no_reach_capability(tmp_path):
    tunnel = runtime.Tunnel(pairing.PairingStore(tmp_path / "relay"), config={"lan": False},
                            plugin_version="0.6.0", state_version="shared-v1", home=tmp_path)
    assert tunnel.capabilities([])["reach"]["lan"] is None


def test_real_zeroconf_discovers_the_listener_on_a_private_interface(tmp_path):
    from zeroconf.asyncio import AsyncServiceInfo, AsyncZeroconf

    available = [b for b in lan.system_bind_addresses() if b.address.version == 4]
    if not available:
        pytest.skip("no private IPv4 interface for a real multicast discovery check")
    bind = available[0]
    store = pairing.PairingStore(tmp_path / "relay")
    tunnel = runtime.Tunnel(store, config={"lan_bind": [str(bind.address)]}, plugin_version="0.6.0",
                            state_version="shared-v1", home=tmp_path)
    page = PairingPage(tunnel, reachable=Reachable(store, FakeService()), gateway=FakeGateway(),
                       network_note=lambda: None)
    owner = tunnel.owner().start()
    page._wake = owner.tick

    async def scenario():
        listener = owner.listener
        browser = phone = None
        try:
            assert listener.binds == [bind]
            assert listener.capabilities()["reach"]["lan"]["advertising"]
            browser = AsyncZeroconf(interfaces=[str(bind.address)])
            info = AsyncServiceInfo(mdns.SERVICE_TYPE, mdns.instance_name(store.host_public()))
            assert await info.async_request(browser.zeroconf, 3000)
            assert info.port == listener.port
            assert info.properties == {b"v": b"1", b"h": mdns.tag(store.host_public()).encode()}
            assert info.parsed_addresses() == [str(bind.address)]
            qr = page.qr()
            payload = pairing.decode_link(qr["link"])
            assert payload["host"] == store.host_public().hex()
            assert payload["lan"] == listener.hints() == [bind.hint(info.port)]
            assert (listener.config.max_half_open, listener.config.max_half_open_per_source,
                    listener.config.max_sessions) == (16, 4, 8)
            phone = Phone(qr["link"])
            await phone.connect()
            while store.attempt() is None:
                await asyncio.sleep(0.01)
            pending = page.state()["pending"]
            assert pending["code"] == phone.code
            assert page.decide(pending["id"], True)["ok"]
            assert await phone.next_control() == {"event": "pairing.approved"}
            capabilities = (await phone.request("info"))["capabilities"]
            assert capabilities["reach"]["lan"] == {
                "addresses": payload["lan"], "advertising": True}
            assert capabilities["relay_proto"] == 1 and capabilities["plugin_version"] == "0.6.0"
        finally:
            if phone is not None:
                await phone.close()
            if browser is not None:
                await browser.async_close()
    try:
        page.open(automatic=True)
        asyncio.run(asyncio.wait_for(scenario(), 15))
    finally:
        owner.stop()
