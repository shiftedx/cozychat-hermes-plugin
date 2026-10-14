"""Which addresses the listener may bind, and which peers it may answer (contract section 5.1).

Private ranges only: ``10/8``, ``172.16/12``, ``192.168/16``, ``169.254/16``, ``fe80::/10`` and
``fc00::/7`` on any interface that is up. ``100.64.0.0/10`` only on a VPN-type interface, detected
by interface and not by range: carrier-grade NAT, Starlink, USB and LTE modems and some hotel and
campus networks hand out the same range, and there it is shared with strangers. Never ``0.0.0.0``,
``::``, loopback (the Hermes API itself lives there), multicast or a public address.

Interfaces come from cross-platform ``psutil``, declared in the plugin requirements. Everything takes the
``net_if_addrs()`` / ``net_if_stats()`` shapes as plain arguments so tests hand in synthetic ones.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from dataclasses import dataclass
from typing import Any, Iterable, List, Mapping, Optional, Sequence, Union

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

PRIVATE = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fe80::/10", "fc00::/7"))
CGNAT = ipaddress.ip_network("100.64.0.0/10")
# Tailscale's IPv6 range; an interface holding one is a VPN interface whatever it is called.
TAILSCALE_V6 = ipaddress.ip_network("fd7a:115c:a1e0::/48")
VPN_PREFIXES = ("utun", "tailscale", "wg", "tun")
logger = logging.getLogger("hermes_cli.plugins.cozychat")


@dataclass(frozen=True)
class BindAddress:
    interface: str
    address: IPAddress
    # The peers this bind answers. The interface's own subnet, or the private range the address
    # sits in when the interface is point-to-point (a /32 or /128, as VPN interfaces usually are).
    network: IPNetwork
    scope: Optional[str] = None

    @property
    def host(self) -> str:
        """The string ``asyncio.start_server`` binds."""
        text = str(self.address)
        return f"{text}%{self.scope}" if self.scope else text

    def hint(self, port: int) -> str:
        """``ip:port`` or ``[ipv6]:port`` for the pairing link. Link-local v6 is never a hint."""
        if self.address.version == 6:
            return f"[{self.address}]:{port}"
        return f"{self.address}:{port}"

    def admits(self, peer: str) -> bool:
        address = _parse(peer)
        return address is not None and address.version == self.address.version \
            and address in self.network


def is_vpn_interface(name: str, addresses: Iterable[Any] = (),
                     overrides: Sequence[str] = ()) -> bool:
    if name in overrides or name.lower().startswith(VPN_PREFIXES):
        return True
    for entry in addresses:
        address = _parse(getattr(entry, "address", ""))
        if address is not None and address.version == 6 and address in TAILSCALE_V6:
            return True
    return False


def select_bind_addresses(if_addrs: Mapping[str, Sequence[Any]],
                          if_stats: Mapping[str, Any], *,
                          vpn_interfaces: Sequence[str] = ()) -> List[BindAddress]:
    """Every address on an up interface that the rules above allow, in a stable order."""
    chosen: List[BindAddress] = []
    for name in sorted(if_addrs):
        stats = if_stats.get(name)
        if stats is None or not getattr(stats, "isup", False):
            continue
        flags = str(getattr(stats, "flags", "")).lower()
        if "loopback" in flags or name.lower() in ("lo", "lo0") \
                or name.lower().startswith("loopback"):
            continue  # loopback interfaces may also carry non-127/8 addresses such as fe80::1
        entries = list(if_addrs[name])
        vpn = is_vpn_interface(name, entries, vpn_interfaces)
        for entry in entries:
            family = getattr(entry, "family", None)
            if family not in (socket.AF_INET, socket.AF_INET6):
                continue
            raw = str(getattr(entry, "address", ""))
            address = _parse(raw)
            if address is None or not _allowed(address, vpn):
                continue
            scope = raw.partition("%")[2] or None
            if address.version == 6 and address.is_link_local:
                scope = scope or name
            else:
                scope = None
            chosen.append(BindAddress(name, address, _network(address, entry.netmask), scope))
    return chosen


def explicit_bind_addresses(hosts: Sequence[str], if_addrs: Mapping[str, Sequence[Any]],
                            if_stats: Mapping[str, Any], *,
                            vpn_interfaces: Sequence[str] = ()) -> List[BindAddress]:
    """``lan_bind``: the owner narrows the listener to some of this computer's addresses.

    It can only narrow. Each named address must be one :func:`select_bind_addresses` would bind
    anyway, on the interface that holds it, so ``lan_bind`` never reaches loopback, ``0.0.0.0``,
    ``::``, a public address, or ``100.64/10`` on an interface that is not a VPN. Anything else is
    dropped. Tests that need loopback hand ``ListenerConfig.interfaces`` a list of their own, which
    no plugin config key can set.
    """
    wanted = {address for address in (_parse(host) for host in hosts) if address is not None}
    allowed = select_bind_addresses(if_addrs, if_stats, vpn_interfaces=vpn_interfaces)
    permitted = {bind.address for bind in allowed}
    for host in hosts:
        if _parse(host) not in permitted:
            logger.warning("cozychat ignored lan_bind address %s: not an allowed local address", host)
    return [bind for bind in allowed
            if bind.address in wanted]


def system_bind_addresses(vpn_interfaces: Sequence[str] = (),
                          only: Sequence[str] = ()) -> List[BindAddress]:
    """The interface scan. ``only`` is ``lan_bind``: when given, just those of the allowed ones."""
    import psutil

    if only:
        return explicit_bind_addresses(only, psutil.net_if_addrs(), psutil.net_if_stats(),
                                       vpn_interfaces=vpn_interfaces)
    return select_bind_addresses(psutil.net_if_addrs(), psutil.net_if_stats(),
                                 vpn_interfaces=vpn_interfaces)


def _allowed(address: IPAddress, vpn: bool) -> bool:
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        return False
    if address.version == 4 and address in CGNAT:
        return vpn
    return any(address.version == net.version and address in net for net in PRIVATE)


def _network(address: IPAddress, netmask: Optional[str]) -> IPNetwork:
    width = 32 if address.version == 4 else 128
    prefix = width
    if netmask:
        try:
            prefix = ipaddress.ip_network(f"0.0.0.0/{netmask}").prefixlen if address.version == 4 \
                else _v6_prefix(netmask)
        except ValueError:
            prefix = width
    found = _range_of(address)
    network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
    if found is not None and (prefix >= width or not network.subnet_of(found)):
        # Point to point: answer the private range the address belongs to. A netmask wider than
        # that range (a /0, or 172.16.0.5/8) is clamped to it, so a peer is never the world.
        return found
    return network


def _range_of(address: IPAddress) -> Optional[IPNetwork]:
    if address.version == 4 and address in CGNAT:
        return CGNAT
    if address.version == 6 and address in TAILSCALE_V6:
        return TAILSCALE_V6
    for net in PRIVATE:
        if address.version == net.version and address in net:
            return net
    return None


def _v6_prefix(netmask: str) -> int:
    text = netmask.partition("/")[0]
    if text.isdigit():
        return int(text)
    return bin(int(ipaddress.IPv6Address(text))).count("1")


def _parse(text: str) -> Optional[IPAddress]:
    try:
        return ipaddress.ip_address(str(text).partition("%")[0])
    except ValueError:
        return None
