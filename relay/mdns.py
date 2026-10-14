"""Optional, interface-scoped discovery. The Noise pin is the authority, never this record."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import socket
from typing import Dict, List, Tuple

from . import lan

logger = logging.getLogger("hermes_cli.plugins.cozychat")

SERVICE_TYPE = "_cozychat._tcp.local."


def tag(host_public: bytes) -> str:
    return hmac.new(host_public, b"cozychat-mdns-v1", hashlib.sha256).digest()[:8].hex()


def instance_name(host_public: bytes) -> str:
    return f"CozyChat-{tag(host_public)[:4]}.{SERVICE_TYPE}"


class Advertiser:
    """One zeroconf stack per bound interface; no address leaks onto an unbound interface."""

    def __init__(self, host_public: bytes) -> None:
        self._public = host_public
        self._active: Dict[str, Tuple[Tuple[lan.BindAddress, ...], int, object]] = {}
        self._missing = False

    @property
    def advertising(self) -> bool:
        return bool(self._active)

    async def update(self, binds: List[lan.BindAddress], port: int) -> None:
        grouped: Dict[str, List[lan.BindAddress]] = {}
        for bind in binds:
            # The listener's test-only loopback override must not announce on the real network.
            if bind.address.is_loopback or bind.address.is_unspecified:
                continue
            grouped.setdefault(bind.interface, []).append(bind)
        removed = [interface for interface, (previous, previous_port, _) in self._active.items()
                   if tuple(grouped.get(interface, [])) != previous or previous_port != port]
        await self._together(self._remove(interface) for interface in removed)
        if self._missing or not grouped:
            return
        try:
            from zeroconf import ServiceInfo
            from zeroconf.asyncio import AsyncZeroconf
        except ImportError:
            self._missing = True
            logger.debug("cozychat discovery is off; zeroconf is absent, address hints still work")
            return

        async def add(interface, addresses):
            zc = None
            try:
                # IPv6 membership requires an interface index. Let zeroconf map the exact bound
                # address to it on each OS; never use InterfaceChoice.All or Default.
                interfaces = []
                index = None
                for bind in addresses:
                    if bind.address.version == 4:
                        interfaces.append(str(bind.address))
                    else:
                        index = socket.if_nametoindex(interface)
                        interfaces.append(((str(bind.address), 0, index), index))
                zc = AsyncZeroconf(interfaces=interfaces)
                info = ServiceInfo(
                    SERVICE_TYPE, instance_name(self._public), port=port,
                    addresses=[b.address.packed for b in addresses],
                    interface_index=index,
                    server=f"cozychat-{tag(self._public)}.local.",
                    properties={"v": "1", "h": tag(self._public)})
                announced = await zc.async_register_service(info, cooperating_responders=True)
                await announced
                self._active[interface] = (tuple(addresses), port, zc)
            except asyncio.CancelledError:
                if zc is not None:
                    await self._close(zc)
                raise
            except Exception:
                logger.debug("cozychat discovery could not announce on %s", interface,
                             exc_info=True)
                if zc is not None:
                    await self._close(zc)

        # Each stack probes its service name. Do that concurrently so many VPN interfaces do
        # not multiply startup latency or delay the owner handover.
        await self._together(add(interface, addresses) for interface, addresses in grouped.items()
                             if interface not in self._active)

    async def _together(self, operations) -> None:
        tasks = [asyncio.ensure_future(operation) for operation in operations]
        try:
            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _close(self, zc) -> None:
        closing = asyncio.ensure_future(zc.async_close())
        try:
            await asyncio.shield(closing)
        except asyncio.CancelledError:
            await closing
            raise
        except Exception:
            logger.debug("cozychat discovery could not withdraw", exc_info=True)

    async def _remove(self, interface: str) -> None:
        _, _, zc = self._active.pop(interface)
        await self._close(zc)

    async def stop(self) -> None:
        await self._together(self._remove(interface) for interface in list(self._active))
