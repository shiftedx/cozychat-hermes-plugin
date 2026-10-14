"""A stand-in phone for the tunnel tests, adapted from the 2026-10-12 prototype's ``phone.py``.

It does what CozyChat will do over the home network: reads the pairing link, connects over TCP,
runs the Noise handshake pinned to the host key from the link, opens ``control`` first, and can
expose the ``api`` service as a loopback port so an unmodified HTTP client talks to Hermes through
the tunnel, the way the app's ``SSHTunnel`` does today.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
from typing import Any, Dict, List, Optional, Tuple

from cozychat.relay import framing, lan, noise, pairing
from cozychat.relay.mux import Mux, Stream

PHONE_NAME = "Kyle’s iPhone"


def loopback_binds() -> List[lan.BindAddress]:
    """The tests' way onto loopback: ``ListenerConfig.interfaces``, which no config key sets.

    ``lan_bind`` cannot reach loopback (it only narrows the interface scan), so tests hand the
    listener this bind list directly.
    """
    address = ipaddress.ip_address("127.0.0.1")
    return [lan.BindAddress("lo0", address, ipaddress.ip_network("127.0.0.1/32"))]


class Phone:
    def __init__(self, link: str, *, static_private: Optional[bytes] = None,
                 name: str = PHONE_NAME) -> None:
        self.link = pairing.decode_link(link)
        self.host_key = bytes.fromhex(self.link["host"])
        self.static_private = static_private or noise.generate_private_key()
        self.static_public = noise.public_key(self.static_private)
        self.name = name
        self.approved = False
        self.session: Optional[noise.Session] = None
        self.mux: Optional[Mux] = None
        self.payload: Optional[Dict[str, Any]] = None
        self.control: Optional[Stream] = None
        self._control_lines: "asyncio.Queue[Dict[str, Any]]" = asyncio.Queue()
        self._next_request = 1
        self._tasks: List[asyncio.Task] = []
        self._server: Optional[asyncio.base_events.Server] = None

    def address(self) -> Tuple[str, int]:
        host, _, port = self.link["lan"][0].rpartition(":")
        return host.strip("[]"), int(port)

    @property
    def code(self) -> str:
        assert self.session is not None
        return noise.pairing_code(self.session.handshake_hash, self.name)

    async def handshake(self, *, psk: Optional[bytes] = None,
                        hello: Optional[bytes] = None) -> Dict[str, Any]:
        """Message 1 and message 2. Raises on a silent close or a wrong psk. ``hello`` replaces
        message 1's payload, for tests of what the host drops."""
        if psk is None:
            psk = noise.ZERO_PSK if self.approved else bytes.fromhex(self.link["psk"])
        host, port = self.address()
        self.reader, self.writer = await asyncio.open_connection(host, port)
        initiator = noise.Initiator(self.static_private, self.host_key, psk)
        if hello is None:
            hello = json.dumps({"phone_name": self.name, "app": "1.0.5",
                                "relay_proto": [1, 1]}).encode("utf-8")
        self.writer.write(framing.encode(initiator.write_message_1(hello)))
        await self.writer.drain()
        message_2 = await asyncio.wait_for(
            framing.read_message(self.reader, framing.TRANSPORT_MAX), 5)
        payload, self.session = initiator.read_message_2(message_2)
        self.payload = json.loads(payload)
        self.mux = Mux(self.session, self.reader, self.writer, initiator=True)
        return self.payload

    async def open_control(self) -> Stream:
        """The first transport frame: ``OPEN control`` (contract section 4 step 1)."""
        assert self.mux is not None
        self.control = await self.mux.open("control")
        self._tasks.append(asyncio.ensure_future(self.mux.run()))
        self._tasks.append(asyncio.ensure_future(self._read_control()))
        return self.control

    async def connect(self) -> Dict[str, Any]:
        payload = await self.handshake()
        await self.open_control()
        return payload

    async def _read_control(self) -> None:
        assert self.control is not None
        buffer = b""
        while True:
            chunk = await self.control.read()
            if not chunk:
                return
            buffer += chunk
            while b"\n" in buffer:
                line, _, buffer = buffer.partition(b"\n")
                message = json.loads(line)
                if message.get("event") == "pairing.approved":
                    self.approved = True
                await self._control_lines.put(message)

    async def next_control(self, timeout: float = 5.0) -> Dict[str, Any]:
        return await asyncio.wait_for(self._control_lines.get(), timeout)

    async def request(self, op: str, **fields: Any) -> Dict[str, Any]:
        assert self.control is not None
        request_id = self._next_request
        self._next_request += 1
        await self.control.write(json.dumps({"id": request_id, "op": op, **fields}).encode() + b"\n")
        while True:
            message = await self.next_control()
            if message.get("id") == request_id:
                return message

    async def expose_api(self) -> int:
        """A loopback port whose every connection is one ``api`` stream."""
        assert self.mux is not None
        mux = self.mux

        async def on_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            stream = await mux.open("api")

            async def up() -> None:
                while chunk := await reader.read(framing.MAX_DATA):
                    await stream.write(chunk)

            async def down() -> None:
                while chunk := await stream.read():
                    writer.write(chunk)
                    await writer.drain()

            tasks = [asyncio.ensure_future(up()), asyncio.ensure_future(down())]
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in tasks:
                task.cancel()
            await stream.close()
            writer.close()

        self._server = await asyncio.start_server(on_connection, "127.0.0.1", 0)
        return self._server.sockets[0].getsockname()[1]

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
        if self.mux is not None:
            await self.mux.close()
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
