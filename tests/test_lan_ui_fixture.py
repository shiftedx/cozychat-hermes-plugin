"""Validate the UI fixture's real listener, explicit approval, history and reconnect path."""

import asyncio
import importlib.util
import json
import tempfile
import sys
from pathlib import Path

import pytest

from tunnel_phone import Phone


def test_ui_fixture_carries_new_reply_and_retains_history_after_listener_restart():
    path = Path(__file__).resolve().parents[4] / "Scripts/hermes-lan-ui-fixture.py"
    if not path.is_file():
        pytest.skip("needs Scripts/hermes-lan-ui-fixture.py, which exists only in the CozyChat monorepo")
    spec = importlib.util.spec_from_file_location("lan_ui_fixture", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    async def request(port, path, key, body=None):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        data = json.dumps(body).encode() if body is not None else b""
        method = "POST" if body is not None else "GET"
        writer.write(f"{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {key}\r\n"
                     f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n".encode() + data)
        await writer.drain()
        response = await reader.read()
        writer.close()
        await writer.wait_closed()
        assert response.startswith(b"HTTP/1.1 200") or response.startswith(b"HTTP/1.1 202")
        return response.split(b"\r\n\r\n", 1)[1]

    async def scenario(root):
        fixture = module.Fixture(root)
        await fixture.start()
        opened = await fixture.control("/pair/open")
        phone = Phone(opened["link"])
        try:
            await phone.connect()
            while fixture.store.attempt() is None:
                await asyncio.sleep(0.01)
            assert (await fixture.control("/pair/state"))["code"] == phone.code
            assert (await fixture.control("/pair/approve"))["approved"]
            assert await phone.next_control() == {"event": "pairing.approved"}
            bootstrap = await phone.request("bootstrap")
            key = bootstrap["api_key"]
            local = await phone.expose_api()
            capabilities = json.loads(await request(local, "/v1/capabilities", key))
            assert capabilities["features"]["runs_idempotency"]["durable"]
            history = json.loads(await request(local, f"/api/sessions/{module.SESSION}/messages", key))
            assert [row["content"] for row in history["data"]] == [module.SAVED]
            admitted = json.loads(await request(local, "/v1/runs", key,
                {"session_id": module.SESSION, "input": "Hello from Wi-Fi"}))
            events = await request(local, f'/v1/runs/{admitted["run_id"]}/events', key)
            assert module.REPLY.encode() in events
            assert len(fixture.submissions) == 1
            await phone.close()
            await fixture.control("/network/offline")
            await fixture.control("/network/online")
            # The approved identity survives a replacement listener session, without another QR.
            restored = Phone(opened["link"], static_private=phone.static_private)
            restored.approved = True
            await restored.connect()
            try:
                local = await restored.expose_api()
                history = json.loads(await request(local, f"/api/sessions/{module.SESSION}/messages", key))
                assert [row["content"] for row in history["data"]] == [module.SAVED, "Hello from Wi-Fi", module.REPLY]
                assert len(fixture.submissions) == 1
            finally:
                await restored.close()
        finally:
            await phone.close()
            await fixture.stop()

    with tempfile.TemporaryDirectory(prefix="cozy-lan-ui-test-", dir="/private/tmp" if sys.platform == "darwin" else None) as root:
        asyncio.run(asyncio.wait_for(scenario(Path(root)), timeout=20))
