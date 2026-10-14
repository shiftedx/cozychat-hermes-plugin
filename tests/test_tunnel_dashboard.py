"""Dashboard stays on loopback; approved phones reach it through the named service."""

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cozychat.relay import pairing, services
from cozychat.relay.host import Listener, ListenerConfig
from test_tunnel_hardening import approved_phone, run
from tunnel_phone import loopback_binds


class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"version": "0.21.6", "auth_required": getattr(self.server, "gated", False), "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def test_dashboard_discovery_requires_token_valid_port_and_live_ungated_health(tmp_path):
    server = ThreadingHTTPServer(("127.0.0.1", 0), DashboardHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    token = "test-dashboard-token"
    values = {"HERMES_DASHBOARD_PORT": str(server.server_port), "HERMES_DASHBOARD_SESSION_TOKEN": token}
    try:
        target = services.discover_dashboard(tmp_path, {}, values)
        assert target == services.DashboardTarget(server.server_port, token)
        server.gated = True
        assert services.discover_dashboard(tmp_path, {}, values) is None
        server.gated = False
        assert services.discover_dashboard(tmp_path, {}, {}) is None
        assert services.discover_dashboard(tmp_path, {}, {**values, "HERMES_DASHBOARD_PORT": "0"}) is None
        assert services.discover_dashboard(tmp_path, {}, {**values, "HERMES_DASHBOARD_PORT": "broken"}) is None
        (tmp_path / ".env").write_text("\n".join(f"{key}={value}" for key, value in values.items()))
        assert services.discover_api(tmp_path, {}).dashboard == target
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    assert services.discover_dashboard(tmp_path, {}, values) is None


def test_dashboard_bootstrap_is_approval_gated_and_absence_is_advertised():
    target = services.ApiTarget(8642, "api-key", dashboard=services.DashboardTarget(9119, "dashboard-token"))
    context = services.SessionContext(approved=False, capabilities=lambda: {}, api=lambda: target)
    assert services._answer(b'{"id":1,"op":"bootstrap"}', context) == {
        "id": 1, "ok": False, "error": "not_approved"}
    context.approved = True
    reply = services._answer(b'{"id":2,"op":"bootstrap"}', context)
    assert reply["dashboard_token"] == "dashboard-token" and reply["dashboard_port"] == 9119
    args = dict(plugin_version="0.6.0", state_version="shared-v1", lan_addresses=[],
                push_available=False, push_paired=False)
    assert services.capability_document(**args)["services"]["dashboard"] is None
    assert services.capability_document(**args, dashboard_available=True)["services"]["dashboard"] == {"available": True}


def test_api_and_dashboard_share_one_real_noise_listener(tmp_path):
    async def scenario():
        async def respond(reader, writer):
            request = await reader.readuntil(b"\r\n\r\n")
            body = request.split(b" ")[1]
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        upstream = await asyncio.start_server(respond, "127.0.0.1", 0)
        port = upstream.sockets[0].getsockname()[1]
        target = services.ApiTarget(port, "api-key", dashboard=services.DashboardTarget(port, "dashboard-token"))
        store = pairing.PairingStore(tmp_path / "relay")
        store.open_window()
        listener = Listener(store, ListenerConfig(port=0, interfaces=loopback_binds),
            capabilities=lambda hints: services.capability_document(plugin_version="0.6.0", state_version="shared-v1",
                lan_addresses=hints, push_available=False, push_paired=False, dashboard_available=True),
            api=lambda: target)
        await listener.start()
        phone = await approved_phone(store, listener)
        try:
            bootstrap = await phone.request("bootstrap")
            assert bootstrap["dashboard_token"] == "dashboard-token"
            for service, path in (("api", "/v1/sessions"), ("dashboard", "/api/profiles")):
                stream = await phone.mux.open(service)
                await stream.write(f"GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
                response = b""
                while chunk := await asyncio.wait_for(stream.read(), 5):
                    response += chunk
                assert response.endswith(path.encode())
        finally:
            await phone.close()
            await listener.stop()
            upstream.close()
            await upstream.wait_closed()

    run(scenario())
