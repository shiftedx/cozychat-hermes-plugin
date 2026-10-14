"""Desktop endpoints against shared pairing state and a real Noise listener; no Hermes service."""

import asyncio
import sys
import base64
import importlib.util
import json
from pathlib import Path

import png
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import cozychat
from cozychat.relay import pairing
from cozychat.relay.desktop import PairingPage
from cozychat.relay.pairing import PairingStore
from cozychat.relay.reachable import Reachable
from cozychat.relay.runtime import Tunnel
from tunnel_phone import Phone, loopback_binds
from test_tunnel_end_to_end import DELTA, DELTAS, fake_api, get, http, post


class FakeService:
    kind = "launchd"

    def __init__(self):
        self.exists = False
        self.calls = []
        self.content = "CozyChat-installed service"

    def installed(self):
        return self.exists

    def available(self):
        return True

    def hermes_installed(self):
        return False

    def matches(self, expected):
        return self.exists and expected == self.content

    def install(self):
        self.calls.append("install")
        self.exists = True
        return self.content

    def uninstall(self, expected):
        if not self.matches(expected):
            return False
        self.calls.append("uninstall")
        self.exists = False
        return True


class FakeGateway:
    def __init__(self):
        self.calls = 0

    def ensure(self, before_start):
        self.calls += 1
        before_start()


@pytest.fixture
def desktop(tmp_path, monkeypatch):
    home = tmp_path / "hermes"
    home.mkdir()
    store = PairingStore(home / "cozychat" / "relay")
    tunnel = Tunnel(store, config={}, plugin_version="0.6.0", state_version="shared-v1",
                    home=home, interfaces=loopback_binds, environ={})
    service, gateway = FakeService(), FakeGateway()
    page = PairingPage(tunnel, reachable=Reachable(store, service), gateway=gateway, network_note=lambda: None)
    owner = tunnel.owner(tick_seconds=0.05).start()
    page._wake = owner.tick
    spec = importlib.util.spec_from_file_location(
        "desktop_test_api", Path(__file__).resolve().parents[1] / "dashboard" / "plugin_api.py")
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)
    monkeypatch.setattr(api, "_page", lambda: page)
    app = FastAPI()
    app.include_router(api.router, prefix="/api/plugins/cozychat")
    with TestClient(app) as client:
        try:
            yield client, page, service, gateway, api
        finally:
            owner.stop()


def url(path):
    return "/api/plugins/cozychat/" + path


def test_desktop_has_host_authority_to_revoke_and_rotate(desktop):
    from test_phone_management import approve
    client, page, _, _, _ = desktop
    key = bytes.fromhex("33" * 32)
    approve(page.store, key, "Phone")
    rotations = []
    page.tunnel.management._rotate = lambda: rotations.append(True) or {
        "rotated": False, "rotation_pending": True}
    assert client.get(url("pair/state")).json()["rotation"]["available"]
    response = client.request("DELETE", url("phones/" + key.hex()), json={"rotate": True})
    assert response.status_code == 200 and response.json()["rotation_pending"]
    assert not page.store.is_approved(key) and rotations == [True]
    response = client.post(url("rotate"))
    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    assert rotations == [True, True]


def test_desktop_manifest_api_advertises_the_same_version_gate(desktop, monkeypatch):
    client, _, _, _, api = desktop
    manifest = json.loads((Path(cozychat.__file__).parent / "dashboard/manifest.json").read_text())
    assert manifest["api"] == Path(api.__file__).name
    assert manifest["version"] == cozychat.VERSION
    monkeypatch.setattr(api._feed, "_package", lambda: cozychat)
    info = client.get(url("info")).json()
    assert info["plugin_version"] == info["version"] == cozychat.VERSION
    assert info["relay_proto"] == cozychat.RELAY_PROTO == 1
    # An old backend with no protocol advertisement must remain unknown to the client gate.
    monkeypatch.delattr(cozychat, "RELAY_PROTO")
    assert client.get(url("info")).json()["relay_proto"] is None


def test_first_visit_opens_once_starts_gateway_and_defaults_reachable_on(desktop):
    client, page, service, gateway, _ = desktop
    assert client.get(url("pair/state")).json()["first_visit"]
    opened = client.post(url("pair/open"), json={"automatic": True})
    assert opened.status_code == 200
    window = page.store.window()
    assert gateway.calls == 1 and service.calls == ["install"]
    assert opened.json()["reachable"]["enabled"]
    assert client.post(url("pair/open"), json={"automatic": True}).status_code == 200
    assert page.store.window() == window and gateway.calls == 1
    page.store.cancel_window()
    assert client.post(url("pair/open"), json={"automatic": True}).json()["window"] is None


def test_qr_is_png_and_matches_valid_lan_only_pair_relay_payload(desktop):
    client, page, _, _, _ = desktop
    assert client.post(url("pair/open")).status_code == 200
    response = client.get(url("pair/qr"))
    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    result = response.json()
    image = base64.b64decode(result["png"].removeprefix("data:image/png;base64,"))
    assert image.startswith(b"\x89PNG\r\n\x1a\n")
    width, height, rows, _ = png.Reader(bytes=image).asRGB8()
    assert width == height and width >= 300
    # Optional independent decoder, installed for the slice's acceptance run. It is a test
    # dependency only, never imported or shipped by the plugin.
    zxing = pytest.importorskip("zxingcpp")
    raster = bytes(value for row in rows for value in row)
    decoded = zxing.read_barcode(zxing.ImageView(raster, width, height, zxing.ImageFormat.RGB))
    assert decoded is not None and decoded.text == result["link"]
    payload = pairing.decode_link(decoded.text)
    assert payload == {"v": 1, "host": page.store.host_public().hex(),
                       "psk": page.store.window().psk.hex(), "exp": page.store.window().exp,
                       "lan": page.tunnel.listening_hints()}
    assert "relay" not in payload and "api_key" not in payload


def test_expired_qr_and_pending_are_withdrawn_and_cannot_be_approved(desktop):
    client, page, _, _, _ = desktop
    now = [1000.0]
    page.store._clock = page._clock = lambda: now[0]
    client.post(url("pair/open"))
    attempt = page.store.begin_attempt(page.store.window().id, b"a" * 32, "Phone", "001002")
    now[0] += 601
    assert client.get(url("pair/qr")).status_code == 410
    state = client.get(url("pair/state")).json()
    assert state["window"] is None and state["pending"] is None
    assert client.post(url("pair/approve"), json={"id": attempt}).status_code == 409
    assert page.store.phones() == []


@pytest.mark.parametrize("decision, outcome", [("approve", "approved"), ("refuse", "refused")])
def test_decision_is_shared_and_only_the_listener_settles_it(desktop, decision, outcome):
    client, page, _, _, _ = desktop
    client.post(url("pair/open"))
    owner = PairingStore(page.store.root)
    window = owner.window()
    attempt = owner.begin_attempt(window.id, b"a" * 32, "Kyle's iPhone", "001002")
    state = client.get(url("pair/state")).json()
    assert state["pending"] == {"id": attempt, "phone_name": "Kyle's iPhone", "code": "001002", "decision": None}
    assert client.post(url("pair/" + decision), json={"id": attempt}).status_code == 200
    assert owner.phones() == []  # no approval is committed by an HTTP handler
    assert owner.attempt().decision == decision
    assert owner.settle(attempt) == outcome
    assert bool(owner.phones()) == (decision == "approve")
    assert owner.window() is None if decision == "approve" else owner.window() == window


def test_stale_duplicate_and_malformed_decisions_do_not_authorize_a_phone(desktop):
    client, page, _, _, _ = desktop
    client.post(url("pair/open"))
    attempt = page.store.begin_attempt(page.store.window().id, b"a" * 32, "Phone", "123456")
    assert client.post(url("pair/approve"), json={"id": "old"}).status_code == 409
    assert client.post(url("pair/approve"), json={"id": 7}).status_code == 400
    assert client.post(url("pair/approve"), json={"id": attempt}).status_code == 200
    assert client.post(url("pair/refuse"), json={"id": attempt}).status_code == 409


def test_phone_list_and_remove_validate_ids(desktop):
    client, page, _, _, _ = desktop
    client.post(url("pair/open"))
    key = b"a" * 32
    attempt = page.store.begin_attempt(page.store.window().id, key, "Phone", "123456")
    page.store.decide(attempt, True)
    page.store.settle(attempt)
    listing = client.get(url("phones"))
    assert listing.status_code == 200 and listing.json()["phones"][0]["name"] == "Phone"
    assert client.delete(url("phones/not-a-key")).status_code == 400
    assert client.delete(url("phones/" + key.hex())).status_code == 200
    assert client.get(url("phones")).json() == {"phones": []}
    assert client.delete(url("phones/" + key.hex())).status_code == 404


def test_reachable_endpoints_remove_only_owned_service_and_persist_off(desktop):
    client, page, service, _, _ = desktop
    assert client.post(url("reachable"), json={"enabled": "false"}).status_code == 400
    assert client.post(url("reachable"), json={"enabled": True}).json()["owned"]
    assert client.post(url("reachable"), json={"enabled": False}).json()["enabled"] is False
    assert service.calls == ["install", "uninstall"]
    assert client.post(url("pair/open")).status_code == 200
    assert service.calls == ["install", "uninstall"]  # a later pairing does not re-enable it


def test_backend_disabled_returns_503_and_preserves_existing_feed_routes(desktop, monkeypatch):
    client, _, _, _, api = desktop
    monkeypatch.undo()
    monkeypatch.setattr(api._feed, "_package", lambda: None)
    assert client.get(url("pair/state")).status_code == 503
    assert client.get(url("pair/qr")).status_code == 503
    assert client.get(url("info")).status_code == 200


def test_optout_no_network_and_wsl_have_clear_copy(desktop):
    client, page, _, gateway, _ = desktop
    page.tunnel.config["lan"] = False
    assert client.post(url("pair/open")).status_code == 409 and gateway.calls == 0
    page.tunnel.config["lan"] = True
    page.tunnel._interfaces = lambda: []
    assert client.post(url("pair/open")).status_code == 409
    assert page.store.window() is None
    page._network_note = lambda: "Hermes is running inside WSL. WSL2 NAT is not reachable over Wi-Fi."
    assert "WSL" in client.get(url("pair/state")).json()["wsl_note"]


def test_service_errors_do_not_leak_credentials_or_show_a_qr(desktop):
    client, page, _, _, _ = desktop
    def fail(before_start):
        raise RuntimeError("operator API_SERVER_KEY=secret")
    page.gateway.ensure = fail
    response = client.post(url("pair/open"))
    assert response.status_code == 503 and "secret" not in response.text
    assert page.store.window() is None


def test_occupied_port_never_publishes_a_qr_from_potential_addresses(desktop, monkeypatch):
    import errno

    client, page, _, _, _ = desktop
    assert page.tunnel.expected_hints()

    async def occupied(*args, **kwargs):
        raise OSError(errno.EADDRINUSE, "occupied")

    monkeypatch.setattr("cozychat.relay.host.asyncio.start_server", occupied)
    assert client.post(url("pair/open")).status_code == 409
    assert page.store.window() is None
    assert client.get(url("pair/qr")).status_code == 410
    assert page.tunnel.listening_hints() == []


def test_qr_uses_owners_bound_port_even_from_a_standby_process(desktop):
    client, page, _, _, _ = desktop
    owner = page.tunnel.owner(tick_seconds=0.05).start()
    page._wake = owner.tick
    try:
        assert client.post(url("pair/open")).status_code == 200
        # The fixture's first supervisor holds the lock. This page must use its receipt, not
        # recompute addresses with its own subsequently changed configuration.
        page.tunnel.config["lan_port"] = 12345
        payload = pairing.decode_link(client.get(url("pair/qr")).json()["link"])
        assert payload["lan"] == page.tunnel.listening_hints()
        assert payload["lan"] != page.tunnel.expected_hints()
    finally:
        owner.stop()


def test_http_approve_drives_real_listener_bootstrap_health_and_sse(desktop):
    client, page, _, _, _ = desktop

    async def scenario():
        server, port = await fake_api("test-key-0123456789")
        (page.tunnel.home / ".env").write_text(f"API_SERVER_KEY=test-key-0123456789\nAPI_SERVER_PORT={port}\n")
        owner = page.tunnel.owner(tick_seconds=0.05).start()
        page._wake = owner.tick
        phone = None
        try:
            response = await asyncio.to_thread(client.post, url("pair/open"))
            assert response.status_code == 200
            qr = (await asyncio.to_thread(client.get, url("pair/qr"))).json()
            phone = Phone(qr["link"])
            await phone.connect()
            for _ in range(100):
                state = (await asyncio.to_thread(client.get, url("pair/state"))).json()
                if state["pending"]:
                    break
                await asyncio.sleep(0.02)
            assert state["pending"]["code"] == phone.code
            before = await phone.request("bootstrap")
            assert before["ok"] is False
            approved = await asyncio.to_thread(client.post, url("pair/approve"),
                                                json={"id": state["pending"]["id"]})
            assert approved.status_code == 200
            assert await phone.next_control() == {"event": "pairing.approved"}
            bootstrap = await phone.request("bootstrap")
            assert bootstrap["api_key"] == "test-key-0123456789"
            local = await phone.expose_api()
            status, body = await http(local, get("/health"))
            assert status == 200 and json.loads(body)["status"] == "ok"
            status, _ = await http(local, post("/v1/runs", {"input": "hello"}, "test-key-0123456789"))
            assert status == 202
            status, body = await http(local, get("/v1/runs/run_fake/events", "test-key-0123456789"))
            assert status == 200
            events = [json.loads(line[6:]) for line in body.decode().splitlines() if line.startswith("data: ")]
            assert len(events) == DELTAS + 1
            assert "".join(event.get("delta", "") for event in events) == DELTA * DELTAS
            assert events[-1]["event"] == "run.completed"
            assert (await asyncio.to_thread(client.get, url("pair/qr"))).status_code == 410
        finally:
            if phone:
                await phone.close()
            server.close()
            await server.wait_closed()

    asyncio.run(asyncio.wait_for(scenario(), 30))


@pytest.mark.parametrize("enabled", [True, False])
def test_existing_hermes_service_toggle_does_not_configure_or_start_gateway(desktop, enabled):
    client, _, service, gateway, _ = desktop
    service.hermes_installed = lambda: True
    response = client.post(url("reachable"), json={"enabled": enabled})
    assert response.status_code == 200
    assert response.json()["enabled"] and response.json()["editable"] is False
    assert response.json()["note"] == "Already kept running by your Hermes service"
    assert gateway.calls == 0 and service.calls == []


def test_native_startup_failure_never_blocks_pairing_and_is_noted(desktop):
    client, page, service, gateway, _ = desktop
    def fail():
        raise RuntimeError("launchctl bootstrap failed")
    service.install = fail
    opened = client.post(url("pair/open"))
    assert opened.status_code == 200 and page.store.window() is not None
    reachable = opened.json()["reachable"]
    assert "Pairing still works" in reachable["note"] and "launchctl" not in reachable["note"]
    assert gateway.calls == 1


def test_state_polls_are_cached_briefly_and_native_timeouts_are_plain(desktop):
    import subprocess
    client, page, service, _, _ = desktop
    reads = []
    original = service.installed
    service.installed = lambda: reads.append(1) or original()
    assert client.get(url("pair/state")).status_code == 200
    assert client.get(url("pair/state")).status_code == 200
    assert len(reads) == 1
    page.reachable._cached = None
    def hang():
        raise subprocess.TimeoutExpired(["powershell.exe", "SECRET"], 30)
    service.installed = hang
    response = client.get(url("pair/state"))
    assert response.status_code == 503 and "SECRET" not in response.text and "powershell" not in response.text


def test_without_hermes_secret_scope_the_page_fails_closed_and_publishes_no_qr(desktop, monkeypatch):
    client, page, *_ = desktop
    monkeypatch.setitem(sys.modules, "agent.secret_scope", None)
    state = client.get(url("pair/state")).json()
    assert state["update_required"] == "Update Hermes to use CozyChat"
    for response in (client.post(url("pair/open"), json={}), client.get(url("pair/qr"))):
        assert response.status_code == 503
        assert response.json()["detail"] == "Update Hermes to use CozyChat"
    assert page.store.window() is None
