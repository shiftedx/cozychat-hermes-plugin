"""Pause at the authorization boundaries; revocation never waits for a polling interval."""

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

import pytest

from cozychat.relay import noise, pairing, services
from cozychat.relay.mux import SessionClose, StreamClose
from test_phone_management import approve, run, tunnel_at
from tunnel_phone import Phone


def test_queued_self_revoke_rechecks_caller_under_mutation_lock(tmp_path, monkeypatch):
    tunnel = tunnel_at(tmp_path / "hermes")
    key = noise.public_key(noise.generate_private_key())
    approve(tunnel.store, key, "Phone")
    entered, resume = threading.Event(), threading.Event()
    locked = tunnel.store.locked

    @contextmanager
    def paused_lock():
        entered.set()
        assert resume.wait(5)
        with locked():
            yield

    monkeypatch.setattr(tunnel.store, "locked", paused_lock)
    with ThreadPoolExecutor(1) as executor:
        request = executor.submit(tunnel.management.answer, {"op": "revoke"}, key)
        try:
            assert entered.wait(5)
            # A different Desktop process uses its own store/lock handle.
            tunnel_at(tunnel.home).management.revoke(key.hex())
        finally:
            resume.set()
        with pytest.raises(services.ControlError, match="^not_approved$"):
            request.result(5)


@pytest.mark.parametrize("operation", [
    {"op": "revoke", "phone_id": "22" * 32},
    {"op": "revoke", "rotate": True}, {"op": "rotate"},
])
def test_phone_cannot_remove_another_phone_or_rotate(tmp_path, operation):
    tunnel = tunnel_at(tmp_path / "hermes")
    caller, other = bytes.fromhex("11" * 32), bytes.fromhex("22" * 32)
    for key in (caller, other):
        approve(tunnel.store, key, "Phone")
    tunnel.management._rotate = lambda: pytest.fail("phone has no host authority")
    with pytest.raises(services.ControlError, match="^host_authority_required$"):
        tunnel.management.answer(operation, caller)
    assert tunnel.store.is_approved(caller) and tunnel.store.is_approved(other)


def test_revoked_phone_finishing_delayed_handshake_is_never_admitted(tmp_path):
    async def scenario():
        tunnel = tunnel_at(tmp_path / "hermes")
        private = noise.generate_private_key()
        approve(tunnel.store, noise.public_key(private), "Phone")
        listener = tunnel.make_listener(port=0, allowlist_poll_seconds=10)
        await listener.start()
        window = tunnel.store.open_window()
        phone = Phone(pairing.pairing_link(tunnel.store.host_public(), window, listener.hints()),
                      static_private=private)
        tunnel.store.cancel_window()
        phone.approved = True
        try:
            await phone.handshake()  # Message 2 has been received; first transport is still withheld.
            tunnel.management.revoke(phone.static_public.hex())
            await phone.open_control()
            await asyncio.wait_for(phone.mux.done.wait(), 1)
            assert phone.mux.remote_close_code == SessionClose.REVOKED
            assert not listener._sessions
        finally:
            await phone.close()
            await listener.stop()
    run(scenario())


def test_privileged_service_rechecks_live_approval_before_opening_upstream(tmp_path, monkeypatch):
    async def scenario():
        tunnel = tunnel_at(tmp_path / "hermes")
        key = noise.public_key(noise.generate_private_key())
        approve(tunnel.store, key, "Phone")
        context = services.SessionContext(approved=True, phone_key=key,
            management=tunnel.management, api=tunnel.api, capabilities=lambda: {})
        tunnel.management.revoke(key.hex())
        opened = []
        async def upstream(*args):
            opened.append(args)
        monkeypatch.setattr(services, "_api", upstream)
        class Stream:
            service = "api"
            async def close(self, code):
                self.code = code
        stream = Stream()
        await services.serve(None, stream, context)
        assert not opened
        assert stream.code == StreamClose.POLICY
    run(scenario())


def test_allowlist_watcher_checks_before_its_first_sleep(tmp_path):
    async def scenario():
        tunnel = tunnel_at(tmp_path / "hermes")
        listener = tunnel.make_listener(allowlist_poll_seconds=10)
        class Mux:
            done = asyncio.Event()
            async def close(self, code):
                self.code = code
                self.done.set()
        mux = Mux()
        await asyncio.wait_for(listener._watch_allowlist(mux, bytes(32)), 1)
        assert mux.code == SessionClose.REVOKED
    run(scenario())
