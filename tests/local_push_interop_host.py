"""Production tunnel listener fixture for CozyKit's local-push interoperability test.

The parent process must isolate ``HOME`` and ``HERMES_HOME``. This fixture additionally keeps all
of its own state under a new temporary directory. One JSON object is written per stdout line:

* startup: address, pinned host public key and the preapproved phone private key;
* after stdin ``{"emit":true}``: ``{"emitted":true}`` after a real Emitter produced the event;
* after stdin ``{"revoke":true}``: ``{"revoked":true}`` after removing the approved phone;
* after stdin ``{"stall":true}``: ``{"stalled":true}``; the next notify subscription is held back
  before its "subscribed" marker until the next revoke;
* stdin EOF: stop the listener and exit.

The private key is test material generated for this process only.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1].parent))

from cozychat.devices import DeviceStore  # noqa: E402
from cozychat.events import Emitter  # noqa: E402
from cozychat.feed import LiveFeed  # noqa: E402
from cozychat.local_push import NotifySubscriptions  # noqa: E402
from cozychat.push import Outbox  # noqa: E402
from cozychat.relay import noise, pairing, services  # noqa: E402
from cozychat.relay.host import Listener, ListenerConfig  # noqa: E402
from cozychat.relay.services import ApiTarget  # noqa: E402
from cozychat.state import SharedState  # noqa: E402
from tunnel_phone import loopback_binds  # noqa: E402


def emit(value: dict) -> None:
    sys.stdout.write(json.dumps(value, separators=(",", ":")) + "\n")
    sys.stdout.flush()


class RecordingRelay:
    def __init__(self):
        self.calls = 0

    def notify(self, *args):
        self.calls += 1
        return 202, None


stalling, released = threading.Event(), threading.Event()
_refresh = NotifySubscriptions.refresh


def _stalled_refresh(self, *args, **kwargs):
    if stalling.is_set() and not released.is_set():
        released.wait(8)  # bounded, so a failed test cannot hang the fixture
    return _refresh(self, *args, **kwargs)


NotifySubscriptions.refresh = _stalled_refresh


def approve(store: pairing.PairingStore, private: bytes) -> None:
    window = store.open_window({"push": False})
    attempt = store.begin_attempt(window.id, noise.public_key(private),
                                  "Local Push Interop", "000000")
    if attempt is None or not store.decide(attempt, True) or store.settle(attempt) != "approved":
        raise RuntimeError("could not preapprove fixture phone")


async def main() -> int:
    root = Path(tempfile.mkdtemp(prefix="cz-local-push-"))
    state = SharedState(root / "shared")
    feed = LiveFeed(state)
    store = pairing.PairingStore(root / "relay")
    phone_private = noise.generate_private_key()
    approve(store, phone_private)
    capabilities = lambda hints: services.capability_document(
        plugin_version="0.6.0", state_version="shared-v1", lan_addresses=hints,
        push_available=True, push_paired=True, notify_available=True,
        api_profiles=("default",))
    listener = Listener(store, ListenerConfig(port=0, interfaces=loopback_binds,
                                              advertise_mdns=False),
                        capabilities=capabilities,
                        api=lambda: ApiTarget(1, None, profiles=("default",)), feed=feed)
    await listener.start()
    outbox = Outbox(state.root / "outbox.sqlite")  # where the listener's fallbacks land
    devices = DeviceStore(state.root)
    key = "local-push-interop-key"
    devices.add({"device_id": "interop", "push_id": "test-only", "key_hex": key.encode().hex()})
    relay = RecordingRelay()
    emitter = Emitter(devices, outbox, {"profile_name": "default"}, feed=feed)
    turns = 0
    try:
        emit({"address": f"127.0.0.1:{listener.port}",
              "host_public_key": store.host_public().hex(),
              "phone_private_key": phone_private.hex(),
              "phone_name": "Local Push Interop", "profile": "default",
              "push_key": key,
              "relay_proto": 1, "approved": True})
        while True:
            line = await asyncio.to_thread(sys.stdin.readline)
            if not line:
                break
            try:
                request = json.loads(line)
            except ValueError:
                continue
            if request == {"emit": True}:
                turns += 1
                emitter.stream_delta(session_id="local-push-interop", delta="Home Wi-Fi reply")
                emitter.session_end(session_id="local-push-interop", platform="api_server",
                                    turn_id=f"local-push-turn-{turns}")
                outbox.drain(relay, devices)
                emit({"emitted": True, "relay_calls": relay.calls})
            elif request == {"stall": True}:
                stalling.set()
                emit({"stalled": True})
            elif request == {"revoke": True}:
                emit({"revoked": store.remove_phone(noise.public_key(phone_private))})
                await asyncio.sleep(0.5)  # let the allowlist poll close the session first
                released.set()
    finally:
        await listener.stop()
        outbox.close()
        state.close()
        shutil.rmtree(root, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
