"""The sealed envelope, against the app's own bytes.

``vectors.json`` carries the vector CozyChat's PushCrypto tests pin plus one payload this module
sealed. Opening the first proves the plugin derives and opens exactly what the app does; the Swift
side opens the second, which is what proves the direction that actually matters in production.
"""

import base64
import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from cozychat import push

VECTORS = json.loads((Path(__file__).parent / "vectors.json").read_text("utf-8"))


def _key(vector):
    return bytes.fromhex(vector["key_material_hex"])


def test_opens_the_apps_frozen_ciphertext():
    vector = VECTORS["app_vector"]
    assert push.open_sealed(_key(vector), vector["ciphertext_b64url"]) == vector["payload"]


def test_swift_opens_what_the_plugin_sealed():
    """The committed plugin_sealed bytes are the ones HermesPluginReleaseTests decrypts."""
    vector = VECTORS["plugin_sealed"]
    assert push.open_sealed(_key(vector), vector["ciphertext_b64url"]) == vector["payload"]


def test_seal_round_trips_and_uses_a_fresh_nonce():
    key = _key(VECTORS["app_vector"])
    payload = {"kind": "message", "threadId": "bot:hermes", "agentName": "hermes", "preview": "hi"}
    first, second = push.seal(key, payload), push.seal(key, payload)
    assert first != second
    assert push.open_sealed(key, first) == payload


def test_wire_form_is_unpadded_base64url_of_nonce_ciphertext_tag():
    sealed = push.seal(b"test-push-key", {"kind": "message"})
    assert "=" not in sealed and "+" not in sealed and "/" not in sealed
    raw = base64.urlsafe_b64decode(sealed + "=" * (-len(sealed) % 4))
    assert len(raw) == 12 + len(b'{"kind":"message"}') + 16


def test_a_wrong_key_does_not_open_the_envelope():
    sealed = push.seal(b"test-push-key", {"kind": "message"})
    with pytest.raises(Exception):
        push.open_sealed(b"another-push-key", sealed)


@pytest.mark.parametrize("byte_index", [12, -1], ids=["ciphertext", "tag"])
def test_tampering_authenticated_ciphertext_or_tag_is_refused(byte_index):
    """Every ciphertext and tag byte is authenticated; this test leaves the nonce intact."""
    key = b"test-push-key"
    sealed = push.seal(key, {"kind": "message"})
    raw = bytearray(base64.urlsafe_b64decode(sealed + "=" * (-len(sealed) % 4)))
    raw[byte_index] ^= 1
    tampered = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    with pytest.raises(InvalidTag):
        push.open_sealed(key, tampered)


def test_a_decoded_envelope_shorter_than_nonce_and_tag_is_refused():
    """A 27-byte envelope has a nonce and only 15 bytes where AES-GCM needs its 16-byte tag."""
    too_short = base64.urlsafe_b64encode(b"\0" * 27).decode("ascii").rstrip("=")

    with pytest.raises(InvalidTag):
        push.open_sealed(b"test-push-key", too_short)


def test_unicode_payload_round_trips_through_canonical_json():
    payload = {"kind": "message", "preview": "Café… こんにちは 👋🏽", "threadId": "bot:hermes"}
    sealed = push.seal(b"test-push-key", payload)

    assert push.open_sealed(b"test-push-key", sealed) == payload
