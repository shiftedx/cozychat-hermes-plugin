"""Derive ``noise_vectors.json`` from fixed seeds, with the ``noiseprotocol`` package as the engine.

Usage, from ``integrations/hermes-plugin`` with the dev requirements installed::

    python cozychat/tests/generate_noise_vectors.py           # rewrite noise_vectors.json
    python cozychat/tests/generate_noise_vectors.py --check   # exit 1 if the file is stale

The vectors come from ``noiseprotocol``, not from ``cozychat.relay.noise``, so that
``test_noise_vectors.py`` checks this plugin's implementation against an independent one rather
than against itself. Every key is ``SHA-256(SEED_DOMAIN "/" vector "/" role)``; nothing is random,
so the same seeds always give the same bytes (``test_noise_interop.py`` holds the file to that).

The pairing code is computed here directly from the spec's formula, again independently of the
plugin: ``HMAC-SHA256(h, "cozychat-pair-code" || utf8(phone name))`` as a big-endian integer
modulo 10^6, zero-padded to six digits.

Rekey (contract section 2) is by message count: each side calls Noise ``Rekey()`` on its sending
cipher after every ``REKEY_INTERVAL`` (2^20) messages it has sent, and on its receiving cipher after
every 2^20 it has received. A session that crosses 2^20 messages is too slow to freeze, so the
``rekey`` vector lowers the interval to ``VECTOR_REKEY_INTERVAL`` (4) and records it in
``rekey_interval``; an implementation reproduces it by lowering its own internal interval to that
value. The other vectors record the production interval, which they never reach.

Payloads are opaque test bytes. What the tunnel actually puts in message 1, message 2 and the
transport frames is the contract's business (``docs/relay-tunnel-v1.md``), not these vectors'.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
import warnings
from pathlib import Path
from typing import Any, Dict, List, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from noise.connection import Keypair, NoiseConnection

VECTORS_PATH = Path(__file__).with_name("noise_vectors.json")

PROTOCOL_NAME = "Noise_IKpsk2_25519_ChaChaPoly_SHA256"
PROLOGUE = b"cozychat-relay-v1"
SEED_DOMAIN = "cozychat-noise-vectors-v1"
PHONE_NAME = "Kyle’s iPhone"  # iOS's default device names use a typographic apostrophe
# The contract's rekey interval, and the lowered one the rekey vector uses so it crosses several rekeys
# in each direction within a few dozen messages.
REKEY_INTERVAL = 1 << 20
VECTOR_REKEY_INTERVAL = 4

# The transport frames of the first two vectors, in order, as (sender, plaintext).
_TRANSPORT = [
    ("initiator", b"phone -> computer, frame 1"),
    ("responder", b"computer -> phone, frame 1"),
    ("initiator", b""),
    ("responder", b"computer -> phone, frame 2"),
    ("initiator", b"phone -> computer, frame 3"),
    ("responder", b"computer -> phone, frame 3"),
]

def _rekey_transport() -> List[Tuple[str, bytes]]:
    """Eleven frames each way, in bursts of uneven length so the two directions' counters never move
    together: each direction crosses its rekey after its 4th and 8th message, at different points in
    wire order, and sends three more under the twice-rekeyed key."""
    bursts = [("initiator", 3), ("responder", 1), ("initiator", 2), ("responder", 5), ("initiator", 4),
              ("responder", 2), ("initiator", 2), ("responder", 3)]
    frames: List[Tuple[str, bytes]] = []
    counts = {"initiator": 0, "responder": 0}
    arrow = {"initiator": "phone -> computer", "responder": "computer -> phone"}
    for sender, length in bursts:
        for _ in range(length):
            counts[sender] += 1
            frames.append((sender, b"%s, frame %d" % (arrow[sender].encode("ascii"), counts[sender])))
    assert counts == {"initiator": 11, "responder": 11}
    return frames


# (name, what it stands for, psk role or None for the zero psk, message 1 payload, message 2
# payload, transport frames, rekey interval).
_VECTORS = [
    (
        "first_pairing",
        "A new phone scanned the QR: the psk is the QR's pairing secret.",
        "psk",
        b"phone hello: first pairing",
        b"computer hello: first pairing",
        _TRANSPORT,
        REKEY_INTERVAL,
    ),
    (
        "reconnect",
        "The same phone, already approved, reconnects: the psk is 32 zero bytes. Same static keys "
        "as first_pairing, fresh ephemerals, and an empty message 2 payload.",
        None,
        b"phone hello: reconnect",
        b"",
        _TRANSPORT,
        REKEY_INTERVAL,
    ),
    (
        "rekey",
        "Count-only rekey with the interval lowered to rekey_interval (production uses 2^20): each "
        "side calls Rekey() on its sending cipher after every rekey_interval messages it sent and on "
        "its receiving cipher after every rekey_interval messages it received. Eleven transport "
        "messages each way cross two rekeys in each direction. A reconnect (zero psk) with its own "
        "ephemerals.",
        None,
        b"phone hello: rekey",
        b"",
        _rekey_transport(),
        VECTOR_REKEY_INTERVAL,
    ),
]


def seed(vector: str, role: str) -> bytes:
    return hashlib.sha256(f"{SEED_DOMAIN}/{vector}/{role}".encode("utf-8")).digest()


def public_hex(private_key: bytes) -> str:
    return (
        X25519PrivateKey.from_private_bytes(private_key)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )


def pairing_code(handshake_hash: bytes, phone_name: str) -> str:
    digest = hmac.new(handshake_hash, b"cozychat-pair-code" + phone_name.encode("utf-8"), hashlib.sha256).digest()
    return "%06d" % (int.from_bytes(digest, "big") % 1_000_000)


def _connection(as_initiator: bool, psk: bytes, static: bytes, ephemeral: bytes, remote_static: bytes = b"") -> NoiseConnection:
    connection = NoiseConnection.from_name(PROTOCOL_NAME.encode("ascii"))
    if as_initiator:
        connection.set_as_initiator()
        connection.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, remote_static)
    else:
        connection.set_as_responder()
    connection.set_psks(psk)
    connection.set_prologue(PROLOGUE)
    connection.set_keypair_from_private_bytes(Keypair.STATIC, static)
    with warnings.catch_warnings():
        # The package warns that a fixed ephemeral is for testing only, which is what this is.
        warnings.simplefilter("ignore", UserWarning)
        connection.set_keypair_from_private_bytes(Keypair.EPHEMERAL, ephemeral)
        connection.start_handshake()
    return connection


def _vector(name: str, description: str, psk_role, payload_1: bytes, payload_2: bytes,
            transport: List[Tuple[str, bytes]], rekey_interval: int) -> Dict[str, Any]:
    # Static keys belong to the phone and the computer, not to a vector, so reconnect reuses them.
    phone_static, host_static = seed("statics", "phone"), seed("statics", "computer")
    phone_ephemeral, host_ephemeral = seed(name, "phone-ephemeral"), seed(name, "computer-ephemeral")
    psk = seed(name, psk_role) if psk_role else bytes(32)
    host_public = bytes.fromhex(public_hex(host_static))

    phone = _connection(True, psk, phone_static, phone_ephemeral, host_public)
    host = _connection(False, psk, host_static, host_ephemeral)

    messages: List[Dict[str, str]] = []

    def record(sender: str, payload: bytes, ciphertext: bytes) -> None:
        messages.append({"sender": sender, "payload_hex": payload.hex(), "ciphertext_hex": ciphertext.hex()})

    message_1 = phone.write_message(payload_1)
    assert host.read_message(message_1) == payload_1
    record("initiator", payload_1, message_1)
    message_2 = host.write_message(payload_2)
    assert phone.read_message(message_2) == payload_2
    record("responder", payload_2, message_2)
    assert phone.handshake_finished and host.handshake_finished
    handshake_hash = phone.get_handshake_hash()
    assert handshake_hash == host.get_handshake_hash()

    ends: Dict[str, Tuple[NoiseConnection, NoiseConnection]] = {"initiator": (phone, host), "responder": (host, phone)}
    sent = {"initiator": 0, "responder": 0}
    for sender, plaintext in transport:
        writer, reader = ends[sender]
        ciphertext = writer.encrypt(plaintext)
        assert reader.decrypt(ciphertext) == plaintext
        record(sender, plaintext, ciphertext)
        # One message sent by this sender is one received by its peer, so both counters are the same
        # number: rekey the writer's sending cipher and the reader's receiving cipher together.
        sent[sender] += 1
        if sent[sender] % rekey_interval == 0:
            writer.rekey_outbound_cipher()
            reader.rekey_inbound_cipher()

    return {
        "name": name,
        "description": description,
        "initiator_static_private_hex": phone_static.hex(),
        "initiator_static_public_hex": public_hex(phone_static),
        "initiator_ephemeral_private_hex": phone_ephemeral.hex(),
        "responder_static_private_hex": host_static.hex(),
        "responder_static_public_hex": public_hex(host_static),
        "responder_ephemeral_private_hex": host_ephemeral.hex(),
        "psk_hex": psk.hex(),
        "rekey_interval": rekey_interval,
        "messages": messages,
        "handshake_hash_hex": handshake_hash.hex(),
        "pairing_code": {"phone_name": PHONE_NAME, "code": pairing_code(handshake_hash, PHONE_NAME)},
    }


def build() -> str:
    """The file's exact contents."""
    document = {
        "protocol_name": PROTOCOL_NAME,
        "prologue_hex": PROLOGUE.hex(),
        "generator": "integrations/hermes-plugin/cozychat/tests/generate_noise_vectors.py",
        "seed_domain": SEED_DOMAIN,
        "notes": [
            "Generated by the noiseprotocol package from fixed seeds; regenerate, never hand-edit.",
            "Private keys are the raw 32 bytes X25519 takes (clamped by X25519 itself, as in "
            "RFC 7748); public keys are derived from them.",
            "Messages are in wire order. The first two are the handshake; the rest are transport "
            "messages, each with empty associated data and its sender's next nonce.",
            "Rekey is by message count only: each side calls Noise Rekey() on its sending cipher "
            "after every rekey_interval messages it sent and on its receiving cipher after every "
            "rekey_interval messages it received; the nonce is not reset. Production uses 2^20; "
            "the rekey vector lowers it so the file can freeze messages across two rekeys each way.",
            "pairing_code.code = HMAC-SHA256(handshake_hash, 'cozychat-pair-code' || "
            "utf8(phone_name)) as a big-endian integer mod 10^6, zero-padded to 6 digits.",
        ],
        "vectors": [_vector(*spec) for spec in _VECTORS],
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="exit 1 if the checked-in file differs")
    arguments = parser.parse_args(argv)
    contents = build()
    if arguments.check:
        if VECTORS_PATH.read_text("utf-8") != contents:
            print(f"{VECTORS_PATH.name} is stale; run {Path(__file__).name} to regenerate it", file=sys.stderr)
            return 1
        return 0
    VECTORS_PATH.write_text(contents, "utf-8")
    print(f"Wrote {VECTORS_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
