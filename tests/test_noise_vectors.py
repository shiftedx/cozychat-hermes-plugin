"""``relay/noise.py`` against the frozen vectors, and the handshake's refusals.

``noise_vectors.json`` was produced by the ``noiseprotocol`` package (see
``generate_noise_vectors.py``), so reproducing it byte for byte is a check against an independent
implementation. This module needs only what Hermes ships; ``test_noise_interop.py`` holds the
tests that import ``noiseprotocol`` itself.
"""

import json
from pathlib import Path

import pytest

from cozychat.relay import noise

DOCUMENT = json.loads((Path(__file__).parent / "noise_vectors.json").read_text("utf-8"))
VECTORS = DOCUMENT["vectors"]


def _hex(vector, field):
    return bytes.fromhex(vector[field])


def test_the_file_pins_this_protocol():
    assert DOCUMENT["protocol_name"].encode("ascii") == noise.PROTOCOL_NAME
    assert bytes.fromhex(DOCUMENT["prologue_hex"]) == noise.PROLOGUE
    assert {vector["name"] for vector in VECTORS} == {"first_pairing", "reconnect", "rekey"}
    reconnect = next(vector for vector in VECTORS if vector["name"] == "reconnect")
    assert _hex(reconnect, "psk_hex") == noise.ZERO_PSK
    for vector in VECTORS:
        transport = vector["messages"][2:]
        assert sum(m["sender"] == "initiator" for m in transport) >= 3
        assert sum(m["sender"] == "responder" for m in transport) >= 3
        if vector["name"] != "rekey":
            assert vector["rekey_interval"] == noise.REKEY_INTERVAL


def test_the_rekey_vector_crosses_two_rekeys_in_each_direction():
    vector = next(vector for vector in VECTORS if vector["name"] == "rekey")
    interval = vector["rekey_interval"]
    assert 1 < interval < noise.REKEY_INTERVAL
    transport = vector["messages"][2:]
    for sender in ("initiator", "responder"):
        assert sum(m["sender"] == sender for m in transport) > 2 * interval


@pytest.mark.parametrize("vector", VECTORS, ids=[vector["name"] for vector in VECTORS])
def test_reproduces_every_vector(vector):
    """Both roles write exactly the vector's bytes, and each opens what the other wrote. The rekey
    interval is the vector's: production's 2^20 for the handshake vectors, lowered for ``rekey``."""
    phone_static = _hex(vector, "initiator_static_private_hex")
    host_static = _hex(vector, "responder_static_private_hex")
    assert noise.public_key(phone_static) == _hex(vector, "initiator_static_public_hex")
    assert noise.public_key(host_static) == _hex(vector, "responder_static_public_hex")
    psk = _hex(vector, "psk_hex")

    phone = noise.Initiator(
        phone_static,
        _hex(vector, "responder_static_public_hex"),
        psk,
        ephemeral_private=_hex(vector, "initiator_ephemeral_private_hex"),
    )
    host = noise.Responder(host_static, ephemeral_private=_hex(vector, "responder_ephemeral_private_hex"))
    first, second, *transport = vector["messages"]

    message_1 = phone.write_message_1(_hex(first, "payload_hex"))
    assert message_1 == _hex(first, "ciphertext_hex")
    assert host.read_message_1(message_1) == _hex(first, "payload_hex")
    assert host.remote_static == _hex(vector, "initiator_static_public_hex")

    message_2, host_session = host.write_message_2(psk, _hex(second, "payload_hex"))
    assert message_2 == _hex(second, "ciphertext_hex")
    payload_2, phone_session = phone.read_message_2(message_2)
    assert payload_2 == _hex(second, "payload_hex")

    assert phone_session.handshake_hash == host_session.handshake_hash == _hex(vector, "handshake_hash_hex")
    assert phone_session.remote_static == _hex(vector, "responder_static_public_hex")

    phone_session.rekey_interval = host_session.rekey_interval = vector["rekey_interval"]
    sessions = {"initiator": (phone_session, host_session), "responder": (host_session, phone_session)}
    for message in transport:
        writer, reader = sessions[message["sender"]]
        ciphertext = writer.encrypt(_hex(message, "payload_hex"))
        assert ciphertext == _hex(message, "ciphertext_hex")
        assert reader.decrypt(ciphertext) == _hex(message, "payload_hex")

    pairing = vector["pairing_code"]
    assert noise.pairing_code(phone_session.handshake_hash, pairing["phone_name"]) == pairing["code"]


def test_skipping_the_rekey_breaks_the_rekey_vector():
    """The rekey vector really pins Rekey(): at the production interval the first message after the
    lowered interval no longer matches the frozen bytes."""
    vector = next(vector for vector in VECTORS if vector["name"] == "rekey")
    phone = noise.Initiator(
        _hex(vector, "initiator_static_private_hex"),
        _hex(vector, "responder_static_public_hex"),
        _hex(vector, "psk_hex"),
        ephemeral_private=_hex(vector, "initiator_ephemeral_private_hex"),
    )
    first, second, *transport = vector["messages"]
    phone.write_message_1(_hex(first, "payload_hex"))
    _, session = phone.read_message_2(_hex(second, "ciphertext_hex"))
    sent = [message for message in transport if message["sender"] == "initiator"]
    interval = vector["rekey_interval"]
    for message in sent[:interval]:
        assert session.encrypt(_hex(message, "payload_hex")) == _hex(message, "ciphertext_hex")
    after = sent[interval]
    assert session.encrypt(_hex(after, "payload_hex")) != _hex(after, "ciphertext_hex")


def _keys():
    phone, host = noise.generate_private_key(), noise.generate_private_key()
    return phone, host, noise.public_key(host)


def test_a_wrong_psk_is_not_detectable_from_message_1_and_fails_the_phone_at_message_2():
    """IKpsk2 mixes the psk after message 1, so the host replies before it can know (rule P1)."""
    phone_static, host_static, host_public = _keys()
    phone = noise.Initiator(phone_static, host_public, b"\x01" * 32)
    host = noise.Responder(host_static)
    assert host.read_message_1(phone.write_message_1(b"hi")) == b"hi"
    message_2, _ = host.write_message_2(b"\x02" * 32)
    with pytest.raises(noise.NoiseError):
        phone.read_message_2(message_2)


def test_message_1_for_another_computer_is_refused_and_the_handshake_is_spent():
    phone_static, host_static, _ = _keys()
    phone = noise.Initiator(phone_static, noise.public_key(noise.generate_private_key()), noise.ZERO_PSK)
    host = noise.Responder(host_static)
    with pytest.raises(noise.NoiseError):
        host.read_message_1(phone.write_message_1())
    assert host.remote_static is None
    with pytest.raises(noise.NoiseError):
        host.write_message_2(noise.ZERO_PSK)


@pytest.mark.parametrize("damage", ["truncate", "flip"])
def test_a_damaged_transport_frame_is_refused_without_desyncing_the_session(damage):
    phone_static, host_static, host_public = _keys()
    phone = noise.Initiator(phone_static, host_public, noise.ZERO_PSK)
    host = noise.Responder(host_static)
    host.read_message_1(phone.write_message_1())
    message_2, host_session = host.write_message_2(noise.ZERO_PSK)
    _, phone_session = phone.read_message_2(message_2)

    frame = phone_session.encrypt(b"hello")
    bad = frame[:10] if damage == "truncate" else frame[:-1] + bytes([frame[-1] ^ 1])
    with pytest.raises(noise.NoiseError):
        host_session.decrypt(bad)
    assert host_session.decrypt(frame) == b"hello"


def test_pairing_code_is_six_digits_and_depends_on_the_phone_name():
    handshake_hash = bytes(range(32))
    code = noise.pairing_code(handshake_hash, "Kyle’s iPhone")
    assert len(code) == 6 and code.isdigit()
    assert code != noise.pairing_code(handshake_hash, "Kyle's iPhone")
