"""The vectors are reproducible, and ``relay/noise.py`` interoperates with ``noiseprotocol`` live.

Needs the dev requirements (``requirements-dev.txt``): ``noiseprotocol`` is a test-only reference
implementation and never a dependency of the installed plugin. The import is deliberately not an
``importorskip``: a CI run without it must fail, not quietly skip the only independent check.
"""

import warnings
from pathlib import Path

import pytest
from noise.connection import Keypair, NoiseConnection

import generate_noise_vectors
from cozychat.relay import noise

VECTORS_PATH = Path(__file__).parent / "noise_vectors.json"


def test_regenerating_from_the_seeds_is_byte_identical():
    assert generate_noise_vectors.build().encode("utf-8") == VECTORS_PATH.read_bytes(), (
        "noise_vectors.json is stale or hand-edited; run cozychat/tests/generate_noise_vectors.py"
    )


def _library(as_initiator, psk, static_private, remote_static=None):
    connection = NoiseConnection.from_name(noise.PROTOCOL_NAME)
    if as_initiator:
        connection.set_as_initiator()
        connection.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, remote_static)
    else:
        connection.set_as_responder()
    connection.set_psks(psk)
    connection.set_prologue(noise.PROLOGUE)
    connection.set_keypair_from_private_bytes(Keypair.STATIC, static_private)
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # live interop uses fresh ephemerals; any warning is a bug
        connection.start_handshake()
    return connection


PSKS = [pytest.param(b"\x07" * 32, id="first_pairing"), pytest.param(noise.ZERO_PSK, id="reconnect")]


@pytest.mark.parametrize("psk", PSKS)
def test_phone_is_the_library_and_the_computer_is_this_plugin(psk):
    phone_static, host_static = noise.generate_private_key(), noise.generate_private_key()
    phone = _library(True, psk, phone_static, noise.public_key(host_static))
    host = noise.Responder(host_static)

    assert host.read_message_1(phone.write_message(b"phone hello")) == b"phone hello"
    assert host.remote_static == noise.public_key(phone_static)
    message_2, session = host.write_message_2(psk, b"computer hello")
    assert phone.read_message(message_2) == b"computer hello"
    assert phone.handshake_finished
    assert phone.get_handshake_hash() == session.handshake_hash

    for index in range(3):
        assert session.decrypt(phone.encrypt(b"up %d" % index)) == b"up %d" % index
        assert phone.decrypt(session.encrypt(b"down %d" % index)) == b"down %d" % index


@pytest.mark.parametrize("psk", PSKS)
def test_phone_is_this_plugin_and_the_computer_is_the_library(psk):
    phone_static, host_static = noise.generate_private_key(), noise.generate_private_key()
    phone = noise.Initiator(phone_static, noise.public_key(host_static), psk)
    host = _library(False, psk, host_static)

    assert host.read_message(phone.write_message_1(b"phone hello")) == b"phone hello"
    payload, session = phone.read_message_2(host.write_message(b"computer hello"))
    assert payload == b"computer hello"
    assert host.handshake_finished
    assert host.get_handshake_hash() == session.handshake_hash

    for index in range(3):
        assert host.decrypt(session.encrypt(b"up %d" % index)) == b"up %d" % index
        assert session.decrypt(host.encrypt(b"down %d" % index)) == b"down %d" % index


def test_rekey_by_message_count_matches_the_library_in_both_directions():
    """R2: Noise ``Rekey()`` on the sending cipher after every N messages sent and on the receiving
    cipher after every N received, with no signal. The library is told to rekey at the same counts;
    N is lowered from 2^20 so the test reaches several rekeys."""
    assert noise.REKEY_INTERVAL == 2**20
    interval = 3
    phone_static, host_static = noise.generate_private_key(), noise.generate_private_key()
    phone = _library(True, noise.ZERO_PSK, phone_static, noise.public_key(host_static))
    host = noise.Responder(host_static)
    host.read_message_1(phone.write_message(b""))
    message_2, session = host.write_message_2(noise.ZERO_PSK, b"")
    phone.read_message(message_2)
    session.rekey_interval = interval

    for index in range(1, 3 * interval + 2):
        assert session.decrypt(phone.encrypt(b"up %d" % index)) == b"up %d" % index
        if index % interval == 0:
            phone.rekey_outbound_cipher()
        assert phone.decrypt(session.encrypt(b"down %d" % index)) == b"down %d" % index
        if index % interval == 0:
            phone.rekey_inbound_cipher()


def test_a_peer_that_skips_the_rekey_cannot_read_on():
    phone_static, host_static = noise.generate_private_key(), noise.generate_private_key()
    phone = _library(True, noise.ZERO_PSK, phone_static, noise.public_key(host_static))
    host = noise.Responder(host_static)
    host.read_message_1(phone.write_message(b""))
    message_2, session = host.write_message_2(noise.ZERO_PSK, b"")
    phone.read_message(message_2)
    session.rekey_interval = 2
    for index in range(2):
        phone.decrypt(session.encrypt(b"x"))
    with pytest.raises(Exception):
        phone.decrypt(session.encrypt(b"after the rekey"))
