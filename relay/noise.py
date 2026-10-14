"""``Noise_IKpsk2_25519_ChaChaPoly_SHA256`` between the phone (initiator) and this plugin (responder).

Written from the Noise Protocol Framework, revision 34 (https://noiseprotocol.org/noise.html),
on ``cryptography`` alone, which Hermes already pins. The pattern::

    IKpsk2:
      <- s
      ...
      -> e, es, s, ss
      <- e, ee, se, psk

The phone knows this computer's static key from the pairing QR, so message 1 already encrypts the
phone's own static key and payload. The psk is the QR's pairing secret on a first pairing and
:data:`ZERO_PSK` on a reconnect, when the computer recognises the phone by its static key alone.

The responder's handshake is split in two on purpose: :meth:`Responder.read_message_1` returns the
phone's static key before any reply exists, so the caller can stay silent to a key it does not
know (no message 2, no error) and pick the psk to expect for one it does.

``tests/noise_vectors.json`` pins every byte of this module against vectors the ``noiseprotocol``
package produced; ``tests/test_noise_interop.py`` runs live handshakes against that package in both
directions. The Swift side opens the same file.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Optional, Tuple, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

PROTOCOL_NAME = b"Noise_IKpsk2_25519_ChaChaPoly_SHA256"
PROLOGUE = b"cozychat-relay-v1"
KEY_LEN = 32
TAG_LEN = 16
HASH_LEN = 32
PSK_LEN = 32
ZERO_PSK = bytes(PSK_LEN)
# Noise's own limit on any one message, handshake or transport, tag included.
MAX_MESSAGE_LEN = 65535
# 2^64 - 1 is reserved by the spec; a cipher refuses to reach it rather than wrap.
_MAX_NONCE = 2**64 - 1
# Rekey by message count only (rule R2): each side calls Noise ``Rekey()`` on its sending cipher
# after every 2^20 messages it sends, and on its receiving cipher after every 2^20 it receives, so
# both ends stay in step with no signal. No time-based rekey; reconnects bring fresh keys.
REKEY_INTERVAL = 1 << 20

PAIR_CODE_LABEL = b"cozychat-pair-code"

# A handshake that failed, or finished, takes no further messages.
_SPENT = -1

# e (32) + encrypted s (32 + tag) + encrypted payload (at least a tag).
MESSAGE_1_MIN_LEN = KEY_LEN + KEY_LEN + TAG_LEN + TAG_LEN
# e (32) + encrypted payload (at least a tag).
MESSAGE_2_MIN_LEN = KEY_LEN + TAG_LEN


class NoiseError(Exception):
    """A handshake or transport message was malformed, failed authentication, or came out of order.

    Deliberately carries no detail a peer could learn from: callers drop the connection silently.
    """


# --- primitives -----------------------------------------------------------------------------


def generate_private_key() -> bytes:
    """A fresh X25519 private key, as the 32 raw bytes every API here takes."""
    return _raw_private(X25519PrivateKey.generate())


def public_key(private_key: bytes) -> bytes:
    """The 32-byte X25519 public key for ``private_key``."""
    return _load_private(private_key).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _raw_private(key: X25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )


def _load_private(private_key: bytes) -> X25519PrivateKey:
    if len(private_key) != KEY_LEN:
        raise ValueError("an X25519 private key is 32 bytes")
    return X25519PrivateKey.from_private_bytes(bytes(private_key))


def _dh(private_key: bytes, public: bytes) -> bytes:
    try:
        return _load_private(private_key).exchange(X25519PublicKey.from_public_bytes(bytes(public)))
    except ValueError as error:
        # cryptography refuses a low-order point (an all-zero shared secret); so does Noise.
        raise NoiseError("invalid public key") from error


def _hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def _hkdf(chaining_key: bytes, input_key_material: bytes, outputs: int) -> Tuple[bytes, ...]:
    """Noise's HKDF (section 4.3): two or three 32-byte outputs."""
    temp_key = _hmac(chaining_key, input_key_material)
    output_1 = _hmac(temp_key, b"\x01")
    output_2 = _hmac(temp_key, output_1 + b"\x02")
    if outputs == 2:
        return output_1, output_2
    return output_1, output_2, _hmac(temp_key, output_2 + b"\x03")


def _nonce(counter: int) -> bytes:
    # ChaChaPoly: 32 bits of zeros, then the 64-bit counter little-endian (section 12.3).
    return b"\x00\x00\x00\x00" + struct.pack("<Q", counter)


# --- CipherState and SymmetricState (sections 5.1 and 5.2) ---------------------------------


class CipherState:
    """One direction of a session: a key and the next nonce."""

    def __init__(self, key: Optional[bytes] = None) -> None:
        self._key = key
        self._nonce = 0

    @property
    def has_key(self) -> bool:
        return self._key is not None

    def encrypt(self, associated_data: bytes, plaintext: bytes) -> bytes:
        if self._key is None:
            return bytes(plaintext)
        self._check_nonce()
        ciphertext = ChaCha20Poly1305(self._key).encrypt(_nonce(self._nonce), bytes(plaintext), associated_data)
        self._nonce += 1
        return ciphertext

    def decrypt(self, associated_data: bytes, ciphertext: bytes) -> bytes:
        if self._key is None:
            return bytes(ciphertext)
        self._check_nonce()
        if len(ciphertext) < TAG_LEN:
            raise NoiseError("message too short")
        try:
            plaintext = ChaCha20Poly1305(self._key).decrypt(_nonce(self._nonce), bytes(ciphertext), associated_data)
        except InvalidTag as error:
            # The nonce does not advance on a failure, as the spec requires.
            raise NoiseError("authentication failed") from error
        self._nonce += 1
        return plaintext

    def rekey(self) -> None:
        """Noise ``Rekey()`` (section 4.2): ``k = ENCRYPT(k, 2^64-1, "", zeros(32))[:32]``.
        The nonce carries on; it does not reset."""
        if self._key is None:
            return
        self._key = ChaCha20Poly1305(self._key).encrypt(_nonce(_MAX_NONCE), bytes(KEY_LEN), b"")[:KEY_LEN]

    def _check_nonce(self) -> None:
        if self._nonce >= _MAX_NONCE:
            raise NoiseError("nonce exhausted; reconnect")


class _SymmetricState:
    def __init__(self, prologue: bytes) -> None:
        # The name is longer than HASHLEN, so h starts as its hash (section 5.2, InitializeSymmetric).
        self.h = _hash(PROTOCOL_NAME)
        self.ck = self.h
        self.cipher = CipherState()
        self.mix_hash(prologue)

    def mix_hash(self, data: bytes) -> None:
        self.h = _hash(self.h + bytes(data))

    def mix_key(self, input_key_material: bytes) -> None:
        self.ck, key = _hkdf(self.ck, input_key_material, 2)
        self.cipher = CipherState(key)

    def mix_key_and_hash(self, input_key_material: bytes) -> None:
        self.ck, temp_hash, key = _hkdf(self.ck, input_key_material, 3)
        self.mix_hash(temp_hash)
        self.cipher = CipherState(key)

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        ciphertext = self.cipher.encrypt(self.h, plaintext)
        self.mix_hash(ciphertext)
        return ciphertext

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        plaintext = self.cipher.decrypt(self.h, ciphertext)
        self.mix_hash(ciphertext)
        return plaintext

    def split(self) -> Tuple[CipherState, CipherState]:
        key_1, key_2 = _hkdf(self.ck, b"", 2)
        return CipherState(key_1), CipherState(key_2)


# --- the session ---------------------------------------------------------------------------


class Session:
    """An established tunnel: one cipher each way, plus what both ends agreed on."""

    def __init__(self, send: CipherState, receive: CipherState, handshake_hash: bytes, remote_static: bytes,
                 *, rekey_interval: int = REKEY_INTERVAL) -> None:
        self._send = send
        self._receive = receive
        self.handshake_hash = handshake_hash
        self.remote_static = remote_static
        # Internal: production always uses REKEY_INTERVAL (2^20). Only the tests lower it, to reach a
        # rekey in a few messages and to reproduce the frozen ``rekey`` vector, which records the
        # lowered interval it was generated with. No config, environment or CLI value reaches it.
        self.rekey_interval = rekey_interval
        self._sent = 0
        self._received = 0

    def encrypt(self, plaintext: bytes) -> bytes:
        """One transport message. Associated data is empty, as in every Noise transport message."""
        if len(plaintext) + TAG_LEN > MAX_MESSAGE_LEN:
            raise ValueError("plaintext too long for one Noise message")
        ciphertext = self._send.encrypt(b"", plaintext)
        self._sent += 1
        if self._sent % self.rekey_interval == 0:
            self._send.rekey()
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) > MAX_MESSAGE_LEN:
            raise NoiseError("message too long")
        plaintext = self._receive.decrypt(b"", ciphertext)  # a failure counts for nothing
        self._received += 1
        if self._received % self.rekey_interval == 0:
            self._receive.rekey()
        return plaintext


def pairing_code(handshake_hash: bytes, phone_name: Union[str, bytes]) -> str:
    """The 6-digit code both screens show before the computer approves a new phone.

    ``HMAC-SHA256(h, "cozychat-pair-code" || utf8(phone name))`` read as a big-endian integer,
    modulo 10^6, zero-padded. ``h`` is the handshake hash, identical on both ends only when nobody
    sat in the middle.

    ``phone_name`` is the exact name the phone sent in message 1. Bytes are used as they are; a
    string is encoded to UTF-8. Nothing is trimmed, truncated or substituted: a display fallback
    such as ``Phone`` for an empty name never reaches this function.
    """
    if len(handshake_hash) != HASH_LEN:
        raise ValueError("the handshake hash is 32 bytes")
    name = phone_name if isinstance(phone_name, bytes) else phone_name.encode("utf-8")
    digest = _hmac(bytes(handshake_hash), PAIR_CODE_LABEL + name)
    return "%06d" % (int.from_bytes(digest, "big") % 1_000_000)


# --- the two roles -------------------------------------------------------------------------


def _check_psk(psk: bytes) -> bytes:
    if len(psk) != PSK_LEN:
        raise ValueError("a psk is 32 bytes")
    return bytes(psk)


def _check_payload(payload: bytes, overhead: int) -> bytes:
    if len(payload) + overhead > MAX_MESSAGE_LEN:
        raise ValueError("payload too long for one Noise message")
    return bytes(payload)


class Initiator:
    """The phone's half. Used here by tests and by the vector generator's cross-check."""

    def __init__(
        self,
        static_private: bytes,
        remote_static: bytes,
        psk: bytes,
        *,
        prologue: bytes = PROLOGUE,
        ephemeral_private: Optional[bytes] = None,
    ) -> None:
        """``ephemeral_private`` exists for test vectors only; leave it out everywhere else."""
        if len(remote_static) != KEY_LEN:
            raise ValueError("an X25519 public key is 32 bytes")
        self._s = bytes(static_private)
        self._s_public = public_key(self._s)
        self._rs = bytes(remote_static)
        self._psk = _check_psk(psk)
        self._e = bytes(ephemeral_private) if ephemeral_private is not None else None
        self._state = _SymmetricState(prologue)
        self._state.mix_hash(self._rs)  # pre-message: <- s
        self._step = 0

    def write_message_1(self, payload: bytes = b"") -> bytes:
        if self._step != 0:
            raise NoiseError("message 1 already written")
        payload = _check_payload(payload, MESSAGE_1_MIN_LEN)
        self._step = _SPENT  # until it succeeds: a failed handshake is never resumed
        state = self._state
        if self._e is None:
            self._e = generate_private_key()
        e_public = public_key(self._e)
        state.mix_hash(e_public)  # e
        state.mix_key(e_public)  # ... and, in a psk handshake, MixKey(e) as well
        state.mix_key(_dh(self._e, self._rs))  # es
        encrypted_static = state.encrypt_and_hash(self._s_public)  # s
        state.mix_key(_dh(self._s, self._rs))  # ss
        message = e_public + encrypted_static + state.encrypt_and_hash(payload)
        self._step = 1
        return message

    def read_message_2(self, message: bytes) -> Tuple[bytes, Session]:
        """The responder's payload and the established session."""
        if self._step != 1:
            raise NoiseError("message 2 out of order")
        message = bytes(message)
        if not MESSAGE_2_MIN_LEN <= len(message) <= MAX_MESSAGE_LEN:
            raise NoiseError("malformed message 2")
        self._step = _SPENT  # until it succeeds: a failed handshake is never resumed
        state = self._state
        re = message[:KEY_LEN]
        state.mix_hash(re)  # e
        state.mix_key(re)
        state.mix_key(_dh(self._e, re))  # ee
        state.mix_key(_dh(self._s, re))  # se
        state.mix_key_and_hash(self._psk)  # psk
        payload = state.decrypt_and_hash(message[KEY_LEN:])
        self._step = 2
        send, receive = state.split()
        session = Session(send, receive, state.h, self._rs)
        self._forget()
        return payload, session

    def _forget(self) -> None:
        self._e = None
        self._psk = ZERO_PSK
        self._state = None  # type: ignore[assignment]


class Responder:
    """This computer's half.

    Call :meth:`read_message_1`, look at :attr:`remote_static`, decide (stay silent, or choose the
    psk to expect), then call :meth:`write_message_2`. An instance handles one handshake.
    """

    def __init__(
        self,
        static_private: bytes,
        *,
        prologue: bytes = PROLOGUE,
        ephemeral_private: Optional[bytes] = None,
    ) -> None:
        """``ephemeral_private`` exists for test vectors only; leave it out everywhere else."""
        self._s = bytes(static_private)
        self._e = bytes(ephemeral_private) if ephemeral_private is not None else None
        self._state = _SymmetricState(prologue)
        self._state.mix_hash(public_key(self._s))  # pre-message: <- s
        self._re: Optional[bytes] = None
        self.remote_static: Optional[bytes] = None
        self._step = 0

    def read_message_1(self, message: bytes) -> bytes:
        """The phone's payload. Afterwards :attr:`remote_static` holds the phone's static key."""
        if self._step != 0:
            raise NoiseError("message 1 already read")
        message = bytes(message)
        if not MESSAGE_1_MIN_LEN <= len(message) <= MAX_MESSAGE_LEN:
            raise NoiseError("malformed message 1")
        self._step = _SPENT  # until it succeeds: a failed handshake is never resumed
        state = self._state
        re = message[:KEY_LEN]
        state.mix_hash(re)  # e
        state.mix_key(re)
        state.mix_key(_dh(self._s, re))  # es
        remote_static = state.decrypt_and_hash(message[KEY_LEN : 2 * KEY_LEN + TAG_LEN])  # s
        state.mix_key(_dh(self._s, remote_static))  # ss
        payload = state.decrypt_and_hash(message[2 * KEY_LEN + TAG_LEN :])
        self._re = re
        self.remote_static = remote_static
        self._step = 1
        return payload

    def write_message_2(self, psk: bytes, payload: bytes = b"") -> Tuple[bytes, Session]:
        """Message 2 and the session. The phone proves it knew ``psk`` only with its first frame."""
        if self._step != 1:
            raise NoiseError("message 2 out of order")
        psk = _check_psk(psk)
        payload = _check_payload(payload, MESSAGE_2_MIN_LEN)
        self._step = _SPENT  # one attempt at message 2, whatever happens
        state = self._state
        if self._e is None:
            self._e = generate_private_key()
        e_public = public_key(self._e)
        state.mix_hash(e_public)  # e
        state.mix_key(e_public)
        state.mix_key(_dh(self._e, self._re))  # ee
        state.mix_key(_dh(self._e, self.remote_static))  # se
        state.mix_key_and_hash(psk)  # psk
        message = e_public + state.encrypt_and_hash(payload)
        initiator_to_responder, responder_to_initiator = state.split()
        session = Session(responder_to_initiator, initiator_to_responder, state.h, self.remote_static)
        self._e = None
        self._state = None  # type: ignore[assignment]
        return message, session
