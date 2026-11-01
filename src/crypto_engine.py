"""Hybrid encryption primitives and the Secure Hybrid Mail envelope."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


PROTOCOL = "SECURE-HYBRID-MAIL"
VERSION = "1.0"


@dataclass(frozen=True)
class DecryptionResult:
    message: dict[str, Any]
    signature_valid: bool
    sender: str
    recipient: str
    timestamp: str


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def generate_session_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def aes_encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key.")
    nonce = os.urandom(12)
    ciphertext_and_tag = AESGCM(key).encrypt(nonce, plaintext, None)
    return ciphertext_and_tag[:-16], nonce, ciphertext_and_tag[-16:]


def aes_decrypt(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
    if len(key) != 32 or len(nonce) != 12 or len(tag) != 16:
        raise ValueError("Invalid AES-GCM key, nonce, or tag length.")
    return AESGCM(key).decrypt(nonce, ciphertext + tag, None)


def rsa_sign(data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )


def rsa_verify(data: bytes, signature: bytes, public_key: rsa.RSAPublicKey) -> bool:
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return False
    return True


def wrap_session_key(session_key: bytes, receiver_public_key: rsa.RSAPublicKey) -> bytes:
    return receiver_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def unwrap_session_key(wrapped_key: bytes, receiver_private_key: rsa.RSAPrivateKey) -> bytes:
    return receiver_private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def encrypt_secure_payload(
    message: dict[str, Any],
    sender: str,
    recipient: str,
    sender_private_key: rsa.RSAPrivateKey,
    recipient_public_key: rsa.RSAPublicKey,
) -> dict[str, Any]:
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    signed_content = {
        "message": message,
        "sender": sender,
        "recipient": recipient,
        "timestamp": timestamp,
    }
    signature = rsa_sign(_canonical_json(signed_content), sender_private_key)
    signed_package = _canonical_json(
        {"content": signed_content, "signature": _b64encode(signature)}
    )

    session_key = generate_session_key()
    ciphertext, nonce, tag = aes_encrypt(signed_package, session_key)
    wrapped_key = wrap_session_key(session_key, recipient_public_key)

    return {
        "protocol": PROTOCOL,
        "version": VERSION,
        "sender": sender,
        "recipient": recipient,
        "timestamp": timestamp,
        "crypto_metadata": {
            "asym_algo": "RSA-2048-OAEP-SHA256",
            "sym_algo": "AES-256-GCM",
            "hash_algo": "SHA-256",
            "sig_algo": "RSA-2048-PSS-SHA256",
        },
        "payload": {
            "wrapped_key": _b64encode(wrapped_key),
            "nonce": _b64encode(nonce),
            "tag": _b64encode(tag),
            "ciphertext": _b64encode(ciphertext),
        },
    }


def decrypt_secure_payload(
    envelope: dict[str, Any],
    recipient_private_key: rsa.RSAPrivateKey,
    sender_public_key: rsa.RSAPublicKey,
) -> DecryptionResult:
    if envelope.get("protocol") != PROTOCOL or envelope.get("version") != VERSION:
        raise ValueError("Unsupported Secure Hybrid Mail envelope.")

    payload = envelope["payload"]
    session_key = unwrap_session_key(
        _b64decode(payload["wrapped_key"]), recipient_private_key
    )
    plaintext = aes_decrypt(
        _b64decode(payload["ciphertext"]),
        session_key,
        _b64decode(payload["nonce"]),
        _b64decode(payload["tag"]),
    )
    signed_package = json.loads(plaintext.decode("utf-8"))
    content = signed_package["content"]
    signature_valid = rsa_verify(
        _canonical_json(content),
        _b64decode(signed_package["signature"]),
        sender_public_key,
    )
    return DecryptionResult(
        message=content["message"],
        signature_valid=signature_valid,
        sender=content["sender"],
        recipient=content["recipient"],
        timestamp=content["timestamp"],
    )


def envelope_to_json(envelope: dict[str, Any]) -> str:
    return json.dumps(envelope, ensure_ascii=False, indent=2)


def envelope_from_json(value: str) -> dict[str, Any]:
    if len(value.encode("utf-8")) > 15_000_000:
        raise ValueError("Envelope exceeds the 15 MB safety limit.")
    envelope = json.loads(value)
    if not isinstance(envelope, dict):
        raise ValueError("Envelope must be a JSON object.")
    return envelope
