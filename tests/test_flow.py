import copy

import pytest
from cryptography.exceptions import InvalidTag

from src.crypto_engine import (
    aes_decrypt,
    aes_encrypt,
    decrypt_secure_payload,
    encrypt_secure_payload,
    generate_session_key,
    rsa_sign,
    rsa_verify,
    unwrap_session_key,
    wrap_session_key,
)
from src.key_manager import generate_rsa_keypair


@pytest.fixture()
def alice_keys():
    return generate_rsa_keypair()


@pytest.fixture()
def bob_keys():
    return generate_rsa_keypair()


def test_aes_gcm_round_trip():
    key = generate_session_key()
    ciphertext, nonce, tag = aes_encrypt(b"Du lieu bi mat", key)

    assert aes_decrypt(ciphertext, key, nonce, tag) == b"Du lieu bi mat"
    assert len(key) == 32
    assert len(nonce) == 12
    assert len(tag) == 16


def test_aes_gcm_detects_one_bit_change():
    key = generate_session_key()
    ciphertext, nonce, tag = aes_encrypt(b"Hop dong 500 trieu", key)
    changed = bytearray(ciphertext)
    changed[len(changed) // 2] ^= 1

    with pytest.raises(InvalidTag):
        aes_decrypt(bytes(changed), key, nonce, tag)


def test_rsa_pss_signature_rejects_modified_message(alice_keys):
    private_key, public_key = alice_keys
    signature = rsa_sign(b"Thong diep goc", private_key)

    assert rsa_verify(b"Thong diep goc", signature, public_key) is True
    assert rsa_verify(b"Thong diep bi sua", signature, public_key) is False


def test_rsa_oaep_only_unwraps_with_the_intended_recipient(bob_keys):
    bob_private, bob_public = bob_keys
    mallory_private, _ = generate_rsa_keypair()
    session_key = generate_session_key()
    wrapped = wrap_session_key(session_key, bob_public)

    assert unwrap_session_key(wrapped, bob_private) == session_key
    with pytest.raises(ValueError):
        unwrap_session_key(wrapped, mallory_private)


def test_complete_sign_encrypt_decrypt_verify_flow(alice_keys, bob_keys):
    alice_private, alice_public = alice_keys
    bob_private, bob_public = bob_keys
    message = {
        "subject": "Hop dong bao mat",
        "body": "Gia tri hop dong la 500 trieu VND.",
        "attachment": None,
    }

    envelope = encrypt_secure_payload(
        message=message,
        sender="alice@example.com",
        recipient="bob@example.com",
        sender_private_key=alice_private,
        recipient_public_key=bob_public,
    )
    result = decrypt_secure_payload(
        envelope=envelope,
        recipient_private_key=bob_private,
        sender_public_key=alice_public,
    )

    assert result.message == message
    assert result.signature_valid is True
    assert envelope["protocol"] == "SECURE-HYBRID-MAIL"
    assert envelope["crypto_metadata"]["sym_algo"] == "AES-256-GCM"


def test_complete_flow_rejects_tampered_ciphertext(alice_keys, bob_keys):
    alice_private, alice_public = alice_keys
    bob_private, bob_public = bob_keys
    envelope = encrypt_secure_payload(
        message={"subject": "Secret", "body": "Noi dung", "attachment": None},
        sender="alice@example.com",
        recipient="bob@example.com",
        sender_private_key=alice_private,
        recipient_public_key=bob_public,
    )
    tampered = copy.deepcopy(envelope)
    ciphertext = bytearray(__import__("base64").b64decode(tampered["payload"]["ciphertext"]))
    ciphertext[0] ^= 1
    tampered["payload"]["ciphertext"] = __import__("base64").b64encode(ciphertext).decode("ascii")

    with pytest.raises(InvalidTag):
        decrypt_secure_payload(tampered, bob_private, alice_public)
