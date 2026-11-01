"""RSA key lifecycle and PEM serialization helpers."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


PemSource = Union[str, bytes, Path]


def generate_rsa_keypair(
    key_size: int = 2048,
) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    if key_size < 2048:
        raise ValueError("RSA keys smaller than 2048 bits are not allowed.")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return private_key, private_key.public_key()


def private_key_to_pem(
    private_key: rsa.RSAPrivateKey, password: str | None = None
) -> bytes:
    encryption = (
        serialization.BestAvailableEncryption(password.encode("utf-8"))
        if password
        else serialization.NoEncryption()
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )


def public_key_to_pem(public_key: rsa.RSAPublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _read_pem(source: PemSource) -> bytes:
    if isinstance(source, bytes):
        return source
    if isinstance(source, Path):
        return source.read_bytes()
    if "-----BEGIN" in source:
        return source.encode("utf-8")
    return Path(source).read_bytes()


def load_private_key(
    source: PemSource, password: str | None = None
) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(
        _read_pem(source),
        password=password.encode("utf-8") if password else None,
    )
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("The PEM data is not an RSA private key.")
    return key


def load_public_key(source: PemSource) -> rsa.RSAPublicKey:
    key = serialization.load_pem_public_key(_read_pem(source))
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("The PEM data is not an RSA public key.")
    return key


def save_private_key(
    private_key: rsa.RSAPrivateKey,
    filepath: str | Path,
    password: str | None = None,
) -> Path:
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(private_key_to_pem(private_key, password))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def save_public_key(public_key: rsa.RSAPublicKey, filepath: str | Path) -> Path:
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(public_key_to_pem(public_key))
    return path


def public_key_fingerprint(public_key: rsa.RSAPublicKey) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(der).hexdigest().upper()
    return " ".join(digest[index : index + 4] for index in range(0, len(digest), 4))


def safe_contact_name(value: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip()).strip("._")
    if not clean:
        raise ValueError("Contact name is empty or invalid.")
    return clean[:80]
