"""Ed25519 key handling (uses the `cryptography` library only)."""
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)


def generate_keypair():
    """Return (private_pem, public_pem) as bytes. Private key is unencrypted."""
    priv = Ed25519PrivateKey.generate()
    private_pem = priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    public_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return private_pem, public_pem


def load_public_key(pem: bytes) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("not an Ed25519 public key")
    return key


def load_private_key(pem: bytes) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("not an Ed25519 private key")
    return key


def raw_public_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def fingerprint(key: Ed25519PublicKey) -> str:
    """SHA-256 of the raw 32-byte public key, hex."""
    return hashlib.sha256(raw_public_bytes(key)).hexdigest()


def short_fp(fp: str) -> str:
    return ":".join(fp[i:i + 4] for i in range(0, 32, 4))
