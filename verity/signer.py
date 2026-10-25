"""Signing and the canonical signed-message construction."""
import base64
import hashlib
import json
from datetime import datetime, timezone

from . import keys
from .errors import EMPTY_INPUT, MAX_DOC_BYTES

FORMAT = "VeritySign"
VERSION = 1
ALG = "Ed25519"
_PREFIX = b"VeritySign-v1\x00"


def build_message(alg: str, digest: bytes, size: int) -> bytes:
    """Domain-separated, algorithm- and size-bound bytes that are actually signed."""
    return _PREFIX + alg.encode() + b"\x00" + digest + size.to_bytes(8, "big")


def sign_document(doc: bytes, private_pem: bytes, doc_name: str = "document") -> bytes:
    """Return the .vsig file contents (JSON bytes)."""
    if not doc:
        raise ValueError(EMPTY_INPUT)
    if len(doc) > MAX_DOC_BYTES:
        raise ValueError("document too large")
    priv = keys.load_private_key(private_pem)
    digest = hashlib.sha256(doc).digest()
    sig = priv.sign(build_message(ALG, digest, len(doc)))
    record = {
        "format": FORMAT, "version": VERSION, "alg": ALG, "hash_alg": "SHA-256",
        "doc_sha256": digest.hex(), "doc_size": len(doc), "doc_name": doc_name,
        "signed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "key_fingerprint": keys.fingerprint(priv.public_key()),
        "signature": base64.b64encode(sig).decode(),
    }
    return json.dumps(record, indent=2).encode()
