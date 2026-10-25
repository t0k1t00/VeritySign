"""Verification: parse .vsig, hash the document, call the library's verify()."""
import base64
import binascii
import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

from cryptography.exceptions import InvalidSignature

from . import errors as E
from . import keys, trust
from .signer import ALG, FORMAT, VERSION, build_message


@dataclass
class VerificationResult:
    signature_valid: bool
    status: str
    failure_reason: Optional[str]
    doc_name: str = ""
    doc_sha256: str = ""
    doc_size: int = 0
    claimed_sha256: Optional[str] = None
    integrity_ok: Optional[bool] = None
    alg: Optional[str] = None
    key_fingerprint: Optional[str] = None
    signer_trusted: bool = False
    trust_label: Optional[str] = None
    signed_at_claimed: Optional[str] = None
    verified_at: str = ""
    notes: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _fail(status, **kw):
    return VerificationResult(False, status, E.EXPLANATIONS[status][0],
                              verified_at=_now(), **kw)


def _parse_sig(sig_bytes):
    """Return (record, signature_raw) or raise ValueError(status)."""
    try:
        rec = json.loads(sig_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError(E.MALFORMED_SIGNATURE)
    if not isinstance(rec, dict) or rec.get("format") != FORMAT:
        raise ValueError(E.MALFORMED_SIGNATURE)
    if rec.get("version") != VERSION or rec.get("alg") != ALG or rec.get("hash_alg") != "SHA-256":
        raise ValueError(E.UNSUPPORTED_ALG)
    try:
        sig = base64.b64decode(rec["signature"], validate=True)
    except (KeyError, TypeError, binascii.Error):
        raise ValueError(E.MALFORMED_SIGNATURE)
    if len(sig) != 64 or not isinstance(rec.get("doc_sha256"), str):
        raise ValueError(E.MALFORMED_SIGNATURE)
    return rec, sig


def verify_document(doc: bytes, sig_bytes: Optional[bytes], pubkey_pem: Optional[bytes],
                    doc_name: str = "document", trust_path=None) -> VerificationResult:
    if doc is not None and len(doc) > E.MAX_DOC_BYTES or \
            (sig_bytes and len(sig_bytes) > E.MAX_SIG_BYTES) or \
            (pubkey_pem and len(pubkey_pem) > E.MAX_KEY_BYTES):
        return _fail(E.TOO_LARGE, doc_name=doc_name)
    if not doc:
        return _fail(E.EMPTY_INPUT, doc_name=doc_name)

    digest = hashlib.sha256(doc).digest()
    base = dict(doc_name=doc_name, doc_sha256=digest.hex(), doc_size=len(doc))

    if not sig_bytes:
        return _fail(E.MALFORMED_SIGNATURE, **base)
    try:
        rec, sig = _parse_sig(sig_bytes)
    except ValueError as e:
        return _fail(str(e), **base)
    base.update(alg=rec["alg"], claimed_sha256=rec["doc_sha256"],
                integrity_ok=(rec["doc_sha256"] == digest.hex()),
                signed_at_claimed=rec.get("signed_at"))

    if not pubkey_pem:
        return _fail(E.MALFORMED_KEY, **base)
    try:
        pub = keys.load_public_key(pubkey_pem)
    except Exception:
        return _fail(E.MALFORMED_KEY, **base)
    fp = keys.fingerprint(pub)
    base["key_fingerprint"] = fp

    # Message is rebuilt from the RECOMPUTED digest, never the claimed one.
    message = build_message(ALG, digest, len(doc))
    try:
        pub.verify(sig, message)
    except InvalidSignature:
        if not base["integrity_ok"]:
            status = E.DOC_MODIFIED
        elif rec.get("key_fingerprint") != fp:
            status = E.WRONG_KEY
        else:
            status = E.INVALID_SIGNATURE
        return _fail(status, **base)

    label = trust.lookup(fp, trust_path)
    notes = []
    if not base["integrity_ok"]:
        notes.append("Signature verified, but the unauthenticated 'doc_sha256' metadata field was wrong.")
    if rec.get("key_fingerprint") != fp:
        notes.append("Signature file's key_fingerprint hint differs from the supplied key (ignored).")
    return VerificationResult(True, E.VALID, None, signer_trusted=label is not None,
                              trust_label=label, verified_at=_now(), notes=notes, **base)
