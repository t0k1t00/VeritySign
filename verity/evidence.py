"""Cryptographic evidence pack: one self-contained JSON file that lets someone else re-verify offline.

The pack's own claims (manifest, reported status) are never trusted. Verification recomputes the
document digest, re-parses the key, recomputes its fingerprint and runs the real signature check.
A single JSON file (no archive) means there are no extraction paths to abuse and nothing is executed.
"""
import base64
import binascii
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from . import errors as E
from . import keys
from .verifier import VerificationResult, verify_digest_only, verify_document

FORMAT = "VeritySign-Evidence"
VERSION = 1
MAX_PACK_BYTES = 40 * 1024 * 1024
_TOP = {"format", "version", "created_at", "document", "signature_record", "public_key_pem", "manifest", "limitations"}
_DOC = {"name", "size", "sha256", "included", "b64"}
_MAN = {"alg", "key_fingerprint", "doc_sha256", "doc_size", "reported_status"}
LIMITATIONS = [
    "This pack proves a signature verifies for a digest under the included public key. It does not prove who "
    "holds the key, that the content is true, or when it was signed.",
    "created_at and the signature file's signed_at are self-reported, not trusted timestamps.",
    "manifest.reported_status is informational only and is ignored by verifiers.",
]


@dataclass
class Check:
    name: str
    state: str  # pass | fail | info
    detail: str


@dataclass
class EvidenceReport:
    structure_ok: bool
    mode: str  # bundled | supplied | digest-only | none
    checks: List[Check] = field(default_factory=list)
    result: Optional[VerificationResult] = None

    @property
    def _consistent(self):
        return bool(self.structure_ok and self.result and self.result.signature_valid
                    and not any(c.state == "fail" for c in self.checks))

    @property
    def evidence_ok(self):
        """Full verification: a real document was examined and everything recomputed correctly."""
        return self._consistent and self.mode != "digest-only"

    @property
    def digest_only_ok(self):
        """Signature verifies over the recorded digest, but no document was examined."""
        return self._consistent and self.mode == "digest-only"


def build_pack(doc: bytes, sig_bytes: bytes, pub_pem: bytes, doc_name: str, include_document: bool) -> bytes:
    """Create a pack. Refuses unless the signature actually verifies right now."""
    r = verify_document(doc, sig_bytes, pub_pem, doc_name)
    if not r.signature_valid:
        raise ValueError(f"cannot export evidence: verification failed ({r.status})")
    if b"PRIVATE KEY" in pub_pem:
        raise ValueError("refusing to bundle private key material")
    pack = {
        "format": FORMAT, "version": VERSION,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "document": {"name": doc_name, "size": len(doc), "sha256": r.doc_sha256, "included": include_document,
                     "b64": base64.b64encode(doc).decode() if include_document else None},
        "signature_record": json.loads(sig_bytes),
        "public_key_pem": pub_pem.decode("ascii"),
        "manifest": {"alg": r.alg, "key_fingerprint": r.key_fingerprint, "doc_sha256": r.doc_sha256,
                     "doc_size": r.doc_size, "reported_status": r.status},
        "limitations": LIMITATIONS,
    }
    return json.dumps(pack, indent=2).encode()


def _bad(rep, name, detail):
    rep.checks.append(Check(name, "fail", detail))
    rep.structure_ok = False
    return rep


def verify_pack(pack_bytes: bytes, document: Optional[bytes] = None, trust_path=None) -> EvidenceReport:
    rep = EvidenceReport(structure_ok=True, mode="none")
    if len(pack_bytes) > MAX_PACK_BYTES:
        return _bad(rep, "Pack size", f"Pack exceeds the {MAX_PACK_BYTES // 1024 // 1024} MB limit.")
    if b"PRIVATE KEY" in pack_bytes:
        return _bad(rep, "No private key material", "The pack contains private-key text and was rejected.")
    try:
        pack = json.loads(pack_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _bad(rep, "Well-formed JSON", "The file is not valid UTF-8 JSON.")
    if not isinstance(pack, dict) or set(pack) != _TOP:
        return _bad(rep, "Required fields", f"Top-level fields must be exactly {sorted(_TOP)}.")
    if pack["format"] != FORMAT or pack["version"] != VERSION:
        return _bad(rep, "Format and version", f"Expected {FORMAT} v{VERSION}; found {pack['format']!r} v{pack['version']!r}.")
    doc, man = pack["document"], pack["manifest"]
    if (not isinstance(doc, dict) or set(doc) != _DOC or not isinstance(man, dict) or set(man) != _MAN
            or not isinstance(pack["signature_record"], dict) or not isinstance(pack["public_key_pem"], str)):
        return _bad(rep, "Required fields", "document, manifest, signature_record or public_key_pem is malformed.")
    rep.checks.append(Check("Structure", "pass", f"{FORMAT} v{VERSION}, all required fields present, no private key text."))

    sig_bytes = json.dumps(pack["signature_record"]).encode()
    try:
        pub_pem = pack["public_key_pem"].encode("ascii")
    except UnicodeEncodeError:
        return _bad(rep, "Public key", "Public key is not ASCII PEM.")

    bundled = None
    if doc["included"]:
        try:
            bundled = base64.b64decode(doc["b64"] or "", validate=True)
        except (binascii.Error, TypeError, ValueError):
            return _bad(rep, "Bundled document", "Bundled document is not valid base64.")
        if len(bundled) > E.MAX_DOC_BYTES:
            return _bad(rep, "Bundled document", "Bundled document exceeds the size limit.")

    if document is not None:
        used, rep.mode = document, "supplied"
        if bundled is not None and bundled != document:
            rep.checks.append(Check("Supplied vs bundled document", "info",
                                    "The supplied document differs from the bundled copy; the supplied one was verified."))
    elif bundled is not None:
        used, rep.mode = bundled, "bundled"
    else:
        used, rep.mode = None, "digest-only"

    if used is not None:
        res = verify_document(used, sig_bytes, pub_pem, doc["name"] if isinstance(doc["name"], str) else "document", trust_path)
    else:
        res = verify_digest_only(str(man["doc_sha256"]), man["doc_size"] if isinstance(man["doc_size"], int) else 0,
                                 sig_bytes, pub_pem, str(doc["name"]), trust_path)
        rep.checks.append(Check("Document examined", "info",
                                "No document bytes available: only the signed digest was checked. "
                                "Supply the document to confirm it matches."))
    rep.result = res

    # Recompute manifest/document claims; none are taken on trust.
    def cmp(name, claimed, actual):
        ok = actual is not None and claimed == actual
        okmsg = ("Consistent with the signed digest (no document was examined)." if rep.mode == "digest-only"
                 else "Matches the recomputed value.")
        rep.checks.append(Check(name, "pass" if ok else "fail", okmsg if ok else "Does not match the recomputed value."))
    cmp("Manifest digest matches document", man["doc_sha256"], res.doc_sha256)
    cmp("Document record digest matches document", doc["sha256"], res.doc_sha256)
    cmp("Manifest size matches document", man["doc_size"], res.doc_size)
    cmp("Manifest algorithm matches signature", man["alg"], res.alg)
    cmp("Manifest key fingerprint matches key", man["key_fingerprint"], res.key_fingerprint)
    rep.checks.append(Check("Reported status ignored", "info",
                            f"The pack says {man['reported_status']!r}; this is not trusted. "
                            f"Recomputed result: {res.status}."))
    return rep
