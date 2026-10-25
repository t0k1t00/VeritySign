import base64
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from verity import errors as E, keys, trust
from verity.signer import sign_document
from verity.verifier import verify_document
from verity.report import to_json

DOC = b"Contract: pay Alice 100 dollars.\n" * 20


@pytest.fixture
def alice():
    return keys.generate_keypair()


@pytest.fixture
def bob():
    return keys.generate_keypair()


@pytest.fixture
def tp(tmp_path):
    return tmp_path / "trust.json"


def v(doc, sig, pub, tp):
    return verify_document(doc, sig, pub, "doc.txt", trust_path=tp)


def test_valid(alice, tp):
    sig = sign_document(DOC, alice[0], "doc.txt")
    r = v(DOC, sig, alice[1], tp)
    assert r.signature_valid and r.status == E.VALID and r.integrity_ok
    assert not r.signer_trusted  # unknown key


def test_valid_and_trusted(alice, tp):
    sig = sign_document(DOC, alice[0])
    fp = keys.fingerprint(keys.load_public_key(alice[1]))
    trust.pin(fp, "Alice", tp)
    r = v(DOC, sig, alice[1], tp)
    assert r.signer_trusted and r.trust_label == "Alice"


@pytest.mark.parametrize("pos", [0, 100, len(DOC) - 1])
def test_tampered_one_byte(alice, tp, pos):
    sig = sign_document(DOC, alice[0])
    bad = bytearray(DOC)
    bad[pos] ^= 1
    r = v(bytes(bad), sig, alice[1], tp)
    assert not r.signature_valid and r.status == E.DOC_MODIFIED and r.integrity_ok is False


def test_wrong_key(alice, bob, tp):
    r = v(DOC, sign_document(DOC, alice[0]), bob[1], tp)
    assert not r.signature_valid and r.status == E.WRONG_KEY


def test_corrupt_signature_bytes(alice, tp):
    rec = json.loads(sign_document(DOC, alice[0]))
    raw = bytearray(base64.b64decode(rec["signature"]))
    raw[0] ^= 0xFF
    rec["signature"] = base64.b64encode(bytes(raw)).decode()
    r = v(DOC, json.dumps(rec).encode(), alice[1], tp)
    assert not r.signature_valid and r.status == E.INVALID_SIGNATURE


def test_missing_signature(alice, tp):
    assert v(DOC, None, alice[1], tp).status == E.MALFORMED_SIGNATURE
    assert v(DOC, b"", alice[1], tp).status == E.MALFORMED_SIGNATURE


def test_garbage_signature(alice, tp):
    assert v(DOC, b"not json", alice[1], tp).status == E.MALFORMED_SIGNATURE
    assert v(DOC, b'{"format":"VeritySign"}', alice[1], tp).status == E.UNSUPPORTED_ALG


def test_missing_and_malformed_key(alice, tp):
    sig = sign_document(DOC, alice[0])
    assert v(DOC, sig, None, tp).status == E.MALFORMED_KEY
    assert v(DOC, sig, b"-----BEGIN PUBLIC KEY-----\nxx\n-----END PUBLIC KEY-----", tp).status == E.MALFORMED_KEY
    assert v(DOC, sig, alice[0], tp).status == E.MALFORMED_KEY  # private key supplied


def test_rsa_key_rejected(alice, tp):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    k = rsa.generate_private_key(65537, 2048).public_key()
    pem = k.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert v(DOC, sign_document(DOC, alice[0]), pem, tp).status == E.MALFORMED_KEY


def test_unsupported_alg(alice, tp):
    rec = json.loads(sign_document(DOC, alice[0]))
    rec["alg"] = "RSA-PSS"
    assert v(DOC, json.dumps(rec).encode(), alice[1], tp).status == E.UNSUPPORTED_ALG


def test_empty_document(alice, tp):
    sig = sign_document(DOC, alice[0])
    assert v(b"", sig, alice[1], tp).status == E.EMPTY_INPUT
    with pytest.raises(ValueError):
        sign_document(b"", alice[0])


def test_too_large(alice, tp, monkeypatch):
    monkeypatch.setattr(E, "MAX_DOC_BYTES", 10)
    assert v(b"x" * 11, b"{}", alice[1], tp).status == E.TOO_LARGE


def test_repeatable(alice, tp):
    sig = sign_document(DOC, alice[0])
    rs = [v(DOC, sig, alice[1], tp) for _ in range(3)]
    assert all(r.status == E.VALID for r in rs)


def test_lying_claimed_digest_cannot_make_forgery_pass(alice, tp):
    """Signature for doc A, attacker swaps in doc B and rewrites the claimed digest."""
    import hashlib
    rec = json.loads(sign_document(DOC, alice[0]))
    other = b"Contract: pay Mallory 1000000.\n"
    rec["doc_sha256"] = hashlib.sha256(other).hexdigest()
    r = v(other, json.dumps(rec).encode(), alice[1], tp)
    assert not r.signature_valid  # recomputed digest is what is verified


def test_report_has_no_private_material(alice, tp):
    r = v(DOC, sign_document(DOC, alice[0]), alice[1], tp)
    out = to_json(r)
    assert b"PRIVATE" not in out


def test_two_signatures_differ_by_key(alice, bob):
    assert json.loads(sign_document(DOC, alice[0]))["signature"] != json.loads(sign_document(DOC, bob[0]))["signature"]
