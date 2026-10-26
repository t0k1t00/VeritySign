import base64
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import verify_cli
from verity import errors as E, evidence, keys
from verity.signer import sign_document

DOC = b"Evidence test document.\n" * 30


@pytest.fixture
def kp():
    return keys.generate_keypair()


@pytest.fixture
def tp(tmp_path):
    return tmp_path / "t.json"


def make(kp, include=True, doc=DOC):
    sig = sign_document(doc, kp[0], "d.txt")
    return evidence.build_pack(doc, sig, kp[1], "d.txt", include)


def edit(pack, fn):
    d = json.loads(pack)
    fn(d)
    return json.dumps(d).encode()


def test_valid_bundled(kp, tp):
    r = evidence.verify_pack(make(kp), None, tp)
    assert r.evidence_ok and r.mode == "bundled" and r.result.signature_valid


def test_valid_digest_only_is_flagged(kp, tp):
    r = evidence.verify_pack(make(kp, include=False), None, tp)
    assert r.mode == "digest-only" and r.result.signature_valid and r.result.integrity_ok is None
    assert r.digest_only_ok and not r.evidence_ok
    assert any("not examined" in n for n in r.result.notes)


def test_digest_only_then_supply_document(kp, tp):
    p = make(kp, include=False)
    assert evidence.verify_pack(p, DOC, tp).mode == "supplied"
    bad = evidence.verify_pack(p, DOC + b"x", tp)
    assert not bad.evidence_ok and bad.result.status == E.DOC_MODIFIED


def test_modified_bundled_document(kp, tp):
    p = edit(make(kp), lambda d: d["document"].update(b64=base64.b64encode(DOC + b"!").decode()))
    r = evidence.verify_pack(p, None, tp)
    assert not r.evidence_ok and not r.result.signature_valid


def test_modified_signature(kp, tp):
    def f(d):
        s = base64.b64decode(d["signature_record"]["signature"])
        d["signature_record"]["signature"] = base64.b64encode(bytes([s[0] ^ 1]) + s[1:]).decode()
    r = evidence.verify_pack(edit(make(kp), f), None, tp)
    assert not r.evidence_ok and r.result.status == E.INVALID_SIGNATURE


def test_wrong_public_key(kp, tp):
    other = keys.generate_keypair()
    r = evidence.verify_pack(edit(make(kp), lambda d: d.update(public_key_pem=other[1].decode())), None, tp)
    assert not r.evidence_ok and r.result.status == E.WRONG_KEY


def test_modified_manifest_does_not_break_crypto_but_fails_evidence(kp, tp):
    r = evidence.verify_pack(edit(make(kp), lambda d: d["manifest"].update(key_fingerprint="a" * 64)), None, tp)
    assert r.result.signature_valid and not r.evidence_ok
    assert any(c.state == "fail" and "fingerprint" in c.name for c in r.checks)


def test_reported_status_is_not_trusted(kp, tp):
    other = keys.generate_keypair()
    p = edit(make(kp), lambda d: d.update(public_key_pem=other[1].decode()))  # manifest still says VALID
    r = evidence.verify_pack(p, None, tp)
    assert json.loads(p)["manifest"]["reported_status"] == "VALID" and not r.result.signature_valid


def test_missing_field_and_extra_field(kp, tp):
    assert not evidence.verify_pack(edit(make(kp), lambda d: d.pop("manifest")), None, tp).structure_ok
    assert not evidence.verify_pack(edit(make(kp), lambda d: d.update(extra=1)), None, tp).structure_ok


def test_unsupported_version(kp, tp):
    r = evidence.verify_pack(edit(make(kp), lambda d: d.update(version=2)), None, tp)
    assert not r.structure_ok and r.result is None


def test_malformed_json_and_binary(tp):
    assert not evidence.verify_pack(b"{not json", None, tp).structure_ok
    assert not evidence.verify_pack(b"\xff\xfe\x00", None, tp).structure_ok


def test_oversized(kp, tp, monkeypatch):
    monkeypatch.setattr(evidence, "MAX_PACK_BYTES", 100)
    assert not evidence.verify_pack(make(kp), None, tp).structure_ok


def test_bad_base64(kp, tp):
    r = evidence.verify_pack(edit(make(kp), lambda d: d["document"].update(b64="***")), None, tp)
    assert not r.structure_ok


def test_pack_never_contains_private_key(kp):
    assert b"PRIVATE" not in make(kp)
    with pytest.raises(ValueError):
        evidence.build_pack(DOC, sign_document(DOC, kp[0]), kp[0], "d", True)


def test_pack_with_private_key_text_is_rejected(kp, tp):
    p = edit(make(kp), lambda d: d.update(limitations=["-----BEGIN PRIVATE KEY-----"]))
    assert not evidence.verify_pack(p, None, tp).structure_ok


def test_cannot_export_failed_verification(kp):
    with pytest.raises(ValueError):
        evidence.build_pack(DOC + b"x", sign_document(DOC, kp[0]), kp[1], "d", True)


def test_trust_status_reported_separately(kp, tp):
    from verity import trust
    p = make(kp)
    assert not evidence.verify_pack(p, None, tp).result.signer_trusted
    trust.pin(keys.fingerprint(keys.load_public_key(kp[1])), "Alice", tp)
    assert evidence.verify_pack(p, None, tp).result.signer_trusted


def test_cli_offline_exit_codes(kp, tmp_path, capsys):
    pack = tmp_path / "e.json"
    pack.write_bytes(make(kp))
    assert verify_cli.main(["evidence", str(pack), "--trust", str(tmp_path / "t.json")]) == 0
    tampered = tmp_path / "bad.json"
    tampered.write_bytes(edit(make(kp), lambda d: d["document"].update(b64=base64.b64encode(b"zzz").decode())))
    assert verify_cli.main(["evidence", str(tampered), "--trust", str(tmp_path / "t.json")]) == 1
    assert verify_cli.main(["evidence", str(tmp_path / "missing.json")]) == 2
    out = capsys.readouterr().out
    assert "VERIFIED" in out and "NOT VERIFIED" in out


def test_cli_digest_only_exit_code(kp, tmp_path):
    pack = tmp_path / "e.json"
    pack.write_bytes(make(kp, include=False))
    assert verify_cli.main(["evidence", str(pack), "--trust", str(tmp_path / "t.json")]) == 3
    (tmp_path / "d").write_bytes(DOC)
    assert verify_cli.main(["evidence", str(pack), "--document", str(tmp_path / "d"), "--trust", str(tmp_path / "t.json")]) == 0


def test_cli_detached(kp, tmp_path):
    (tmp_path / "d").write_bytes(DOC)
    (tmp_path / "s").write_bytes(sign_document(DOC, kp[0]))
    (tmp_path / "k").write_bytes(kp[1])
    assert verify_cli.main(["detached", str(tmp_path / "d"), str(tmp_path / "s"), str(tmp_path / "k")]) == 0
    (tmp_path / "d").write_bytes(DOC + b"x")
    assert verify_cli.main(["detached", str(tmp_path / "d"), str(tmp_path / "s"), str(tmp_path / "k")]) == 1
