import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from verity import keys, policy, trust
from verity.signer import sign_document
from verity.verifier import verify_document

DOC = b"policy test doc\n" * 10


@pytest.fixture
def kp():
    return keys.generate_keypair()


@pytest.fixture
def tp(tmp_path):
    return tmp_path / "t.json"


def res(kp, tp, doc=DOC, sigdoc=DOC):
    return verify_document(doc, sign_document(sigdoc, kp[0]), kp[1], "d", trust_path=tp)


def dec(name, r):
    return policy.evaluate(policy.BUILTIN[name], r)


def test_unknown_key_standard_warns_strict_rejects_demo_accepts(kp, tp):
    r = res(kp, tp)
    assert r.signature_valid
    assert dec("standard", r).decision == policy.ACCEPT_WARN
    assert dec("strict", r).decision == policy.REJECT
    assert dec("demonstration", r).decision == policy.ACCEPT


def test_same_crypto_validity_different_decisions(kp, tp):
    r = res(kp, tp)
    decisions = {dec(n, r).decision for n in policy.BUILTIN}
    assert len(decisions) == 3 and r.signature_valid is True


def test_trusted_key_accepted_everywhere(kp, tp):
    trust.pin(keys.fingerprint(keys.load_public_key(kp[1])), "Alice", tp)
    r = res(kp, tp)
    for n in policy.BUILTIN:
        assert dec(n, r).decision == policy.ACCEPT


@pytest.mark.parametrize("name", list(policy.BUILTIN))
def test_invalid_signature_rejected_under_every_policy(kp, tp, name):
    r = res(kp, tp, doc=DOC + b"x")
    d = dec(name, r)
    assert not r.signature_valid and d.decision == policy.REJECT
    assert d.outcomes[0].state == policy.FAIL and all(o.state == policy.NA for o in d.outcomes[1:])


def test_policy_cannot_upgrade_invalid(kp, tp):
    r = res(kp, tp, doc=DOC + b"x")
    lenient = dict(policy.BUILTIN["demonstration"], unknown_signer="allow")
    assert policy.evaluate(lenient, r).decision == policy.REJECT and not r.signature_valid


def test_unknown_signer_distinct_from_invalid(kp, tp):
    unknown = dec("strict", res(kp, tp))
    invalid = dec("strict", res(kp, tp, doc=DOC + b"x"))
    assert unknown.outcomes[0].state == policy.PASS and invalid.outcomes[0].state == policy.FAIL


def test_size_limit_rule(kp, tp):
    big = b"y" * (2 * 1024 * 1024)
    d = dec("demonstration", res(kp, tp, doc=big, sigdoc=big))
    assert d.decision == policy.REJECT
    assert any(o.rule == "Document size limit" and o.state == policy.FAIL for o in d.outcomes)


def test_key_size_not_applicable_to_ed25519(kp, tp):
    d = dec("standard", res(kp, tp))
    assert next(o for o in d.outcomes if o.rule == "Key size").state == policy.NA
    p = dict(policy.BUILTIN["standard"], min_key_bits=2048)
    out = policy.evaluate(p, res(kp, tp), key_bits=1024).outcomes
    assert next(o for o in out if o.rule == "Key size").state == policy.FAIL


def test_approved_fingerprint_list(kp, tp):
    r = res(kp, tp)
    p = dict(policy.BUILTIN["standard"], approved_fingerprints=["ab" * 32])
    assert policy.evaluate(p, r).decision == policy.REJECT
    p["approved_fingerprints"] = [r.key_fingerprint]
    assert policy.evaluate(p, r).decision == policy.ACCEPT_WARN


def test_missing_integrity_metadata_fails_strict(kp, tp):
    r = res(kp, tp)
    r.integrity_ok = None  # e.g. digest-only evidence
    r.signer_trusted = True
    d = dec("strict", r)
    assert d.decision == policy.REJECT
    assert any(o.rule == "Integrity metadata" and o.state == policy.FAIL for o in d.outcomes)


def test_algorithm_allowlist(kp, tp):
    r = res(kp, tp)
    r.alg = "RSA-PKCS1v15"
    assert dec("standard", r).decision == policy.REJECT
    with pytest.raises(ValueError):
        policy.validate_policy(dict(policy.BUILTIN["standard"], allowed_algs=["Ed25519", "MD5-RSA"]))


def test_policy_file_roundtrip_and_tamper():
    data = policy.policy_to_file(policy.BUILTIN["strict"])
    assert policy.load_policy(data)["unknown_signer"] == "reject"
    d = json.loads(data)
    d["unknown_signer"] = "allow"
    with pytest.raises(ValueError, match="digest mismatch"):
        policy.load_policy(json.dumps(d).encode())
    d.pop("policy_sha256")
    with pytest.raises(ValueError):
        policy.load_policy(json.dumps(d).encode())


def test_policy_file_validation():
    for bad in [b"nope", b"[]", b"{}", b"x" * (policy.MAX_POLICY_BYTES + 1)]:
        with pytest.raises(ValueError):
            policy.load_policy(bad)
    with pytest.raises(ValueError):
        policy.validate_policy(dict(policy.BUILTIN["standard"], unknown_signer="maybe"))
    with pytest.raises(ValueError):
        policy.validate_policy(dict(policy.BUILTIN["standard"], max_doc_bytes=True))
