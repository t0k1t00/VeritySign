import sys
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from verity import pqc_lab

pytestmark = pytest.mark.skipif("ML-DSA-65" not in pqc_lab.algorithms(), reason="ML-DSA not available in this cryptography build")

# FIPS 204 Table 2 sizes in bytes: (public key, signature)
FIPS204 = {"ML-DSA-44": (1312, 2420), "ML-DSA-65": (1952, 3309), "ML-DSA-87": (2592, 4627)}


@pytest.mark.parametrize("name", list(FIPS204))
def test_sign_verify_tamper_wrong_key_and_sizes(name):
    cls = pqc_lab.algorithms()[name][0]
    priv, other = cls.generate(), cls.generate()
    msg = b"post-quantum test"
    sig = priv.sign(msg)
    priv.public_key().verify(sig, msg)
    with pytest.raises(InvalidSignature):
        priv.public_key().verify(sig, msg + b"x")
    with pytest.raises(InvalidSignature):
        other.public_key().verify(sig, msg)
    assert (len(pqc_lab._pub_raw(priv.public_key())), len(sig)) == FIPS204[name]


def test_run_lab_rows_are_measured_and_consistent():
    rows = pqc_lab.run_lab(trials=3)
    names = [r.algorithm for r in rows]
    assert "Ed25519" in names and "ML-DSA-65" in names
    for r in rows:
        assert r.verified and r.tampered_rejected and r.wrong_key_rejected
        assert r.keygen_ms > 0 and r.sign_ms > 0 and r.verify_ms > 0
    ed = next(r for r in rows if r.algorithm == "Ed25519")
    assert (ed.public_key_bytes, ed.signature_bytes) == (32, 64)


def test_trials_validated_and_unavailable_handled(monkeypatch):
    with pytest.raises(ValueError):
        pqc_lab.run_lab(trials=0)
    monkeypatch.setattr(pqc_lab, "mldsa", None)
    assert list(pqc_lab.algorithms()) == ["Ed25519"]
    assert [r.algorithm for r in pqc_lab.run_lab(trials=1)] == ["Ed25519"]
