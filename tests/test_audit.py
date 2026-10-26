import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from verity import audit

H = "ab" * 32


@pytest.fixture
def log(tmp_path):
    p = tmp_path / "a.jsonl"
    for i in range(5):
        audit.append_event("verify", H, "VALID" if i % 2 == 0 else "DOC_MODIFIED", "Ed25519", "cd" * 32, path=p)
    return p


def chain(p, **kw):
    recs, err = audit.read_records(p)
    return audit.verify_chain(recs, err, **kw), recs


def rewrite(p, recs):
    p.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in recs), "utf-8")


def test_empty_log(tmp_path):
    rep, recs = chain(tmp_path / "none.jsonl")
    assert rep.ok and rep.count == 0 and recs == []


def test_valid_chain(log):
    rep, recs = chain(log)
    assert rep.ok and rep.count == 5 and rep.head_hash == recs[-1]["hash"]


def test_modified_record(log):
    _, recs = chain(log)
    assert recs[2]["outcome"] == "VALID"
    recs[2]["outcome"] = "DOC_MODIFIED"
    rewrite(log, recs)
    rep, _ = chain(log)
    assert not rep.ok and rep.first_bad_seq == 2 and "modified" in rep.reason


def test_modified_prev_hash(log):
    _, recs = chain(log)
    recs[3]["prev_hash"] = "0" * 64
    recs[3]["hash"] = audit.record_hash(recs[3])  # attacker even fixes this record's own hash
    rewrite(log, recs)
    rep, _ = chain(log)
    assert not rep.ok and rep.first_bad_seq == 3 and "link" in rep.reason


def test_reordered(log):
    _, recs = chain(log)
    recs[1], recs[2] = recs[2], recs[1]
    rewrite(log, recs)
    rep, _ = chain(log)
    assert not rep.ok and rep.first_bad_seq == 1


def test_missing_middle(log):
    _, recs = chain(log)
    del recs[2]
    rewrite(log, recs)
    rep, _ = chain(log)
    assert not rep.ok and rep.first_bad_seq == 2


def test_truncated_tail_undetected_without_anchor_detected_with_anchor(log):
    rep, recs = chain(log)
    head, count = rep.head_hash, rep.count
    rewrite(log, recs[:3])
    rep2, _ = chain(log)
    assert rep2.ok and "cannot be ruled out" in rep2.reason  # honest limitation
    rep3, _ = chain(log, anchor_head=head, anchor_count=count)
    assert not rep3.ok and "anchor" in rep3.reason


def test_full_rewrite_undetected_without_anchor(log):
    rep, _ = chain(log)
    head = rep.head_hash
    forged_path = log.parent / "forged.jsonl"
    for _ in range(5):
        audit.append_event("verify", "00" * 32, "VALID", "Ed25519", "cd" * 32, path=forged_path)
    forged, _ = chain(forged_path)
    assert forged.ok  # internally consistent forgery
    forged_with_anchor, _ = chain(forged_path, anchor_head=head)
    assert not forged_with_anchor.ok


def test_invalid_serialization(log):
    with log.open("a") as f:
        f.write("{broken\n")
    rep, _ = chain(log)
    assert not rep.ok and "not valid JSON" in rep.reason
    with pytest.raises(ValueError):
        audit.append_event("verify", path=log)


def test_bad_structure_and_unknown_type(log):
    _, recs = chain(log)
    recs[1]["extra"] = 1
    rewrite(log, recs)
    assert not chain(log)[0].ok
    with pytest.raises(ValueError):
        audit.append_event("bogus", path=log.parent / "x")


def test_no_sensitive_content_fields(log):
    _, recs = chain(log)
    assert set(recs[0]) == audit._FIELDS and "PRIVATE" not in log.read_text()
