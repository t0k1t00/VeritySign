"""Hash-linked (tamper-evident) audit log, stored as JSON Lines.

Each record's hash = SHA-256(canonical_json(record without 'hash')), and each record contains the
previous record's hash. Editing, reordering or deleting a record in the middle breaks the chain.

What this does NOT protect against: someone with write access can delete the tail, or rebuild the
entire chain with fresh hashes. Detecting that needs an external anchor (e.g. the head hash saved
elsewhere, an independent witness, or a transparency log). `verify_chain` accepts such an anchor.
Timestamps are self-reported by this machine and are not trusted time.
"""
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from .canon import canonical_json, sha256_hex

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "audit_log.jsonl"
GENESIS = "0" * 64
EVENT_TYPES = ("sign", "verify", "evidence_verify")
_FIELDS = {"seq", "event_id", "type", "time", "doc_sha256", "outcome", "alg", "key_fingerprint",
           "policy", "decision", "prev_hash", "hash"}
_HEX64 = set("0123456789abcdef")


def record_hash(rec: dict) -> str:
    return sha256_hex(canonical_json({k: v for k, v in rec.items() if k != "hash"}))


def _path(path):
    return Path(path or DEFAULT_PATH)


def read_records(path=None):
    """Return (records, parse_error). parse_error is (line_number, message) or None."""
    p = _path(path)
    if not p.exists():
        return [], None
    recs = []
    for n, line in enumerate(p.read_text("utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            return recs, (n, "line is not valid JSON")
        recs.append(r)
    return recs, None


def append_event(event_type, doc_sha256=None, outcome=None, alg=None, key_fingerprint=None,
                 policy=None, decision=None, path=None) -> dict:
    """Append one event. Only digests/fingerprints are stored, never document contents or keys."""
    if event_type not in EVENT_TYPES:
        raise ValueError("unknown event type")
    recs, err = read_records(path)
    if err:
        raise ValueError(f"audit log is unreadable at line {err[0]}; verify the chain before appending")
    prev = recs[-1]["hash"] if recs else GENESIS
    rec = {"seq": len(recs), "event_id": str(uuid.uuid4()), "type": event_type,
           "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "doc_sha256": doc_sha256, "outcome": outcome, "alg": alg, "key_fingerprint": key_fingerprint,
           "policy": policy, "decision": decision, "prev_hash": prev}
    rec["hash"] = record_hash(rec)
    p = _path(path)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")
    return rec


@dataclass
class ChainReport:
    ok: bool
    count: int
    head_hash: Optional[str]
    first_bad_seq: Optional[int]
    reason: str


def verify_chain(records: List[dict], parse_error=None, anchor_head: Optional[str] = None,
                 anchor_count: Optional[int] = None) -> ChainReport:
    """Check every record's structure, hash, sequence number and link. Reports the first failure."""
    prev = GENESIS
    for i, r in enumerate(records):
        if (not isinstance(r, dict) or set(r) != _FIELDS or r.get("type") not in EVENT_TYPES
                or not isinstance(r.get("hash"), str) or not isinstance(r.get("prev_hash"), str)):
            return ChainReport(False, len(records), None, i, f"record {i} has an invalid structure")
        if r["seq"] != i:
            return ChainReport(False, len(records), None, i,
                               f"record {i} has sequence number {r['seq']}: an entry was removed, inserted or reordered")
        if r["prev_hash"] != prev:
            return ChainReport(False, len(records), None, i,
                               f"record {i} does not link to the previous record's hash")
        if record_hash(r) != r["hash"]:
            return ChainReport(False, len(records), None, i,
                               f"record {i} content does not match its hash: the record was modified")
        prev = r["hash"]
    if parse_error:
        return ChainReport(False, len(records), None, len(records),
                           f"line {parse_error[0]}: {parse_error[1]}")
    head = prev if records else None
    if anchor_head is not None or anchor_count is not None:
        if (anchor_count is not None and len(records) != anchor_count) or \
                (anchor_head is not None and (head or GENESIS) != anchor_head):
            return ChainReport(False, len(records), head, None,
                               "chain is internally consistent but does not match the saved anchor: "
                               "records were truncated, replaced or rewritten after the anchor was taken")
    return ChainReport(True, len(records), head, None,
                       "all records are consistent" + (" and match the saved anchor" if anchor_head or anchor_count else
                                                       "; no external anchor supplied, so truncation or a full rewrite "
                                                       "cannot be ruled out"))
