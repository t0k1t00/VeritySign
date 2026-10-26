"""Canonical JSON used before hashing (audit records, policy files).

Sorted keys, no whitespace, ASCII-escaped, UTF-8. This is a deliberate subset of RFC 8785 (JCS):
it is sufficient because our records contain only strings, integers, booleans, null, lists and
objects (no floats), where the two serialisations coincide.
"""
import hashlib
import json


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
