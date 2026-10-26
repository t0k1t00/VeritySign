"""Policy-based verification.

A policy is evaluated AFTER cryptographic verification. It can only add restrictions:
an invalid signature is always REJECT, and no policy can turn it into a valid one.
"""
import json
from dataclasses import dataclass
from typing import List, Optional

from .canon import canonical_json, sha256_hex
from .errors import MAX_DOC_BYTES, VALID

PASS, FAIL, WARN, NA = "PASS", "FAIL", "WARN", "N/A"
ACCEPT, ACCEPT_WARN, REJECT = "ACCEPT", "ACCEPT_WITH_WARNINGS", "REJECT"

SUPPORTED_ALGS = ("Ed25519",)
MAX_POLICY_BYTES = 64 * 1024

_SCHEMA = {  # field -> (type, allowed values or None)
    "name": (str, None), "description": (str, None),
    "allowed_algs": (list, None), "min_format_version": (int, None),
    "max_doc_bytes": (int, None), "unknown_signer": (str, ("allow", "warn", "reject")),
    "require_integrity_metadata": (bool, None), "approved_fingerprints": (list, None),
    "min_key_bits": (int, None),
}

BUILTIN = {
    "standard": dict(
        name="Standard",
        description="Verify the signature and report the signer's trust status. Unknown signers produce a warning.",
        allowed_algs=["Ed25519"], min_format_version=1, max_doc_bytes=MAX_DOC_BYTES, unknown_signer="warn",
        require_integrity_metadata=False, approved_fingerprints=[], min_key_bits=0),
    "strict": dict(
        name="Strict",
        description="Accept only signatures from keys in the local trust store, and require the signature file's "
                    "digest metadata to match the document.",
        allowed_algs=["Ed25519"], min_format_version=1, max_doc_bytes=10 * 1024 * 1024, unknown_signer="reject",
        require_integrity_metadata=True, approved_fingerprints=[], min_key_bits=0),
    "demonstration": dict(
        name="Demonstration",
        description="Lenient on signer trust but limits documents to 1 MB, so controlled examples can show "
                    "different rule outcomes.",
        allowed_algs=["Ed25519"], min_format_version=1, max_doc_bytes=1024 * 1024, unknown_signer="allow",
        require_integrity_metadata=False, approved_fingerprints=[], min_key_bits=0),
}


@dataclass
class RuleOutcome:
    rule: str
    state: str
    detail: str


@dataclass
class PolicyDecision:
    policy: str
    policy_sha256: str
    decision: str
    outcomes: List[RuleOutcome]
    summary: str

    def to_dict(self):
        return {"policy": self.policy, "policy_sha256": self.policy_sha256, "decision": self.decision,
                "summary": self.summary, "rules": [vars(o) for o in self.outcomes]}


def policy_digest(policy: dict) -> str:
    body = {k: v for k, v in policy.items() if k != "policy_sha256"}
    return sha256_hex(canonical_json(body))


def validate_policy(p) -> dict:
    """Strict schema check. Raises ValueError with a readable message."""
    if not isinstance(p, dict):
        raise ValueError("policy must be a JSON object")
    extra = set(p) - set(_SCHEMA) - {"policy_sha256"}
    missing = set(_SCHEMA) - set(p)
    if extra or missing:
        raise ValueError(f"policy fields invalid (unexpected: {sorted(extra)}, missing: {sorted(missing)})")
    for k, (t, allowed) in _SCHEMA.items():
        v = p[k]
        if not isinstance(v, t) or (t is int and isinstance(v, bool)):
            raise ValueError(f"'{k}' has the wrong type")
        if allowed and v not in allowed:
            raise ValueError(f"'{k}' must be one of {allowed}")
    if any(a not in SUPPORTED_ALGS for a in p["allowed_algs"]):
        raise ValueError(f"allowed_algs may only contain {list(SUPPORTED_ALGS)} (strict allowlist)")
    if not all(isinstance(f, str) and len(f) == 64 and all(c in "0123456789abcdef" for c in f)
               for f in p["approved_fingerprints"]):
        raise ValueError("approved_fingerprints must be 64-character lowercase hex SHA-256 fingerprints")
    if p["max_doc_bytes"] <= 0 or p["max_doc_bytes"] > MAX_DOC_BYTES or p["min_format_version"] < 1 or p["min_key_bits"] < 0:
        raise ValueError("numeric limits out of range")
    return p


def policy_to_file(policy: dict) -> bytes:
    validate_policy(policy)
    out = dict(policy)
    out["policy_sha256"] = policy_digest(policy)
    return json.dumps(out, indent=2, sort_keys=True).encode()


def load_policy(data: bytes) -> dict:
    """Parse a policy file. Rejects bad schema and any edit that breaks its embedded digest.

    The digest detects accidental or naive modification only; it does not authenticate who wrote the file.
    """
    if len(data) > MAX_POLICY_BYTES:
        raise ValueError("policy file too large")
    try:
        p = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("policy file is not valid JSON")
    validate_policy(p)
    if "policy_sha256" not in p:
        raise ValueError("policy file has no integrity digest (policy_sha256)")
    if p["policy_sha256"] != policy_digest(p):
        raise ValueError("policy file digest mismatch: the file was modified after it was exported")
    return {k: v for k, v in p.items() if k != "policy_sha256"}


def evaluate(policy: dict, result, key_bits: Optional[int] = None) -> PolicyDecision:
    """Apply `policy` to a VerificationResult. Never upgrades an invalid result."""
    validate_policy(policy)
    out: List[RuleOutcome] = []
    crypto_ok = result.signature_valid and result.status == VALID
    out.append(RuleOutcome("Cryptographic signature valid", PASS if crypto_ok else FAIL,
                           "Signature verified by the cryptography library." if crypto_ok
                           else f"Verification failed ({result.status}). Policies cannot override this."))
    if not crypto_ok:
        for r in ["Algorithm allowlist", "Format version", "Document size limit", "Key size", "Signer trust",
                  "Approved fingerprints", "Integrity metadata"]:
            out.append(RuleOutcome(r, NA, "Not evaluated because the signature is not valid."))
        return PolicyDecision(policy["name"], policy_digest(policy), REJECT, out,
                              "Rejected: the cryptographic check failed.")

    alg_ok = result.alg in policy["allowed_algs"]
    out.append(RuleOutcome("Algorithm allowlist", PASS if alg_ok else FAIL,
                           f"{result.alg} is {'in' if alg_ok else 'not in'} {policy['allowed_algs']}."))
    ver_ok = (result.format_version or 0) >= policy["min_format_version"]
    out.append(RuleOutcome("Format version", PASS if ver_ok else FAIL,
                           f"Signature format v{result.format_version}; policy requires v{policy['min_format_version']} or later."))
    size_ok = result.doc_size <= policy["max_doc_bytes"]
    out.append(RuleOutcome("Document size limit", PASS if size_ok else FAIL,
                           f"{result.doc_size:,} bytes against a limit of {policy['max_doc_bytes']:,}."))
    if policy["min_key_bits"] > 0 and key_bits is not None:
        kb_ok = key_bits >= policy["min_key_bits"]
        out.append(RuleOutcome("Key size", PASS if kb_ok else FAIL, f"{key_bits}-bit key against minimum {policy['min_key_bits']}."))
    else:
        out.append(RuleOutcome("Key size", NA, "Ed25519 has a single fixed parameter set (256-bit), so a minimum "
                                               "key size is not meaningful for it."))
    if result.signer_trusted:
        out.append(RuleOutcome("Signer trust", PASS, f"Key is pinned locally as '{result.trust_label}'. "
                                                      "This is a local decision, not a verified real-world identity."))
    else:
        mode = policy["unknown_signer"]
        state = {"allow": PASS, "warn": WARN, "reject": FAIL}[mode]
        out.append(RuleOutcome("Signer trust", state, f"Key is not in the trust store; policy action: {mode}."))
    if policy["approved_fingerprints"]:
        ok = result.key_fingerprint in policy["approved_fingerprints"]
        out.append(RuleOutcome("Approved fingerprints", PASS if ok else FAIL,
                               "Key fingerprint is on the approved list." if ok else "Key fingerprint is not on the approved list."))
    else:
        out.append(RuleOutcome("Approved fingerprints", NA, "This policy has no fingerprint allowlist."))
    if policy["require_integrity_metadata"]:
        ok = result.integrity_ok is True
        out.append(RuleOutcome("Integrity metadata", PASS if ok else FAIL,
                               "Digest recorded in the signature file matches the document." if ok
                               else "Digest recorded in the signature file could not be matched to the document."))
    else:
        out.append(RuleOutcome("Integrity metadata", NA, "Not required by this policy."))

    if any(o.state == FAIL for o in out):
        failed = [o.rule for o in out if o.state == FAIL]
        return PolicyDecision(policy["name"], policy_digest(policy), REJECT, out,
                              "Rejected by policy. The signature itself is valid; failed rules: " + ", ".join(failed) + ".")
    if any(o.state == WARN for o in out):
        return PolicyDecision(policy["name"], policy_digest(policy), ACCEPT_WARN, out,
                              "Accepted with warnings: the signature is valid but the signer is not trusted locally.")
    return PolicyDecision(policy["name"], policy_digest(policy), ACCEPT, out, "Accepted: all applicable rules passed.")
