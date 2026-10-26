# VeritySign security features: design, evaluation and limits

## 1. Starting point (audit of the existing code)
- Stack: Python, Streamlit UI, `cryptography` library. Engine in `verity/`, no UI imports.
- Format: **custom** detached signature, `.vsig` v1 JSON, Ed25519 over a domain-separated message
  (`"VeritySign-v1\0" + "Ed25519" + \0 + SHA-256 digest + size`). The verifier recomputes the digest and never trusts the file's claimed one.
- Existing: key generation, signing, tamper detection, fingerprint, local trust store, session history, JSON/HTML report. 18 tests passing.
- Gaps found: no portable proof a third party can re-check; history lived only in the browser session; trust handling was a single
  warn/trusted flag with no configurable decision; `signed_at` is self-asserted (documented); no algorithm other than Ed25519 (so nothing claimed falsely).

## 2. Candidate scoring (1 to 5, higher is better; reliability and testability scored so higher = lower risk)
Weights: security value 25%, novelty 15%, feasibility 20%, reliability/regression risk 20%, demo impact 10%, relevance 10%.

| Candidate | Security | Novelty | Feasible | Low risk | Demo | Relevance | Weighted | Decision |
|---|---|---|---|---|---|---|---|---|
| A Evidence pack + G independent verifier (merged: same capability) | 5 | 4 | 4 | 4 | 5 | 5 | 4.5 | **Implemented** |
| B Tamper-evident audit trail | 4 | 4 | 5 | 5 | 4 | 4 | 4.3 | **Implemented** |
| C Policy-based verification | 4 | 3 | 5 | 5 | 4 | 5 | 4.2 | **Implemented** |
| D Post-quantum lab (ML-DSA) | 3 | 5 | 4 | 4 | 4 | 5 | 3.9 | **Implemented as isolated experiment** (library supports it; no new dependency) |
| F Algorithm agility | 3 | 2 | 4 | 3 | 2 | 4 | 3.0 | Only as architecture: strict allowlist in policy; no plugin system |
| E Chain of custody | 3 | 4 | 2 | 2 | 3 | 3 | 2.9 | **Deferred**: needs signed event records, key handling per handoff and its own test suite |

Overlaps removed: G is the evidence verifier (library plus CLI plus UI tab), not a separate feature. F is absorbed by the policy allowlist.

## 3. What was built
| Feature | Files | Entry point |
|---|---|---|
| Evidence pack | `verity/evidence.py`, `verify_cli.py` | Evidence Center, CLI |
| Audit trail | `verity/audit.py`, `verity/canon.py` | Audit Trail |
| Policies | `verity/policy.py` | Policies, selector on Verify and Evidence |
| Cryptography Lab (experimental) | `verity/pqc_lab.py` | Cryptography Lab |
| Shared engine change | `verity/verifier.py` (`verify_digest_only`, `format_version`) | all |

Existing signature format and behaviour are unchanged; all 18 original tests still pass.

### Evidence pack (`*.vevidence.json`, format `VeritySign-Evidence` v1)
One JSON file: document record (optionally with the bytes in base64), the `.vsig` record, the public key PEM, a manifest, and limitations text.
Single JSON means no archive extraction, so no path traversal; nothing is executed. Verification:
1. Reject oversize input, private-key text, bad JSON, unexpected or missing fields, unsupported version, bad base64.
2. Choose the document: supplied > bundled > none (digest-only).
3. Run the real verifier. Recompute digest and fingerprint. Compare every manifest field to the recomputed values.
4. `manifest.reported_status` is displayed but ignored.
Result is **Verified** only if a document was actually examined. A digest-only pack gives "signature valid, document not examined" (CLI exit 3).

### Audit trail
JSON Lines, one record per signing or verification event: `seq`, `event_id`, `type`, `time`, `doc_sha256`, `outcome`, `alg`, `key_fingerprint`, `policy`, `decision`, `prev_hash`, `hash`.
`hash = SHA-256(canonical_json(record without hash))`; canonical JSON = sorted keys, no whitespace, ASCII (a subset of RFC 8785 that is exact for our string/integer-only records).
No file names, document contents or keys are stored.

| Attack | Detected? |
|---|---|
| Edit a record | Yes |
| Edit a link (even re-hashing that record) | Yes |
| Reorder, insert or remove a middle record | Yes |
| Corrupt line / invalid structure | Yes |
| Delete newest records (truncation) | **No** unless an external anchor (saved head hash/count) is supplied |
| Rebuild the whole chain with new hashes | **No** unless anchored |
| Change the system clock | **No**: timestamps are self-reported |

Protection against a privileged attacker needs an external anchor, independent witnesses, or an append-only transparency service (the idea behind Sigstore's Rekor and RFC 9162 logs). VeritySign does not implement those.

### Policies
Evaluated after the cryptographic check. Rules: signature valid, algorithm allowlist, format version, size limit, key size (N/A for Ed25519, whose parameters are fixed), signer trust (allow/warn/reject), approved fingerprints, integrity metadata. Each rule shows Passed / Failed / Warning / Not applicable.
Built-ins: **Standard** (unknown signer warns), **Strict** (trusted keys only, metadata must match, 10 MB), **Demonstration** (lenient trust, 1 MB limit).
An invalid signature is REJECT under every policy and later rules are "not evaluated". Policy files carry a SHA-256 digest that detects later edits; it does not authenticate the author.

### Cryptography Lab (experimental)
Real Ed25519 and ML-DSA-44/65/87 (NIST FIPS 204) from the installed `cryptography` 50.0.1. Reports exact key and signature sizes and median keygen/sign/verify time over N trials (`time.perf_counter`), plus self-checks (valid verifies, tampered and wrong key rejected). It does not alter the signing format.
Observed sizes match FIPS 204: ML-DSA-65 public key 1952 B, signature 3309 B (Ed25519: 32 B and 64 B). Private keys are shown in 32-byte seed form.

## 4. Threat model (summary)
In scope: modified documents, swapped keys or signatures, forged manifests, tampered audit records or policy files, hostile input files.
Out of scope: key theft, compromised host, identity proofing, revocation, trusted timestamps, PKI. A valid signature proves only that the key holder signed those bytes.

## 5. Test results (actually run)
`python -m pytest`: **69 passed** (18 original, 20 evidence and CLI, 11 audit, 15 policy, 5 cryptography lab). Streamlit pages were also exercised with Streamlit's `AppTest` (no exceptions on any page; evidence demo, policy comparison and lab benchmark executed), and the CLI was run against real files (verified, tampered, digest-only cases).
Not done: automated browser tests, keyboard/contrast audit, clean-environment install test.

## 6. Industry practice versus this prototype
- Established: detached signatures and verification (FIPS 186-5, RFC 8032), hash-chained logs and transparency logs (RFC 9162, Sigstore Rekor), timestamp authorities (RFC 3161), PQ signatures (FIPS 204).
- Prototype adaptation: a local single-writer hash chain, a custom evidence JSON, local trust pinning. These are **not** Sigstore, PKI or a transparency service and are not interoperable with them.

## 7. References
- NIST FIPS 204, Module-Lattice-Based Digital Signature Standard: https://csrc.nist.gov/pubs/fips/204/final
- NIST FIPS 186-5, Digital Signature Standard (DSS).
- RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA).
- RFC 8785, JSON Canonicalization Scheme. RFC 3161, Time-Stamp Protocol. RFC 9162, Certificate Transparency Version 2.0.
- Sigstore documentation: https://docs.sigstore.dev/ (transparency log: https://docs.sigstore.dev/logging/overview/)
- `cryptography` library documentation (Ed25519, ML-DSA): https://cryptography.io/
Note: these references are cited from prior knowledge; they were not re-fetched during this session.

## 8. Future work
Chain of custody with signed handoff events; trusted timestamps (RFC 3161) in the evidence pack; external anchoring of the audit head; a versioned `.vsig` v2 with ML-DSA and policy allowlist support.
