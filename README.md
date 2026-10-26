# VeritySign: Digital Document Verifier

Verify a detached Ed25519 signature over any file, and separately check whether the signing key is one you trust.

## Run (from inside this folder, so the theme in .streamlit/config.toml is used)
```
pip install -r requirements.txt
python make_samples.py        # optional: creates samples/
streamlit run app.py
python -m pytest              # 69 tests
```

## How it works
- Document → SHA-256 digest.
- Signed bytes = `"VeritySign-v1\0" + "Ed25519" + \0 + digest + size (8 bytes)` (domain-separated, algorithm- and size-bound).
- `.vsig` is versioned JSON holding the signature plus metadata. The verifier **recomputes** the digest from the uploaded file and never trusts the claimed one.
- Trust = the key's fingerprint (SHA-256 of the raw public key) is pinned in `trusted_keys.json`.

## Layout
`verity/` engine (no UI imports) · `app.py` entry and navigation · `views.py` pages · `ui.py` shared components · `assets/style.css` design tokens and styles · `tests/` pytest · `samples/` demo files (keys are DEMO ONLY)

## Security features (see docs/SECURITY_FEATURES.md)
- **Evidence Center**: export a self-contained `*.vevidence.json` pack and re-verify it. Everything is recomputed; the pack's own claims are not trusted.
- **Independent CLI verifier**: `python verify_cli.py evidence PACK.json [--document FILE]` or `python verify_cli.py detached DOC SIG KEY`.
  Exit codes: 0 verified, 1 not verified, 2 unreadable input, 3 signature valid but no document examined.
- **Audit Trail**: hash-linked log (`audit_log.jsonl`, created on first use, git-ignored). Detects edits, reordering and middle deletions; truncation or a full rewrite need an external anchor.
- **Policies**: Standard, Strict, Demonstration, or a custom policy file. Policies add restrictions after the cryptographic check and can never validate an invalid signature.
- **Cryptography Lab (experimental)**: real Ed25519 vs ML-DSA (FIPS 204) sizes and timings. Does not change the signing format.

## Limitations
No PKI/X.509, no revocation, `signed_at` is self-asserted, no embedded-PDF (PAdES) signature validation: it verifies VeritySign signatures over file bytes only. A valid signature does not prove identity or that the content is true.
