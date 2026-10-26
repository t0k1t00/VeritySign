"""Independent command-line verifier. Uses the same `verity` library, no UI and no stored verdicts.

  python verify_cli.py evidence PACK.json [--document FILE] [--trust trusted_keys.json]
  python verify_cli.py detached DOCUMENT SIGNATURE.vsig PUBLIC_KEY.pem [--trust trusted_keys.json]

Exit codes: 0 verified, 1 not verified, 2 unreadable input, 3 digest-only (no document examined).
Exit code 0 only if the signature is cryptographically valid (and, for evidence packs, all checks pass).
Valid does not mean trusted: the signer-trust line is reported separately.
"""
import argparse
import sys
from pathlib import Path

from verity import errors as E
from verity.evidence import verify_pack
from verity.verifier import verify_document


def _print_result(r):
    print(f"Signature : {'VALID' if r.signature_valid else 'INVALID'} ({r.status})")
    if not r.signature_valid and r.failure_reason:
        print(f"Reason    : {r.failure_reason}")
    print(f"SHA-256   : {r.doc_sha256}")
    print(f"Algorithm : {r.alg}")
    print(f"Key fp    : {r.key_fingerprint}")
    if r.signature_valid:
        print(f"Signer    : {'trusted locally as ' + repr(r.trust_label) if r.signer_trusted else 'UNKNOWN (not in trust store)'}")
    for n in r.notes:
        print(f"Note      : {n}")
    print("Caveat    : a valid signature does not prove real-world identity, truthfulness, or signing time.")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("evidence")
    e.add_argument("pack")
    e.add_argument("--document")
    e.add_argument("--trust")
    d = sub.add_parser("detached")
    d.add_argument("document")
    d.add_argument("signature")
    d.add_argument("public_key")
    d.add_argument("--trust")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "evidence":
            doc = Path(a.document).read_bytes() if a.document else None
            rep = verify_pack(Path(a.pack).read_bytes(), doc, a.trust)
            print(f"Mode      : {rep.mode}")
            for c in rep.checks:
                print(f"[{c.state.upper():4}] {c.name}: {c.detail}")
            if rep.result:
                _print_result(rep.result)
            ok = rep.evidence_ok
            if rep.digest_only_ok:
                print("RESULT    : SIGNATURE VERIFIED OVER THE RECORDED DIGEST, BUT NO DOCUMENT WAS EXAMINED (use --document)")
                return 3
        else:
            r = verify_document(Path(a.document).read_bytes(), Path(a.signature).read_bytes(),
                                Path(a.public_key).read_bytes(), Path(a.document).name, a.trust)
            _print_result(r)
            ok = r.signature_valid
    except OSError as ex:
        print(f"Cannot read input: {ex}", file=sys.stderr)
        return 2
    print("RESULT    :", "VERIFIED (cryptographic check only)" if ok else "NOT VERIFIED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
