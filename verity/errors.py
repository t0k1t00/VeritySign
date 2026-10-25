"""Status codes and human-readable explanations for verification outcomes."""

VALID = "VALID"
INVALID_SIGNATURE = "INVALID_SIGNATURE"
DOC_MODIFIED = "DOC_MODIFIED"
WRONG_KEY = "WRONG_KEY"
MALFORMED_SIGNATURE = "MALFORMED_SIGNATURE"
MALFORMED_KEY = "MALFORMED_KEY"
UNSUPPORTED_ALG = "UNSUPPORTED_ALG"
EMPTY_INPUT = "EMPTY_INPUT"
TOO_LARGE = "TOO_LARGE"

MAX_DOC_BYTES = 25 * 1024 * 1024
MAX_SIG_BYTES = 64 * 1024
MAX_KEY_BYTES = 64 * 1024

EXPLANATIONS = {
    VALID: ("The signature is mathematically valid for these exact bytes and this public key.",
            "This does not prove who the signer is. Check the trust status."),
    INVALID_SIGNATURE: ("The signature does not verify for this document and key.",
                        "The signature bytes were altered or were not made over this document."),
    DOC_MODIFIED: ("The document's SHA-256 differs from the digest that was signed.",
                   "The file was changed after signing, or this is a different file. Obtain the original."),
    WRONG_KEY: ("The supplied public key is not the key that produced this signature.",
                "Ask the signer for their correct public key and compare fingerprints."),
    MALFORMED_SIGNATURE: ("The signature file is missing or is not a valid VeritySign v1 file.",
                          "Use the .vsig file produced by Signer Studio."),
    MALFORMED_KEY: ("The public key is missing, corrupt, or not an Ed25519 public key in PEM format.",
                    "Supply a PEM file beginning with -----BEGIN PUBLIC KEY-----."),
    UNSUPPORTED_ALG: ("The signature file uses an algorithm or version this verifier does not support.",
                      "Only VeritySign version 1 with Ed25519 is accepted."),
    EMPTY_INPUT: ("The document is empty.", "Empty files are rejected to avoid meaningless signatures."),
    TOO_LARGE: ("An input exceeds the size limit.", "Documents up to 25 MB are accepted."),
}
