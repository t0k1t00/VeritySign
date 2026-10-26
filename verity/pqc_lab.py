"""EXPERIMENTAL cryptography lab: Ed25519 vs ML-DSA (NIST FIPS 204).

Isolated from the signing format: VeritySign v1 signatures remain Ed25519 only. Real implementations
from the `cryptography` library (OpenSSL-backed) are used; nothing is simulated.
"""
import statistics
import time
from dataclasses import dataclass
from typing import List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization as S
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa
except ImportError:  # older cryptography releases
    mldsa = None

RAW = dict(encoding=S.Encoding.Raw)


def _pub_raw(pub):
    return pub.public_bytes(S.Encoding.Raw, S.PublicFormat.Raw)


def _priv_raw(priv):
    return priv.private_bytes(S.Encoding.Raw, S.PrivateFormat.Raw, S.NoEncryption())


def algorithms():
    """name -> (private key class, standard, note). ML-DSA entries exist only if the library supports them."""
    algs = {"Ed25519": (Ed25519PrivateKey, "RFC 8032 / FIPS 186-5",
                        "Classical elliptic-curve signature; broken by a large quantum computer (Shor).")}
    if mldsa is not None:
        for name, cls, cat in [("ML-DSA-44", "MLDSA44PrivateKey", 2), ("ML-DSA-65", "MLDSA65PrivateKey", 3),
                               ("ML-DSA-87", "MLDSA87PrivateKey", 5)]:
            if hasattr(mldsa, cls):
                algs[name] = (getattr(mldsa, cls), f"NIST FIPS 204 (security category {cat})",
                              "Lattice-based post-quantum signature. Private key shown in 32-byte seed form.")
    return algs


@dataclass
class LabRow:
    algorithm: str
    standard: str
    public_key_bytes: int
    private_key_bytes: int
    signature_bytes: int
    keygen_ms: float
    sign_ms: float
    verify_ms: float
    verified: bool
    tampered_rejected: bool
    wrong_key_rejected: bool
    note: str


def _rejects(pub, sig, msg) -> bool:
    try:
        pub.verify(sig, msg)
        return False
    except InvalidSignature:
        return True


def _median_ms(fn, trials):
    times = []
    for _ in range(trials):
        t = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t) * 1000)
    return statistics.median(times)


def run_lab(trials: int = 20, message: bytes = b"VeritySign PQC lab message " * 40,
            only: Optional[List[str]] = None) -> List[LabRow]:
    """Measure each algorithm `trials` times; report the median. Sizes are exact byte counts."""
    if trials < 1:
        raise ValueError("trials must be >= 1")
    rows = []
    for name, (cls, standard, note) in algorithms().items():
        if only and name not in only:
            continue
        priv = cls.generate()
        pub = priv.public_key()
        sig = priv.sign(message)
        other = cls.generate().public_key()
        rows.append(LabRow(
            algorithm=name, standard=standard,
            public_key_bytes=len(_pub_raw(pub)), private_key_bytes=len(_priv_raw(priv)), signature_bytes=len(sig),
            keygen_ms=_median_ms(cls.generate, trials),
            sign_ms=_median_ms(lambda: priv.sign(message), trials),
            verify_ms=_median_ms(lambda: pub.verify(sig, message), trials),
            verified=not _rejects(pub, sig, message),
            tampered_rejected=_rejects(pub, sig, message + b"!"),
            wrong_key_rejected=_rejects(other, sig, message),
            note=note))
    return rows
