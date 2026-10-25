"""Generate demo files in samples/. Keys here are DEMO ONLY."""
from pathlib import Path

from verity import keys
from verity.signer import sign_document

out = Path(__file__).parent / "samples"
out.mkdir(exist_ok=True)
doc = b"CONFIDENTIAL AGREEMENT\nAlice agrees to pay Bob $1,000.\n"
pa, pua = keys.generate_keypair()
_, pub = keys.generate_keypair()
(out / "agreement.txt").write_bytes(doc)
(out / "agreement.txt.vsig").write_bytes(sign_document(doc, pa, "agreement.txt"))
(out / "agreement_TAMPERED.txt").write_bytes(doc.replace(b"$1,000", b"$9,000"))
(out / "alice_public.pem").write_bytes(pua)
(out / "alice_DEMO_private.pem").write_bytes(pa)
(out / "bob_public.pem").write_bytes(pub)
(out / "bad_signature.vsig").write_bytes(b"garbage")
print("samples written to", out)
