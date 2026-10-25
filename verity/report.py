"""Report generation. Only public data from VerificationResult is included."""
import html
import json

DISCLAIMER = ("A valid signature shows the bytes match the signature and public key. It does not "
              "prove the signer's real-world identity, the truth of the content, or when it was signed.")


def to_json(result) -> bytes:
    d = result.to_dict()
    d["disclaimer"] = DISCLAIMER
    return json.dumps(d, indent=2).encode()


def to_html(result) -> bytes:
    rows = "".join(f"<tr><th>{html.escape(str(k))}</th><td><code>{html.escape(str(v))}</code></td></tr>"
                   for k, v in result.to_dict().items())
    color = "#16a34a" if result.signature_valid else "#dc2626"
    page = (f"<html><head><meta charset='utf-8'><title>VeritySign Report</title></head>"
            f"<body style='font-family:sans-serif;max-width:800px;margin:2em auto'>"
            f"<h1>VeritySign Verification Report</h1>"
            f"<h2 style='color:{color}'>{html.escape(result.status)}</h2>"
            f"<table border='1' cellpadding='6' style='border-collapse:collapse'>{rows}</table>"
            f"<p><em>{DISCLAIMER}</em></p></body></html>")
    return page.encode()
