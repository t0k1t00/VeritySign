"""Shared presentation components (design system). No cryptography here."""
import html
from pathlib import Path

import streamlit as st

from verity import errors as E
from verity import keys
from verity.report import DISCLAIMER, to_html, to_json

CSS_PATH = Path(__file__).parent / "assets" / "style.css"

STATUS_LABEL = {
    E.VALID: "Valid", E.INVALID_SIGNATURE: "Invalid signature", E.DOC_MODIFIED: "Document modified",
    E.WRONG_KEY: "Wrong key", E.MALFORMED_SIGNATURE: "Malformed signature", E.MALFORMED_KEY: "Malformed key",
    E.UNSUPPORTED_ALG: "Unsupported algorithm", E.EMPTY_INPUT: "Empty input", E.TOO_LARGE: "Too large",
}


def inject_css():
    css = CSS_PATH.read_text(encoding="utf-8")
    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)


def icon(name, cls="", label=None):
    aria = f'role="img" aria-label="{html.escape(label)}"' if label else 'aria-hidden="true"'
    return f'<span class="msr {cls}" {aria}>{name}</span>'


def esc(x):
    return html.escape(str(x))


def page_header(icon_name, title, subtitle):
    st.markdown(
        f'<div class="page-head"><div class="ico">{icon(icon_name)}</div><div>'
        f'<div class="crumb">VeritySign</div><h1>{esc(title)}</h1><p>{esc(subtitle)}</p></div></div>',
        unsafe_allow_html=True)


def card_open(title=None, icon_name=None):
    t = f'<div class="card-title">{icon(icon_name) if icon_name else ""}{esc(title)}</div>' if title else ""
    return t


def card(inner_html, title=None, icon_name=None, hover=False):
    st.markdown(f'<div class="card {"hover" if hover else ""}">{card_open(title, icon_name)}{inner_html}</div>',
                unsafe_allow_html=True)


def stat(icon_name, tone, number, label):
    return (f'<div class="card hover"><div class="stat"><div class="ico tone-{tone}">{icon(icon_name)}</div>'
            f'<div><div class="num">{number}</div><div class="lab">{esc(label)}</div></div></div></div>')


def empty(icon_name, title, body):
    return (f'<div class="empty"><div class="ico">{icon(icon_name)}</div><b>{esc(title)}</b>'
            f'<span>{esc(body)}</span></div>')


def badge(text, tone, icon_name):
    return f'<span class="badge {tone}">{icon(icon_name)}{esc(text)}</span>'


def status_badge(status):
    if status == E.VALID:
        return badge("Valid", "ok", "check_circle")
    return badge(STATUS_LABEL.get(status, status), "err", "cancel")


def verdict(kind, label, value, detail, icon_name):
    st.markdown(f'<div class="verdict {kind}" role="status"><div class="ico">{icon(icon_name, "fill")}</div><div>'
                f'<div class="k">{esc(label)}</div><div class="v">{esc(value)}</div><div class="d">{esc(detail)}</div></div></div>',
                unsafe_allow_html=True)


def kv_table(rows):
    cells = "".join(f'<div class="k">{esc(k)}</div><div>{v}</div>' for k, v in rows)
    st.markdown(f'<div class="kv">{cells}</div>', unsafe_allow_html=True)


def mono(x):
    return f'<code>{esc(x)}</code>'


def diff_hex(a, b):
    """Return b with characters that differ from a highlighted."""
    return "".join(f'<span class="diff-bad">{esc(y)}</span>' if x != y else esc(y) for x, y in zip(a, b))


def hashbox(label, inner):
    st.markdown(f'<div class="hashbox"><div class="k">{esc(label)}</div><div class="mono">{inner}</div></div>',
                unsafe_allow_html=True)


def table(headers, rows_html):
    head = "".join(f"<th scope='col'>{esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows_html)
    st.markdown(f'<div class="tbl-wrap"><table class="tbl"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>',
                unsafe_allow_html=True)


def show_result(r, key="r"):
    c1, c2 = st.columns(2)
    with c1:
        if r.signature_valid:
            verdict("ok", "Cryptographic check", "Signature valid",
                    "Signature matches these exact bytes and this public key.", "verified")
        else:
            verdict("err", "Cryptographic check", "Signature invalid", STATUS_LABEL.get(r.status, r.status), "gpp_bad")
    with c2:
        if r.signature_valid and r.signer_trusted:
            verdict("ok", "Signer trust", f"Trusted: {r.trust_label}", "Key is pinned in your local trust store.", "lock")
        elif r.signature_valid:
            verdict("warn", "Signer trust", "Unknown signer",
                    "Key is not in your trust store. A valid signature does not prove identity.", "warning")
        else:
            verdict("neutral", "Signer trust", "Not assessed", "Trust is only evaluated for valid signatures.", "do_not_disturb_on")
    st.write("")
    if not r.signature_valid:
        what, fix = E.EXPLANATIONS[r.status]
        with st.expander("What happened?", expanded=True, icon=":material/help:"):
            st.markdown(f"**Reason:** {what}\n\n**What to try:** {fix}")
    for n in r.notes:
        st.info(n, icon=":material/info:")
    integ = {True: badge("Matches signed digest", "ok", "check_circle"),
             False: badge("Differs from signed digest", "err", "cancel"),
             None: badge("Not available", "neutral", "remove")}[r.integrity_ok]
    kv_table([
        ("File", mono(r.doc_name)), ("Size", mono(f"{r.doc_size:,} bytes")),
        ("SHA-256 (computed)", mono(r.doc_sha256 or "n/a")),
        ("SHA-256 (claimed in .vsig)", mono(r.claimed_sha256 or "n/a")),
        ("Document integrity", integ), ("Algorithm", mono(r.alg or "n/a")),
        ("Key fingerprint", mono(keys.short_fp(r.key_fingerprint) if r.key_fingerprint else "n/a")),
        ("Signed at (self-asserted)", mono(r.signed_at_claimed or "n/a")),
        ("Verified at", mono(r.verified_at)),
    ])
    st.caption(DISCLAIMER)
    d1, d2, _ = st.columns([1.2, 1.2, 2])
    d1.download_button("JSON report", to_json(r), "verification_report.json", key=key + "j",
                       icon=":material/download:", use_container_width=True)
    d2.download_button("HTML report", to_html(r), "verification_report.html", key=key + "h",
                       icon=":material/download:", use_container_width=True)
