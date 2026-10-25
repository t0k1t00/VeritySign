"""Page functions. Same functionality as before, restyled with ui.py components."""
import hashlib
from datetime import datetime

import streamlit as st

import ui
from verity import errors as E, keys, trust
from verity.signer import sign_document
from verity.verifier import verify_document


def read(f):
    return f.getvalue() if f is not None else None


def log(r):
    st.session_state.history.insert(0, {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "file": r.doc_name, "status": r.status,
        "valid": r.signature_valid, "trusted": r.signer_trusted,
        "signer": r.trust_label if r.signature_valid and r.signer_trusted else ("Unknown" if r.signature_valid else "-")})


# ---------------------------------------------------------------- dashboard
def dashboard():
    ui.page_header("space_dashboard", "Dashboard",
                   "Verify the bytes. Know the signer. Check a document against its signature, and separately whether you trust the key.")
    h = st.session_state.history
    total = len(h)
    ok = sum(x["valid"] for x in h)
    failed = total - ok
    trusted = sum(x["valid"] and x["trusted"] for x in h)
    cols = st.columns(4)
    for c, args in zip(cols, [("description", "primary", total, "Verifications this session"),
                              ("verified", "ok", ok, "Valid signatures"),
                              ("gpp_bad", "err", failed, "Failed verifications"),
                              ("lock", "info", trusted, "From trusted signers")]):
        c.markdown(ui.stat(*args), unsafe_allow_html=True)
    st.write("")

    left, right = st.columns([3, 2])
    with left:
        with st.container(border=True):
            st.markdown(f'<div class="card-title">{ui.icon("upload_file")}Verify a document</div>'
                        '<p class="muted">Upload a document, its <code>.vsig</code> signature and the signer&#39;s public key.</p>'
                        f'<p class="muted">Up to {E.MAX_DOC_BYTES // 1024 // 1024} MB. Files are processed in memory only and are never stored.</p>',
                        unsafe_allow_html=True)
            l1, l2 = st.columns(2)
            l1.page_link(st.session_state.pages["verify"], label="Start verification", icon=":material/arrow_forward:")
            l2.page_link(st.session_state.pages["demo"], label="Try the guided demo", icon=":material/play_circle:")
    with right:
        if total:
            order = [(E.VALID, "var(--ok)")] + [(s, "var(--err)") for s in E.EXPLANATIONS if s != E.VALID]
            rows = ""
            for s, col in order:
                n = sum(x["status"] == s for x in h)
                if n:
                    rows += (f'<div class="row"><span>{ui.esc(ui.STATUS_LABEL[s])}</span><div class="track"><div class="fill" '
                             f'style="width:{n / total * 100:.0f}%;background:{col}"></div></div><b>{n}</b></div>')
            ui.card(f'<div class="bars">{rows}</div><div class="legend-note">Count of verifications by outcome, this session.</div>',
                    "Outcomes", "bar_chart")
        else:
            ui.card(ui.empty("bar_chart", "No data yet", "Outcome statistics appear after your first verification."),
                    "Outcomes", "bar_chart")
    st.write("")
    ui.card('<div class="flow">'
            + "".join(f'<div class="step"><div class="n">{n}</div><div><b>{t}</b><span class="d">{d}</span></div></div>'
                      for n, t, d in [(1, "Hash", "SHA-256 of the file"), (2, "Sign", "Ed25519 private key"),
                                      (3, "Verify", "Public key checks signature"), (4, "Trust", "Is the key pinned?")])
            + '</div>', "How it works", "account_tree")
    st.write("")
    a, b = st.columns(2)
    with a:
        ui.card('<ul class="muted"><li>These exact bytes were signed by the holder of the matching private key</li>'
                "<li>The document's SHA-256 digest</li><li>Whether the key is in your trust store</li></ul>",
                "What it proves", "check_circle")
    with b:
        ui.card('<ul class="muted"><li>Who the signer really is</li><li>That the content is true</li><li>When it was signed</li>'
                "<li>That the key was never compromised or revoked</li><li>Embedded PDF (PAdES) signatures are not supported</li></ul>",
                "What it does not prove", "info")
    st.write("")
    st.markdown("#### Recent activity")
    activity_table(h[:5])


def activity_table(h):
    if not h:
        ui.card(ui.empty("history", "No verifications yet", "Run a verification or the guided demo to see activity here."))
        return
    ui.table(["Time", "File", "Status", "Signer"],
             [[ui.esc(x["time"]), ui.mono(x["file"]), ui.status_badge(x["status"]), ui.esc(x["signer"])] for x in h])


# ------------------------------------------------------------------- verify
def verify():
    ui.page_header("fact_check", "Verify a document",
                   "Provide the document, its signature file and the signer's public key.")
    c1, c2, c3 = st.columns(3)
    doc = c1.file_uploader("Document (required)", key="up_doc", help="Any file type")
    sig = c2.file_uploader("Signature .vsig (required)", type=["vsig", "json"], key="up_sig")
    pub = c3.file_uploader("Public key .pem (required)", type=["pem", "pub"], key="up_pub")
    st.caption(f"Up to {E.MAX_DOC_BYTES // 1024 // 1024} MB. Files are processed in memory only. "
               "This verifies VeritySign signatures over file bytes, not signatures embedded in PDFs.")
    missing = [n for n, f in [("document", doc), ("signature", sig), ("public key", pub)] if f is None]
    if st.button("Verify signature", type="primary", icon=":material/verified_user:", disabled=bool(missing)):
        with st.status("Verifying", expanded=False) as s:
            s.update(label="Hashing document (SHA-256) and checking signature")
            r = verify_document(read(doc), read(sig), read(pub), doc.name)
            s.update(label="Verification complete", state="complete")
        log(r)
        st.session_state.last = r
    if missing:
        st.caption("Waiting for: " + ", ".join(missing) + ".")
    if "last" in st.session_state:
        st.write("")
        r = st.session_state.last
        show_result(r)
        if r.signature_valid and not r.signer_trusted:
            with st.expander("Pin this key as trusted", icon=":material/push_pin:"):
                label = st.text_input("Label (required)", placeholder="e.g. Alice Smith")
                st.caption("Only pin a key after confirming its fingerprint with the signer through another channel.")
                if st.button("Pin key", disabled=not label.strip(), icon=":material/push_pin:"):
                    trust.pin(r.key_fingerprint, label)
                    st.success("Pinned. Verify again to see the updated trust status.", icon=":material/check_circle:")


def show_result(r):
    ui.show_result(r, "v")


# ------------------------------------------------------------ signer studio
def studio():
    ui.page_header("edit_document", "Signer Studio", "Generate a demo key pair and sign a document.")
    st.warning("Demo tool. Your private key is generated in memory and is not saved by this app. "
               "Download it only if you need it and keep it secret.", icon=":material/warning:")
    if st.button("Generate Ed25519 key pair", icon=":material/key:"):
        st.session_state.kp = keys.generate_keypair()
    if "kp" in st.session_state:
        priv, pubpem = st.session_state.kp
        fp = keys.fingerprint(keys.load_public_key(pubpem))
        ui.kv_table([("Fingerprint", ui.mono(keys.short_fp(fp)))])
        a, b, _ = st.columns([1.3, 1.6, 2])
        a.download_button("Public key", pubpem, "public_key.pem", icon=":material/download:", use_container_width=True)
        b.download_button("Private key (secret)", priv, "private_key.pem", icon=":material/download:", use_container_width=True)
    st.markdown("#### Sign a document")
    doc = st.file_uploader("Document to sign (required)", key="sdoc")
    upk = st.file_uploader("Private key .pem (optional)", key="spk",
                           help="Defaults to the key generated above")
    if st.button("Sign document", type="primary", disabled=doc is None, icon=":material/draw:"):
        pk = read(upk) or (st.session_state.kp[0] if "kp" in st.session_state else None)
        if pk is None:
            st.error("Generate or upload a private key first.", icon=":material/error:")
        else:
            try:
                st.session_state.vsig = (sign_document(read(doc), pk, doc.name), doc.name)
            except Exception as e:
                st.error(f"Could not sign: {e}", icon=":material/error:")
    if "vsig" in st.session_state:
        data, name = st.session_state.vsig
        st.success(f"Signature created for {name}", icon=":material/check_circle:")
        st.download_button("Download .vsig", data, name + ".vsig", icon=":material/download:")
        st.code(data.decode(), language="json")


# --------------------------------------------------------------------- demo
def demo():
    ui.page_header("science", "Demo & Tamper Lab",
                   "Every scenario generates fresh keys and runs the real verifier. Nothing is hardcoded.")
    sample = (b"CONFIDENTIAL AGREEMENT\nParty A agrees to pay Party B $1,000.\nSigned in good faith.\n" * 5)
    if "demo" not in st.session_state:
        pa, pua = keys.generate_keypair()
        _, pub_ = keys.generate_keypair()
        st.session_state.demo = dict(sig=sign_document(sample, pa, "agreement.txt"), pua=pua, pub=pub_)
    D = st.session_state.demo
    scen = {
        "1. Valid document and signature": (sample, D["sig"], D["pua"]),
        "2. Same document, amount changed": (sample.replace(b"$1,000", b"$9,000"), D["sig"], D["pua"]),
        "3. Correct file, wrong public key": (sample, D["sig"], D["pub"]),
        "4. Malformed signature file": (sample, b"this is not a signature", D["pua"]),
    }
    st.markdown("#### Guided demo")
    for i, (name, (d_, s_, k_)) in enumerate(scen.items()):
        with st.expander(name, expanded=(i == 0)):
            if st.button("Run verification", key=f"run{i}", icon=":material/play_arrow:"):
                r = verify_document(d_, s_, k_, "agreement.txt")
                log(r)
                ui.show_result(r, f"d{i}")
    st.markdown("#### Tamper Lab")
    st.caption("Flip a single bit of the signed document and watch the SHA-256 digest and the verdict change.")
    c1, c2 = st.columns(2)
    pos = c1.slider("Byte position", 0, len(sample) - 1, 10)
    bit = c2.slider("Bit to flip", 0, 7, 0)
    flip = st.toggle("Apply bit flip", value=False)
    mod = bytearray(sample)
    if flip:
        mod[pos] ^= 1 << bit
    h0, h1 = hashlib.sha256(sample).hexdigest(), hashlib.sha256(bytes(mod)).hexdigest()
    ui.hashbox("Original SHA-256", ui.esc(h0))
    ui.hashbox("Current SHA-256 (differences highlighted)", ui.diff_hex(h0, h1))
    r = verify_document(bytes(mod), D["sig"], D["pua"], "agreement.txt")
    if r.signature_valid:
        ui.verdict("ok", "Result", "Signature valid", "Unmodified document.", "verified")
    else:
        ui.verdict("err", "Result", "Signature invalid", f"{ui.STATUS_LABEL[r.status]}. One bit changed.", "gpp_bad")


# -------------------------------------------------------------- trust store
@st.dialog("Remove pinned key?")
def confirm_remove(fp, label):
    st.write(f"Signatures from **{label}** will show as unknown signer until the key is pinned again.")
    a, b = st.columns(2)
    if a.button("Remove", type="primary", icon=":material/delete:", use_container_width=True):
        trust.unpin(fp)
        st.rerun()
    if b.button("Cancel", use_container_width=True):
        st.rerun()


def trust_store():
    ui.page_header("verified_user", "Trust Store",
                   "Pinned public-key fingerprints, like SSH known_hosts. Pin only keys whose fingerprints you have confirmed out of band.")
    store = trust.all_keys()
    if not store:
        ui.card(ui.empty("key_off", "No pinned keys yet", "Verify a document, then pin its signer's key, or pin a key file below."))
    for fp, label in store.items():
        a, b, c = st.columns([2, 4, 1.4], vertical_alignment="center")
        a.markdown(f"**{label}**")
        b.markdown(ui.mono(keys.short_fp(fp) + "..."), unsafe_allow_html=True)
        if c.button("Remove", key="rm" + fp, icon=":material/delete:", use_container_width=True):
            confirm_remove(fp, label)
    st.markdown("#### Pin a public key file")
    f = st.file_uploader("Public key .pem (required)", key="tpk")
    lab = st.text_input("Label (required)", placeholder="e.g. Alice Smith", key="tlab")
    if st.button("Pin key", disabled=not (f and lab.strip()), icon=":material/push_pin:"):
        try:
            trust.pin(keys.fingerprint(keys.load_public_key(read(f))), lab)
            st.rerun()
        except Exception:
            st.error("This is not a valid Ed25519 public key PEM file.", icon=":material/error:")


# ------------------------------------------------------------------ history
def history():
    ui.page_header("history", "History", "Verifications from this browser session. Kept in memory and cleared when the session ends.")
    h = st.session_state.history
    if h:
        q = st.text_input("Filter by file name", placeholder="Search", icon=":material/search:")
        shown = [x for x in h if q.lower() in x["file"].lower()]
        ui.table(["Time", "File", "Status", "Signer"],
                 [[ui.esc(x["time"]), ui.mono(x["file"]), ui.status_badge(x["status"]), ui.esc(x["signer"])] for x in shown])
        if not shown:
            st.caption("No entries match this filter.")
        if st.button("Clear history", icon=":material/delete:"):
            st.session_state.history = []
            st.rerun()
    else:
        ui.card(ui.empty("history", "Nothing yet", "Completed verifications will be listed here."))
