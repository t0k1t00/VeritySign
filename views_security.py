"""Security feature pages: Evidence Center, Audit Trail, Policies, Cryptography Lab."""
import base64
import json
import platform
from datetime import datetime

import streamlit as st

import ui
import views
from verity import audit, evidence, keys, policy, pqc_lab
from verity.signer import sign_document
from verity.verifier import verify_document


def _show_checks(rep):
    ui.table(["Check", "Outcome", "Detail"], [[ui.esc(c.name), ui.check_badge(c.state), ui.esc(c.detail)] for c in rep.checks])


# ----------------------------------------------------------------- evidence
def evidence_center():
    ui.page_header("inventory_2", "Evidence Center",
                   "Export a self-contained evidence pack and re-verify it independently, offline. "
                   "The verifier recomputes everything and never trusts the pack's own claims.")
    t_make, t_verify, t_demo = st.tabs(["Create pack", "Verify pack", "Guided demo"])

    with t_make:
        c1, c2, c3 = st.columns(3)
        doc = c1.file_uploader("Document (required)", key="ev_doc")
        sig = c2.file_uploader("Signature .vsig (required)", key="ev_sig")
        pub = c3.file_uploader("Public key .pem (required)", key="ev_pub")
        inc = st.checkbox("Bundle the original document in the pack", value=False,
                          help="Off: the pack holds only the digest, signature and public key. "
                               "The recipient must then supply the document to confirm it matches.")
        st.caption("The pack never contains private keys. Export is refused unless the signature verifies right now.")
        missing = [n for n, f in [("document", doc), ("signature", sig), ("public key", pub)] if f is None]
        if st.button("Create evidence pack", type="primary", icon=":material/package_2:", disabled=bool(missing)):
            try:
                st.session_state.pack = (evidence.build_pack(views.read(doc), views.read(sig), views.read(pub), doc.name, inc),
                                         doc.name, inc)
            except ValueError as e:
                st.session_state.pop("pack", None)
                st.error(str(e), icon=":material/error:")
        if "pack" in st.session_state:
            data, name, included = st.session_state.pack
            st.success("Evidence pack created.", icon=":material/check_circle:")
            ui.kv_table([("Contains original document", ui.badge("Yes" if included else "No, digest only",
                                                                 "warn" if included else "neutral", "description")),
                         ("Size", ui.mono(f"{len(data):,} bytes")), ("Private key", ui.badge("Never included", "ok", "lock"))])
            st.download_button("Download evidence pack", data, name + ".vevidence.json", icon=":material/download:")

    with t_verify:
        pk = st.file_uploader("Evidence pack (.json, required)", type=["json"], key="ev_pack")
        d2 = st.file_uploader("Document (optional)", key="ev_docv",
                              help="Required to confirm a digest-only pack. If supplied, it is verified instead of any bundled copy.")
        pol = views.policy_picker("ev_policy")
        if st.button("Verify evidence pack", type="primary", icon=":material/fact_check:", disabled=pk is None):
            with st.status("Verifying evidence", expanded=False) as s:
                s.update(label="Recomputing digest, fingerprint and signature")
                rep = evidence.verify_pack(views.read(pk), views.read(d2))
                s.update(label="Verification complete", state="complete")
            d = policy.evaluate(pol, rep.result) if rep.result else None
            if rep.result:
                views.log(rep.result)
                views.audit_event("evidence_verify", rep.result, pol["name"], d)
            st.session_state.ev_last = (rep, d)
        if pk is None:
            st.caption("Waiting for: evidence pack.")
        if "ev_last" in st.session_state:
            rep, d = st.session_state.ev_last
            mode = {"bundled": "Verified the bundled document", "supplied": "Verified the document you supplied",
                    "digest-only": "Digest only: no document examined", "none": "No verification performed"}[rep.mode]
            if rep.evidence_ok and rep.mode != "digest-only":
                ui.verdict("ok", "Evidence check", "Evidence verified", mode + ". All recomputed checks passed.", "verified")
            elif rep.digest_only_ok:
                ui.verdict("warn", "Evidence check", "Signature valid, document not examined",
                           "Supply the document to confirm it matches the signed digest.", "warning")
            else:
                ui.verdict("err", "Evidence check", "Evidence not verified", mode + ". See the failed checks below.", "gpp_bad")
            st.write("")
            _show_checks(rep)
            if rep.result:
                st.markdown("#### Cryptographic result")
                views.show_result(rep.result)
                st.markdown("#### Policy evaluation")
                ui.policy_panel(d)
        st.markdown("#### Verify without this app")
        st.code("python verify_cli.py evidence my_document.vevidence.json\n"
                "python verify_cli.py evidence my_document.vevidence.json --document my_document.pdf", language="bash")
        st.caption("The command-line verifier uses the same verification library but no interface and no stored verdicts. "
                   "Its exit code is 0 only when everything verifies.")

    with t_demo:
        st.caption("Runs the real engine end to end with a fresh key pair. Nothing here is hardcoded.")
        if st.button("Run end-to-end demo", icon=":material/play_arrow:"):
            doc = b"Purchase order #1042: 25 units at $40.\n" * 8
            priv, pubpem = keys.generate_keypair()
            sig = sign_document(doc, priv, "order.txt")
            pack = evidence.build_pack(doc, sig, pubpem, "order.txt", True)
            ok = evidence.verify_pack(pack)
            forged = json.loads(pack)
            forged["document"]["b64"] = base64.b64encode(doc.replace(b"25 units", b"250 units")).decode()
            bad = evidence.verify_pack(json.dumps(forged).encode())
            stolen = json.loads(pack)
            stolen["public_key_pem"] = keys.generate_keypair()[1].decode()
            wrong = evidence.verify_pack(json.dumps(stolen).encode())
            digest_only = evidence.verify_pack(evidence.build_pack(doc, sig, pubpem, "order.txt", False))
            rows = [("1. Sign and export pack with bundled document", ok), ("2. Document edited inside the pack", bad),
                    ("3. Public key swapped inside the pack", wrong), ("4. Digest-only pack, no document supplied", digest_only)]
            ui.table(["Scenario", "Mode", "Signature", "Evidence"],
                     [[ui.esc(n), ui.esc(r.mode), ui.status_badge(r.result.status),
                       ui.badge("Verified", "ok", "check_circle") if r.evidence_ok else
                       (ui.badge("Digest only", "warn", "warning") if r.digest_only_ok else ui.badge("Not verified", "err", "cancel"))]
                      for n, r in rows])
            st.caption("Scenario 4 verifies the signature over the recorded digest but is not marked as a full document check.")


# -------------------------------------------------------------------- audit
def audit_trail():
    ui.page_header("receipt_long", "Audit Trail",
                   "A hash-linked log of signing and verification events. Editing, reordering or deleting a record in the middle breaks the chain.")
    recs, err = audit.read_records()
    rep = audit.verify_chain(recs, err)
    if not recs and not err:
        ui.card(ui.empty("receipt_long", "No audit events yet",
                         "Sign or verify a document and each event is appended here with its digest and fingerprint."))
    else:
        ui.kv_table([("Records", ui.mono(len(recs))),
                     ("Chain status", ui.badge("Consistent", "ok", "check_circle") if rep.ok
                      else ui.badge(f"Broken at record {rep.first_bad_seq}", "err", "cancel")),
                     ("Head hash", ui.mono(rep.head_hash or "n/a"))])
        if not rep.ok:
            st.error(f"First problem: {rep.reason}.", icon=":material/error:")
        ui.table(["#", "Time (self-reported)", "Event", "Outcome", "Decision", "Hash"],
                 [[ui.esc(r.get("seq")), ui.esc(r.get("time")), ui.esc(r.get("type")), ui.esc(r.get("outcome") or "-"),
                   ui.esc(r.get("decision") or "-"), ui.mono(str(r.get("hash"))[:16] + "...")] for r in reversed(recs[-25:])])
        st.caption("Latest 25 records. Only digests, fingerprints and outcomes are stored: never document contents, file names or keys.")

    st.markdown("#### Verify the chain")
    c1, c2 = st.columns([3, 1])
    anchor_head = c1.text_input("Saved head hash (optional anchor)", placeholder="Paste a head hash you saved earlier",
                                help="An anchor kept somewhere else lets the check detect truncation or a full rewrite.")
    anchor_n = c2.number_input("Saved record count", min_value=0, value=0, step=1)
    if st.button("Verify audit chain", type="primary", icon=":material/verified_user:"):
        r2 = audit.verify_chain(recs, err, anchor_head.strip() or None, int(anchor_n) or None)
        (st.success if r2.ok else st.error)(r2.reason[0].upper() + r2.reason[1:] + ".",
                                            icon=":material/check_circle:" if r2.ok else ":material/error:")

    st.markdown("#### Controlled tamper demonstration")
    st.caption("Works on an in-memory copy. Your real log is never modified.")
    if len(recs) < 2:
        st.info("Create at least two audit events (verify a document twice) to run the demonstration.", icon=":material/info:")
    else:
        i = st.number_input("Record to alter", 0, len(recs) - 1, 0, key="tamper_i")
        field = st.selectbox("Field to change", ["outcome", "doc_sha256", "decision", "prev_hash"])
        if st.button("Alter the copy and re-verify", icon=":material/science:"):
            copy = json.loads(json.dumps(recs))
            copy[int(i)][field] = "tampered" if field != "doc_sha256" else "00" * 32
            rep2 = audit.verify_chain(copy)
            if rep2.ok:
                st.warning("The change was not detected.", icon=":material/warning:")
            else:
                st.error(f"Detected. First invalid record: {rep2.first_bad_seq}. {rep2.reason[0].upper() + rep2.reason[1:]}.",
                         icon=":material/error:")

    with st.expander("What this log can and cannot protect against", icon=":material/policy:"):
        st.markdown(
            "**Detects:** edited records, edited links, reordered, inserted or removed middle records, and unreadable lines.\n\n"
            "**Cannot detect without an external anchor:** deleting the newest records, or rebuilding the whole chain with new hashes. "
            "Someone with write access to this machine can do both. Saving the head hash elsewhere (above) detects them; stronger "
            "protection needs independent witnesses or an append-only transparency service.\n\n"
            "**Timestamps** come from this computer's clock and are not trusted time.")


# ----------------------------------------------------------------- policies
def policies():
    ui.page_header("policy", "Verification Policies",
                   "Rules applied after the cryptographic check. The same valid signature can be accepted, accepted with warnings, or rejected, "
                   "but a policy can never make an invalid signature valid.")
    for key, p in policy.BUILTIN.items():
        with st.expander(f"{p['name']}: {p['description']}", expanded=(key == "standard")):
            ui.kv_table([("Algorithm allowlist", ui.mono(", ".join(p["allowed_algs"]))),
                         ("Minimum format version", ui.mono(p["min_format_version"])),
                         ("Maximum document size", ui.mono(f"{p['max_doc_bytes']:,} bytes")),
                         ("Unknown signer", ui.mono(p["unknown_signer"])),
                         ("Require integrity metadata", ui.mono(p["require_integrity_metadata"])),
                         ("Policy digest", ui.mono(policy.policy_digest(p)))])
            st.download_button("Export policy file", policy.policy_to_file(p), f"policy_{key}.json", key="dl" + key,
                               icon=":material/download:")

    st.markdown("#### Same signature, different decisions")
    st.caption("Generates a fresh valid signature with an unpinned key and applies each policy to it.")
    if st.button("Run comparison", icon=":material/compare:"):
        doc = b"Policy comparison document.\n" * 4
        priv, pubpem = keys.generate_keypair()
        r = verify_document(doc, sign_document(doc, priv, "policy_demo.txt"), pubpem, "policy_demo.txt")
        bad = verify_document(doc + b"x", sign_document(doc, priv, "policy_demo.txt"), pubpem, "policy_demo.txt")
        rows = []
        for k, p in policy.BUILTIN.items():
            dv, db = policy.evaluate(p, r), policy.evaluate(p, bad)
            rows.append([ui.esc(p["name"]), ui.status_badge(r.status), ui.decision_badge(dv.decision),
                         ui.status_badge(bad.status), ui.decision_badge(db.decision)])
        ui.table(["Policy", "Valid doc: signature", "Valid doc: decision", "Tampered doc: signature", "Tampered doc: decision"], rows)

    st.markdown("#### Use a custom policy file")
    up = st.file_uploader("Policy file (.json, exported from this page)", type=["json"], key="pol_up")
    if up is not None:
        try:
            st.session_state.custom_policy = policy.load_policy(views.read(up))
            st.success(f"Loaded policy '{st.session_state.custom_policy['name']}'. It now appears in the policy selectors.",
                       icon=":material/check_circle:")
        except ValueError as e:
            st.session_state.pop("custom_policy", None)
            st.error(f"Policy rejected: {e}", icon=":material/error:")
    st.caption("A policy file's digest detects modification after export. It does not prove who wrote the file.")


# ---------------------------------------------------------------------- lab
def crypto_lab():
    ui.page_header("biotech", "Cryptography Lab",
                   "Experimental comparison of Ed25519 with the NIST post-quantum signature standard ML-DSA (FIPS 204).")
    st.markdown(ui.badge("Experimental", "warn", "science") + " &nbsp; Isolated from signing: VeritySign signatures are still Ed25519 only.",
                unsafe_allow_html=True)
    algs = pqc_lab.algorithms()
    if len(algs) == 1:
        st.info(
            "\U0001f512 ML-DSA is not supported by the installed OpenSSL backend on this machine. "
            "The benchmark below runs Ed25519 only. "
            "To enable ML-DSA, upgrade to OpenSSL ≥ 3.3 and reinstall the `cryptography` package.",
            icon="ℹ️",
        )
    trials = st.slider("Trials per operation", 5, 100, 20)
    if st.button("Run benchmark", type="primary", icon=":material/speed:"):
        with st.status("Measuring", expanded=False) as s:
            st.session_state.lab = (pqc_lab.run_lab(trials), trials, datetime.now().strftime("%H:%M:%S"))
            s.update(label="Measurement complete", state="complete")
    if "lab" in st.session_state:
        rows, n, at = st.session_state.lab
        ui.table(["Algorithm", "Standard", "Public key (B)", "Private key (B)", "Signature (B)", "Keygen (ms)", "Sign (ms)", "Verify (ms)", "Self-checks"],
                 [[ui.esc(r.algorithm), ui.esc(r.standard), ui.esc(r.public_key_bytes), ui.esc(r.private_key_bytes), ui.esc(r.signature_bytes),
                   ui.esc(f"{r.keygen_ms:.3f}"), ui.esc(f"{r.sign_ms:.3f}"), ui.esc(f"{r.verify_ms:.3f}"),
                   ui.badge("All passed", "ok", "check_circle") if (r.verified and r.tampered_rejected and r.wrong_key_rejected)
                   else ui.badge("Failed", "err", "cancel")] for r in rows])
        st.caption(f"Method: median of {n} runs per operation using time.perf_counter, one 1,080-byte message, measured at {at} on this "
                   f"machine ({platform.system()} {platform.machine()}, Python {platform.python_version()}). Timings include library call overhead and vary "
                   "between runs. Private keys are shown in the 32-byte seed form; sizes are exact. Self-checks: valid signature verifies, tampered message and wrong key are rejected.")
    with st.expander("Compatibility and limitations", icon=":material/info:"):
        st.markdown("- ML-DSA signatures are far larger than Ed25519 (about 2.4 to 4.6 KB against 64 bytes), which matters for file formats and storage.\n"
                    "- VeritySign's `.vsig` v1 format allows only Ed25519. Adding ML-DSA would need a new format version and an explicit policy allowlist entry, "
                    "so existing signatures keep verifying unchanged.\n"
                    "- Results come from the installed library's real implementation; this lab does not claim ML-DSA is more or less secure in any other respect.")
