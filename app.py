"""VeritySign - Digital Document Verifier (Streamlit entry point)."""
import streamlit as st

import ui
import views

st.set_page_config(page_title="VeritySign", page_icon=":material/verified_user:", layout="wide")
ui.inject_css()

if "history" not in st.session_state:
    st.session_state.history = []

P = {
    "dashboard": st.Page(views.dashboard, title="Dashboard", icon=":material/space_dashboard:", url_path="dashboard", default=True),
    "verify": st.Page(views.verify, title="Verify", icon=":material/fact_check:", url_path="verify"),
    "studio": st.Page(views.studio, title="Signer Studio", icon=":material/edit_document:", url_path="studio"),
    "demo": st.Page(views.demo, title="Demo & Tamper Lab", icon=":material/science:", url_path="demo"),
    "trust": st.Page(views.trust_store, title="Trust Store", icon=":material/verified_user:", url_path="trust"),
    "history": st.Page(views.history, title="History", icon=":material/history:", url_path="history"),
}
st.session_state.pages = P

nav = st.navigation(list(P.values()), position="hidden")

with st.sidebar:
    st.markdown(f'<div class="brand"><div class="brand-mark">{ui.icon("verified_user", "fill")}</div>'
                '<div><div class="brand-name">VeritySign</div><div class="brand-sub">Document verification</div></div></div>',
                unsafe_allow_html=True)
    for group, keys_ in [("Verify", ["dashboard", "verify", "demo"]), ("Manage", ["studio", "trust", "history"])]:
        st.markdown(f'<div class="nav-group">{group}</div>', unsafe_allow_html=True)
        for k in keys_:
            st.page_link(P[k])
    st.markdown('<div class="side-note" style="margin-top:1.5rem">Ed25519 and SHA-256. Local only: nothing is uploaded or stored.</div>',
                unsafe_allow_html=True)

nav.run()
