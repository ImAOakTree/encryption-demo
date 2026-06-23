import streamlit as st
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import secrets

st.set_page_config(page_title="AES-256 Encryption Demo", page_icon="🔐", layout="centered")

st.title("🔐 AES-256 Encryption Demo")
st.caption("Type a message, encrypt it, then try decrypting with the correct key vs a wrong key.")

st.divider()

# --- Key management ---
if "key" not in st.session_state:
    st.session_state.key = AESGCM.generate_key(bit_length=256)
if "ciphertext" not in st.session_state:
    st.session_state.ciphertext = None
if "nonce" not in st.session_state:
    st.session_state.nonce = None

col1, col2 = st.columns([3, 1])
with col1:
    st.markdown("**AES-256 Key**")
    st.code(st.session_state.key.hex()[:32] + "…", language=None)
with col2:
    st.markdown("&nbsp;", unsafe_allow_html=True)
    if st.button("🔁 New Key", use_container_width=True):
        st.session_state.key = AESGCM.generate_key(bit_length=256)
        st.session_state.ciphertext = None
        st.session_state.nonce = None
        st.rerun()

st.divider()

# --- Step 1: Input ---
st.subheader("1. Your message")
plaintext = st.text_area("Type anything:", value="Hello parents! This is a secret message.", height=80, label_visibility="collapsed")

# --- Step 2: Encrypt ---
st.subheader("2. Encrypt")
if st.button("🔒 Encrypt", type="primary", use_container_width=True):
    aesgcm = AESGCM(st.session_state.key)
    st.session_state.nonce = os.urandom(12)
    st.session_state.ciphertext = aesgcm.encrypt(st.session_state.nonce, plaintext.encode(), None)

if st.session_state.ciphertext:
    st.markdown("**Ciphertext** (what an attacker sees):")
    st.code(st.session_state.ciphertext.hex(), language=None)
else:
    st.info("Hit **Encrypt** to scramble your message.")

st.divider()

# --- Step 3: Decrypt ---
st.subheader("3. Decrypt")
col_a, col_b = st.columns(2)

with col_a:
    if st.button("✅ Correct key", use_container_width=True, disabled=st.session_state.ciphertext is None):
        try:
            aesgcm = AESGCM(st.session_state.key)
            result = aesgcm.decrypt(st.session_state.nonce, st.session_state.ciphertext, None)
            st.success(f"**Decrypted:** {result.decode()}")
        except Exception as e:
            st.error(f"Failed: {e}")

with col_b:
    if st.button("❌ Wrong key", use_container_width=True, disabled=st.session_state.ciphertext is None):
        try:
            wrong_key = AESGCM.generate_key(bit_length=256)
            aesgcm = AESGCM(wrong_key)
            result = aesgcm.decrypt(st.session_state.nonce, st.session_state.ciphertext, None)
            st.success(result.decode())
        except Exception:
            st.error("⚠️ Authentication failed — data is completely unreadable without the correct key.")

st.divider()
st.caption("Built with AES-256-GCM via Python `cryptography` library. This is the same algorithm used by HTTPS, WhatsApp, and your bank.")
