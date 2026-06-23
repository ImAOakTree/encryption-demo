import streamlit as st
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import time

st.set_page_config(page_title="AES-256 Encryption Demo", page_icon="🔐", layout="centered")

st.title("🔐 AES-256 Encryption Demo")
st.caption("See exactly what happens to your data when it's encrypted.")

st.divider()

if "key" not in st.session_state:
    st.session_state.key = AESGCM.generate_key(bit_length=256)
if "ciphertext" not in st.session_state:
    st.session_state.ciphertext = None
if "nonce" not in st.session_state:
    st.session_state.nonce = None
if "last_plaintext" not in st.session_state:
    st.session_state.last_plaintext = None

# --- Key ---
st.subheader("🗝️ Encryption Key (AES-256)")
st.caption("A random 256-bit secret. Both sender and receiver must have this — nobody else.")
key_hex = st.session_state.key.hex()
cols = st.columns(4)
for i, col in enumerate(cols):
    chunk = key_hex[i*16:(i+1)*16]
    col.code(chunk, language=None)

if st.button("🔁 Generate new key"):
    st.session_state.key = AESGCM.generate_key(bit_length=256)
    st.session_state.ciphertext = None
    st.session_state.nonce = None
    st.rerun()

st.divider()

# --- Input ---
st.subheader("✏️ Your message")
plaintext = st.text_area("", value="Hello parents! This is a secret.", height=80, label_visibility="collapsed")

st.divider()

# --- Encrypt ---
st.subheader("🔒 Encryption pipeline")

if st.button("Encrypt →", type="primary", use_container_width=True):
    aesgcm = AESGCM(st.session_state.key)
    st.session_state.nonce = os.urandom(12)
    st.session_state.ciphertext = aesgcm.encrypt(st.session_state.nonce, plaintext.encode(), None)
    st.session_state.last_plaintext = plaintext

if st.session_state.ciphertext:
    p = st.session_state.last_plaintext
    ct = st.session_state.ciphertext
    nonce = st.session_state.nonce

    # Step 1
    with st.container(border=True):
        st.markdown("**Step 1 — Plaintext (your original message)**")
        st.code(p, language=None)
        cols = st.columns(len(p.encode()) if len(p) <= 20 else 20)
        sample = p.encode()[:20]
        for i, col in enumerate(cols):
            col.metric(label=f"'{chr(sample[i])}'", value=sample[i], help="ASCII byte value")
        if len(p) > 20:
            st.caption(f"… showing first 20 of {len(p.encode())} bytes")

    st.markdown("<div style='text-align:center; font-size:24px; margin:4px 0'>⬇️</div>", unsafe_allow_html=True)

    # Step 2
    with st.container(border=True):
        st.markdown("**Step 2 — Nonce or Number used once is a random 12-byte initialization vector**")
        st.caption("Generated fresh for every encryption. Without it, identical messages would produce identical ciphertext — a security leak.")
        st.code(nonce.hex(), language=None)
        ncols = st.columns(12)
        for i, col in enumerate(ncols):
            col.metric(label=f"b{i}", value=nonce[i])

    st.markdown("<div style='text-align:center; font-size:24px; margin:4px 0'>⬇️</div>", unsafe_allow_html=True)

    # Step 3
    with st.container(border=True):
        st.markdown("**Step 3 — AES-GCM cipher mixes key + nonce + plaintext**")
        st.caption("256-bit key XORed through 14 rounds of substitution, permutation, and mixing. Produces ciphertext + authentication tag.")

        c1, c2, c3 = st.columns(3)
        c1.info(f"🔑 Key\n\n`{key_hex[:8]}…`")
        c2.info(f"🎲 Nonce\n\n`{nonce.hex()[:8]}…`")
        c3.info(f"📝 Plaintext\n\n`{p[:8]}…`")

        st.markdown("<div style='text-align:center; font-size:20px'>⬇️ 14 rounds of mixing</div>", unsafe_allow_html=True)

    st.markdown("<div style='text-align:center; font-size:24px; margin:4px 0'>⬇️</div>", unsafe_allow_html=True)

    # Step 4
    with st.container(border=True):
        st.markdown("**Step 4 — Ciphertext output**")
        st.caption("Indistinguishable from random noise. The last 16 bytes are the GCM authentication tag.")

        ct_hex = ct.hex()
        data_hex = ct_hex[:-32]
        tag_hex  = ct_hex[-32:]

        st.markdown("Data bytes:")
        st.code(data_hex, language=None)
        st.markdown("Authentication tag (last 16 bytes — used to verify correct key on decryption):")
        st.code(tag_hex, language=None)

        # byte heatmap using progress bars
        st.caption("Byte value distribution — should look random (no patterns):")
        sample_bytes = list(ct[:32])
        bcols = st.columns(len(sample_bytes))
        for i, col in enumerate(bcols):
            col.progress(sample_bytes[i] / 255)

else:
    st.info("Hit **Encrypt →** to see the pipeline.")

st.divider()

# --- Decrypt ---
st.subheader("🔓 Decryption")
if st.session_state.ciphertext is None:
    st.warning("Encrypt a message first.")
else:
    c1, c2 = st.columns(2)
    with c1:
        if st.button("✅ Correct key", use_container_width=True):
            aesgcm = AESGCM(st.session_state.key)
            result = aesgcm.decrypt(st.session_state.nonce, st.session_state.ciphertext, None)
            st.success(f"**Decrypted:** {result.decode()}")

    with c2:
        if st.button("❌ Wrong key", use_container_width=True):
            try:
                wrong_key = AESGCM.generate_key(bit_length=256)
                aesgcm = AESGCM(wrong_key)
                aesgcm.decrypt(st.session_state.nonce, st.session_state.ciphertext, None)
            except Exception:
                st.error("Authentication failed — the tag doesn't match. Zero output. Attacker gets nothing.")

st.divider()
st.caption("AES-256-GCM · Same algorithm used by HTTPS, WhatsApp, Signal, and your bank.")