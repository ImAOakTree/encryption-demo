import streamlit as st
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import os

st.set_page_config(page_title="Encryption Demo", page_icon="🔐", layout="wide")

st.title("🔐 Encryption Demo")
st.caption("Compare AES-256 (symmetric) vs RSA (asymmetric) encryption side by side.")

# ── session state ──────────────────────────────────────────────
if "aes_key" not in st.session_state:
    st.session_state.aes_key = AESGCM.generate_key(bit_length=256)
if "aes_ct" not in st.session_state:
    st.session_state.aes_ct = None
if "aes_nonce" not in st.session_state:
    st.session_state.aes_nonce = None
if "aes_pt" not in st.session_state:
    st.session_state.aes_pt = None

if "rsa_private" not in st.session_state:
    with st.spinner("Generating RSA-2048 key pair…"):
        st.session_state.rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
if "rsa_ct" not in st.session_state:
    st.session_state.rsa_ct = None
if "rsa_pt" not in st.session_state:
    st.session_state.rsa_pt = None

# ── comparison table ───────────────────────────────────────────
with st.expander("📊 AES vs RSA — quick comparison", expanded=True):
    t = st.columns(3)
    t[0].markdown("&nbsp;")
    t[1].markdown("**AES-256 (symmetric)**")
    t[2].markdown("**RSA-2048 (asymmetric)**")

    rows = [
        ("Keys",        "1 shared secret key",          "Public key + private key pair"),
        ("Speed",       "Very fast",                     "~100× slower than AES"),
        ("Key sharing", "Hard — must share secretly",    "Easy — public key is public"),
        ("Used for",    "Bulk data, files, messages",    "Key exchange, signatures"),
        ("Real world",  "WhatsApp messages, files",      "HTTPS handshake, email signing"),
        ("Key size",    "256 bits",                      "2048–4096 bits"),
    ]
    for label, aes_val, rsa_val in rows:
        c = st.columns(3)
        c[0].markdown(f"**{label}**")
        c[1].markdown(aes_val)
        c[2].markdown(rsa_val)

    st.info("💡 In practice HTTPS uses **both**: RSA to securely exchange an AES key, then AES to encrypt everything after that.")

st.divider()

# ══════════════════════════════════════════════════════════════
# LEFT: AES-256
# RIGHT: RSA-2048
# ══════════════════════════════════════════════════════════════
left, right = st.columns(2, gap="large")

# ─────────────────────────────────────────────────────────────
with left:
    st.subheader("🔑 AES-256 — Symmetric")
    st.caption("One shared key encrypts and decrypts.")

    with st.container(border=True):
        st.markdown("**Shared key**")
        k = st.session_state.aes_key.hex()
        st.code(k[:32] + "…", language=None)
        if st.button("🔁 New AES key", key="new_aes"):
            st.session_state.aes_key = AESGCM.generate_key(bit_length=256)
            st.session_state.aes_ct = None
            st.rerun()

    aes_msg = st.text_area("Message", value="Hello! This is secret.", key="aes_msg", height=80)

    if st.button("🔒 Encrypt (AES)", use_container_width=True, key="aes_enc"):
        aesgcm = AESGCM(st.session_state.aes_key)
        st.session_state.aes_nonce = os.urandom(12)
        st.session_state.aes_ct = aesgcm.encrypt(st.session_state.aes_nonce, aes_msg.encode(), None)
        st.session_state.aes_pt = aes_msg

    if st.session_state.aes_ct:
        with st.container(border=True):
            st.markdown("**Pipeline**")
            st.markdown(f"✏️ Plaintext → `{st.session_state.aes_pt[:20]}…`")
            st.markdown(f"🎲 Nonce → `{st.session_state.aes_nonce.hex()[:16]}…`")
            st.markdown(f"🔑 Key → `{st.session_state.aes_key.hex()[:16]}…`")
            st.markdown("⬇️ *14 rounds of AES mixing*")
            st.markdown("**Ciphertext:**")
            st.code(st.session_state.aes_ct.hex()[:64] + "…", language=None)

            st.caption("Byte distribution (should look random):")
            bcols = st.columns(16)
            for i, col in enumerate(bcols):
                col.progress(st.session_state.aes_ct[i] / 255)

        c1, c2 = st.columns(2)
        with c1:
            if st.button("✅ Correct key", use_container_width=True, key="aes_dec_ok"):
                aesgcm = AESGCM(st.session_state.aes_key)
                result = aesgcm.decrypt(st.session_state.aes_nonce, st.session_state.aes_ct, None)
                st.success(f"**Decrypted:** {result.decode()}")
        with c2:
            if st.button("❌ Wrong key", use_container_width=True, key="aes_dec_bad"):
                try:
                    AESGCM(AESGCM.generate_key(bit_length=256)).decrypt(
                        st.session_state.aes_nonce, st.session_state.aes_ct, None)
                except Exception:
                    st.error("Authentication failed — zero output.")
    else:
        st.info("Hit **Encrypt (AES)** to see the pipeline.")

# ─────────────────────────────────────────────────────────────
with right:
    st.subheader("🔑🔑 RSA-2048 — Asymmetric")
    st.caption("Public key encrypts. Only the private key can decrypt.")

    priv = st.session_state.rsa_private
    pub  = priv.public_key()
    pub_numbers = pub.public_key().public_numbers() if hasattr(pub, 'public_key') else pub.public_numbers()

    with st.container(border=True):
        st.markdown("**Public key** *(share freely — anyone can encrypt)*")
        e = pub_numbers.e
        n = pub_numbers.n
        st.code(f"e = {e}\nn = {str(n)[:60]}…", language=None)

        st.markdown("**Private key** *(keep secret — only you can decrypt)*")
        st.code("d = [HIDDEN — never shared]", language=None)

        if st.button("🔁 New RSA key pair", key="new_rsa"):
            with st.spinner("Generating…"):
                st.session_state.rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            st.session_state.rsa_ct = None
            st.rerun()

    rsa_msg = st.text_area("Message", value="Hello! This is secret.", key="rsa_msg", height=80)

    if st.button("🔒 Encrypt (RSA)", use_container_width=True, key="rsa_enc"):
        try:
            st.session_state.rsa_ct = pub.encrypt(
                rsa_msg.encode(),
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            st.session_state.rsa_pt = rsa_msg
        except ValueError as ex:
            st.error(f"Message too long for RSA: {ex}")

    if st.session_state.rsa_ct:
        with st.container(border=True):
            st.markdown("**Pipeline**")
            st.markdown(f"✏️ Plaintext → `{st.session_state.rsa_pt[:20]}…`")
            st.markdown(f"🔑 Public key (e, n) used to encrypt")
            st.markdown("⬇️ *OAEP padding + modular exponentiation*")
            st.markdown("**Ciphertext:**")
            st.code(st.session_state.rsa_ct.hex()[:64] + "…", language=None)
            st.caption(f"Ciphertext is always {len(st.session_state.rsa_ct) * 8} bits — same as the key size.")

            st.caption("Byte distribution:")
            bcols = st.columns(16)
            for i, col in enumerate(bcols):
                col.progress(st.session_state.rsa_ct[i] / 255)

        c1, c2 = st.columns(2)
        with c1:
            if st.button("✅ Private key", use_container_width=True, key="rsa_dec_ok"):
                result = priv.decrypt(
                    st.session_state.rsa_ct,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
                st.success(f"**Decrypted:** {result.decode()}")
        with c2:
            if st.button("❌ Wrong private key", use_container_width=True, key="rsa_dec_bad"):
                try:
                    wrong = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                    wrong.decrypt(
                        st.session_state.rsa_ct,
                        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                    )
                except Exception:
                    st.error("Decryption failed — wrong private key.")
    else:
        st.info("Hit **Encrypt (RSA)** to see the pipeline.")

st.divider()
st.caption("AES-256-GCM · RSA-2048-OAEP · Same algorithms used by HTTPS, WhatsApp, Signal, and your bank.")
