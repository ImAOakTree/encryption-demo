# 🔐 Encryption Demo

Interactive Streamlit demo showing what happens to data when it's encrypted. Built as a task parkour station.

- **`encryption_demo.py`** — AES-256-GCM pipeline walkthrough + decryption test.
- **`encryption_demo_with_RSA.py`** — AES (symmetric) vs RSA (asymmetric), side by side.

## Setup

```bash
git clone https://github.com/ImAOakTree/encryption-demo.git #clone it to a folder of your choice
cd encryption-demo

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
streamlit run encryption_demo.py            # AES walkthrough
streamlit run encryption_demo_with_RSA.py   # AES vs RSA
```

There are two Demo Sites starting. The Code can be found in the Repo.

## Example Presentation (Step by Step)

1. **Start:** "You use encryption every day, but never see it. Here it is."
2. **Key:** Show the 256-bit key. "This random number is the whole secret — unbreakable by brute force."
3. **Encrypt:** Hit **Encrypt →** and walk the boxes: plaintext (letters are just numbers) → nonce (fresh random value, no patterns) → AES mixing → ciphertext (looks like pure noise).
4. **Decrypt:** **✅ Correct key** → message comes back. **❌ Wrong key** → zero output. (This contrast is the payoff — show both.)
5. **RSA to AES comparison:** AES = one shared key. RSA = public key encrypts, private key decrypts. HTTPS uses both: RSA to share an AES key, then AES for speed.
6. **End:** "Same algorithm that protects your bank and your messages."

## Takeaways

- Encryption turns readable data into something indistinguishable from random noise.
- Security depends on keeping the **key** secret, not hiding the algorithm.
- Wrong key = **nothing**, not "almost right" — no partial leakage.
- AES is fast but needs a shared secret; RSA is slow but solves key sharing. Real systems use both.
