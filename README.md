<div align="center">

# 🔑 fido2-yubikey-demo

**The cryptographic heart of FIDO2 / WebAuthn, implemented and explained.**
A self-contained, runnable demo that creates a credential, signs an authentication assertion (as a YubiKey would), and verifies it the way a relying party does — including a demonstration of **why FIDO2 is phishing-resistant**.

![Python](https://img.shields.io/badge/Python-3.10+-0A1929?style=for-the-badge&logo=python&logoColor=12ABDB)
![FIDO2](https://img.shields.io/badge/FIDO2-WebAuthn-0A1929?style=for-the-badge)
![Crypto](https://img.shields.io/badge/ES256-ECDSA_P--256-0A1929?style=for-the-badge)

</div>

---

## What it shows

WebAuthn/FIDO2 authentication boils down to a **challenge–response signature** over data the authenticator controls. This project implements that core, with no hardware required, so you can *see* every byte:

1. **Registration** — generate an EC P-256 key pair (the authenticator's credential).
2. **Authentication** — the authenticator builds `authenticatorData`, hashes the `clientDataJSON`, and signs them.
3. **Verification** — the relying party checks the RP ID hash, the user-present flag, the origin, the challenge, and the ECDSA signature.

> Same primitives a YubiKey uses (`ES256` / ECDSA over NIST P-256). Real hardware just keeps the private key in a secure element.

## Why FIDO2 beats phishing 🎣🚫

The **origin** is inside `clientDataJSON`, which is **signed**. A phishing site at `evil-login.com` can relay a challenge, but the signature is bound to its own origin — so the legitimate relying party's verification **fails**. The demo proves this: `demo.py` runs an assertion captured on a phishing origin and verification rejects it.

## Run it

```bash
pip install -r requirements.txt
python -m src.demo
pytest -q          # valid signature verifies; tampered/phished assertions are rejected
```

Expected: a successful login, then a **rejected** phishing attempt and a **rejected** tampered signature.

## Files

```
src/webauthn_core.py   credential creation, assertion signing, RP-side verification
src/demo.py            full register → authenticate → verify walkthrough
tests/                 pytest: positive + negative (phishing, tamper) cases
docs/fido2-explained.md  concepts: WebAuthn, attestation, UV/UP, discoverable creds, YubiKey
```

## Next step: real YubiKeys

To drive a physical key, this maps directly onto [Yubico's `python-fido2`](https://github.com/Yubico/python-fido2) (`Fido2Server` + browser `navigator.credentials`). See `docs/fido2-explained.md` for the bridge to a full WebAuthn server.

## Disclaimer
Educational. Cryptography via the `cryptography` library — don't roll your own crypto in production; use vetted WebAuthn libraries.
