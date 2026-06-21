# FIDO2 / WebAuthn, explained

## The two halves

- **WebAuthn** — the browser/relying-party API (`navigator.credentials.create()` / `.get()`).
- **CTAP2** — the protocol between the browser and the authenticator (e.g. a YubiKey over USB/NFC).

Together they let a website authenticate a user with a key pair instead of a password.

## Registration (make credential)

1. The relying party (RP) sends a random **challenge** and its **RP ID** (a domain).
2. The authenticator generates a **key pair**; the private key stays on the device (in a YubiKey, inside a secure element).
3. It returns the **public key** + an **attestation** (optional proof of what kind of device it is).

## Authentication (get assertion) — what this repo implements

1. RP sends a fresh **challenge**.
2. The authenticator builds **`authenticatorData`** = `SHA256(rpId) || flags || signCount` and signs
   `authenticatorData || SHA256(clientDataJSON)`.
3. The RP verifies: RP ID hash matches, **user-present** (and optionally **user-verified**) flags set,
   **origin** and **challenge** match, and the **signature** is valid for the stored public key.

## Why it's phishing-resistant 🎣🚫

The **origin** is part of `clientDataJSON`, and `clientDataJSON` is **signed**. The browser sets the origin
to the *real* site the user is on. So if a user lands on `examp1e-login.com`, any assertion produced there is
bound to that origin — and the genuine RP's check `origin == "https://example.com"` fails. Credentials are also
**scoped to the RP ID**, so a key for `example.com` won't even be offered on another domain. Passwords and OTP
codes have no such binding, which is why they get phished.

## Key terms

| Term | Meaning |
|------|---------|
| RP ID | The domain a credential is bound to (e.g. `example.com`) |
| UP / UV | User Present (touch) / User Verified (PIN or biometric) |
| signCount | Monotonic counter; a decrease hints at a cloned authenticator |
| Discoverable credential | "Passkey" — the key is resident on the authenticator, enabling usernameless login |
| Attestation | Optional signed statement about the authenticator's make/model |

## Where YubiKeys fit

A YubiKey is a hardware authenticator implementing CTAP2. The private key is generated and stored in a secure
element and never leaves it; the touch satisfies **user presence**, an optional PIN satisfies **user
verification**. The crypto in this repo (`ES256` / ECDSA P-256) is exactly what a YubiKey performs.

## From this demo to a real server

This repo implements the verification core. A production setup adds: CBOR/COSE encoding, attestation validation,
credential storage, and the browser dance — all handled by [Yubico's `python-fido2`](https://github.com/Yubico/python-fido2)
(`Fido2Server.register_begin/complete`, `authenticate_begin/complete`) wired to `navigator.credentials` in the page.
