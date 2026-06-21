"""End-to-end walkthrough: register, authenticate, and reject phishing/tampering.

Run:  python -m src.demo
"""
from __future__ import annotations

import os

from .webauthn_core import (
    VerificationError,
    create_credential,
    sign_assertion,
    verify_assertion,
)

RP_ID = "example.com"
ORIGIN = "https://example.com"
PHISHING_ORIGIN = "https://examp1e-login.com"


def _line(label: str, ok: bool, extra: str = "") -> None:
    mark = "[PASS]  " if ok else "[REJECT]"
    print(f"  {mark}  {label}{(' - ' + extra) if extra else ''}")


def main() -> None:
    print("== FIDO2 / WebAuthn assertion demo ==\n")

    # Registration
    credential = create_credential()
    print(f"[register] new ES256 credential id={credential.credential_id.hex()}\n")

    # 1. Legitimate authentication
    challenge = os.urandom(32)
    auth_data, client_data, signature = sign_assertion(credential, RP_ID, challenge, ORIGIN)
    print("[authenticate] genuine login on", ORIGIN)
    try:
        verify_assertion(
            credential.public_key, auth_data, client_data, signature,
            expected_rp_id=RP_ID, expected_origin=ORIGIN, expected_challenge=challenge,
        )
        _line("genuine assertion", True)
    except VerificationError as exc:
        _line("genuine assertion", False, str(exc))

    # 2. Phishing: same key, but the assertion was produced on a look-alike origin
    phish_data, phish_client, phish_sig = sign_assertion(credential, "examp1e-login.com", challenge, PHISHING_ORIGIN)
    print("\n[phishing] attacker relays the login from", PHISHING_ORIGIN)
    try:
        verify_assertion(
            credential.public_key, phish_data, phish_client, phish_sig,
            expected_rp_id=RP_ID, expected_origin=ORIGIN, expected_challenge=challenge,
        )
        _line("phishing assertion", True, "THIS SHOULD NOT HAPPEN")
    except VerificationError as exc:
        _line("phishing assertion", False, str(exc))

    # 3. Tampering: flip a byte of the signature
    print("\n[tamper] attacker modifies the signature")
    tampered = bytearray(signature)
    tampered[-1] ^= 0x01
    try:
        verify_assertion(
            credential.public_key, auth_data, client_data, bytes(tampered),
            expected_rp_id=RP_ID, expected_origin=ORIGIN, expected_challenge=challenge,
        )
        _line("tampered assertion", True, "THIS SHOULD NOT HAPPEN")
    except VerificationError as exc:
        _line("tampered assertion", False, str(exc))

    print("\nTakeaway: the signed origin makes FIDO2 phishing-resistant by construction.")


if __name__ == "__main__":
    main()
