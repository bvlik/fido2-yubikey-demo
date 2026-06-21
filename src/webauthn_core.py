"""Minimal, correct implementation of the FIDO2/WebAuthn assertion flow.

This models what an authenticator (e.g. a YubiKey) and a relying party do during
WebAuthn authentication, using ES256 (ECDSA over NIST P-256) — the most common
FIDO2 algorithm. No hardware required.

Spec references:
    - authenticatorData: https://www.w3.org/TR/webauthn-2/#authenticator-data
    - signature:        sign( authenticatorData || SHA256(clientDataJSON) )
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

# authenticatorData flag bits (WebAuthn §6.1)
FLAG_USER_PRESENT = 0x01
FLAG_USER_VERIFIED = 0x04


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


class VerificationError(Exception):
    """Raised when an assertion fails any relying-party check."""


@dataclass
class Credential:
    """An authenticator credential. In real hardware the private key never leaves the device."""
    private_key: ec.EllipticCurvePrivateKey
    credential_id: bytes
    sign_count: int = 0

    @property
    def public_key(self) -> EllipticCurvePublicKey:
        return self.private_key.public_key()


def create_credential() -> Credential:
    """Registration: generate a new ES256 credential."""
    return Credential(
        private_key=ec.generate_private_key(ec.SECP256R1()),
        credential_id=os.urandom(16),
    )


def build_client_data(type_: str, challenge: bytes, origin: str) -> bytes:
    """Serialize clientDataJSON exactly as the browser does (compact, base64url challenge)."""
    return json.dumps(
        {
            "type": type_,
            "challenge": b64url_encode(challenge),
            "origin": origin,
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode("utf-8")


def build_authenticator_data(
    rp_id: str, *, user_present: bool = True, user_verified: bool = False, sign_count: int = 0
) -> bytes:
    """rpIdHash (32) || flags (1) || signCount (4)  — the assertion authenticatorData."""
    flags = 0
    if user_present:
        flags |= FLAG_USER_PRESENT
    if user_verified:
        flags |= FLAG_USER_VERIFIED
    return hashlib.sha256(rp_id.encode("utf-8")).digest() + bytes([flags]) + sign_count.to_bytes(4, "big")


def sign_assertion(
    credential: Credential, rp_id: str, challenge: bytes, origin: str
) -> tuple[bytes, bytes, bytes]:
    """Authenticator side: produce (authenticatorData, clientDataJSON, signature)."""
    credential.sign_count += 1
    client_data = build_client_data("webauthn.get", challenge, origin)
    auth_data = build_authenticator_data(rp_id, sign_count=credential.sign_count)
    signed = auth_data + hashlib.sha256(client_data).digest()
    signature = credential.private_key.sign(signed, ec.ECDSA(hashes.SHA256()))
    return auth_data, client_data, signature


def verify_assertion(
    public_key: EllipticCurvePublicKey,
    auth_data: bytes,
    client_data: bytes,
    signature: bytes,
    *,
    expected_rp_id: str,
    expected_origin: str,
    expected_challenge: bytes,
    require_user_present: bool = True,
) -> bool:
    """Relying-party side: run every WebAuthn assertion check. Raises VerificationError on failure."""
    # 1. clientDataJSON checks
    try:
        cd = json.loads(client_data)
    except json.JSONDecodeError as exc:
        raise VerificationError("clientDataJSON is not valid JSON") from exc
    if cd.get("type") != "webauthn.get":
        raise VerificationError("unexpected clientData type")
    if cd.get("origin") != expected_origin:
        raise VerificationError(f"origin mismatch (phishing?): {cd.get('origin')!r}")
    if b64url_decode(cd.get("challenge", "")) != expected_challenge:
        raise VerificationError("challenge mismatch (replay?)")

    # 2. authenticatorData checks
    if auth_data[:32] != hashlib.sha256(expected_rp_id.encode("utf-8")).digest():
        raise VerificationError("rpIdHash mismatch")
    flags = auth_data[32]
    if require_user_present and not (flags & FLAG_USER_PRESENT):
        raise VerificationError("user-present flag not set")

    # 3. signature over authenticatorData || SHA256(clientDataJSON)
    signed = auth_data + hashlib.sha256(client_data).digest()
    try:
        public_key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise VerificationError("invalid signature") from exc
    return True
