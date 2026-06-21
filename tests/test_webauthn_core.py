"""Positive and negative tests for the WebAuthn assertion core."""
import os

import pytest

from src.webauthn_core import (
    VerificationError,
    create_credential,
    sign_assertion,
    verify_assertion,
)

RP_ID = "example.com"
ORIGIN = "https://example.com"


def _assert(credential, challenge, **overrides):
    auth_data, client_data, signature = sign_assertion(credential, RP_ID, challenge, ORIGIN)
    params = dict(
        expected_rp_id=RP_ID, expected_origin=ORIGIN, expected_challenge=challenge,
    )
    params.update(overrides)
    return verify_assertion(credential.public_key, auth_data, client_data, signature, **params)


def test_genuine_assertion_verifies():
    cred = create_credential()
    challenge = os.urandom(32)
    assert _assert(cred, challenge) is True


def test_phishing_origin_is_rejected():
    cred = create_credential()
    challenge = os.urandom(32)
    # assertion signed on a phishing origin
    auth_data, client_data, signature = sign_assertion(cred, "evil.com", challenge, "https://evil.com")
    with pytest.raises(VerificationError, match="origin mismatch"):
        verify_assertion(
            cred.public_key, auth_data, client_data, signature,
            expected_rp_id=RP_ID, expected_origin=ORIGIN, expected_challenge=challenge,
        )


def test_replayed_challenge_is_rejected():
    cred = create_credential()
    auth_data, client_data, signature = sign_assertion(cred, RP_ID, os.urandom(32), ORIGIN)
    with pytest.raises(VerificationError, match="challenge mismatch"):
        verify_assertion(
            cred.public_key, auth_data, client_data, signature,
            expected_rp_id=RP_ID, expected_origin=ORIGIN, expected_challenge=os.urandom(32),
        )


def test_tampered_signature_is_rejected():
    cred = create_credential()
    challenge = os.urandom(32)
    auth_data, client_data, signature = sign_assertion(cred, RP_ID, challenge, ORIGIN)
    tampered = bytearray(signature)
    tampered[-1] ^= 0x01
    with pytest.raises(VerificationError, match="invalid signature"):
        verify_assertion(
            cred.public_key, auth_data, client_data, bytes(tampered),
            expected_rp_id=RP_ID, expected_origin=ORIGIN, expected_challenge=challenge,
        )
