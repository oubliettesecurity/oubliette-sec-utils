"""Tests for the fail-closed webhook signature verifier."""

import hashlib
import hmac as _hmac

from oubliette_sec_utils import verify_webhook_signature

SECRET = "wh-endpoint-secret"
BODY = b"seller_id=SELLER123&product=pro&email=buyer@acme.com"


def _sign(body: bytes, secret: str = SECRET) -> str:
    return _hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_accepts_valid_signature():
    assert verify_webhook_signature(BODY, _sign(BODY), SECRET) is True


def test_accepts_sha256_prefix_and_uppercase():
    assert verify_webhook_signature(BODY, "sha256=" + _sign(BODY).upper(), SECRET) is True


def test_rejects_wrong_signature():
    assert verify_webhook_signature(BODY, "deadbeef", SECRET) is False


def test_rejects_missing_signature():
    assert verify_webhook_signature(BODY, None, SECRET) is False
    assert verify_webhook_signature(BODY, "", SECRET) is False


def test_failclosed_when_no_secret():
    # No secret configured -> verification cannot succeed, even with a "valid" sig.
    assert verify_webhook_signature(BODY, _sign(BODY), None) is False
    assert verify_webhook_signature(BODY, _sign(BODY), "") is False
    assert verify_webhook_signature(BODY, None, None) is False


def test_signature_bound_to_body():
    # A signature valid for a different body must not verify.
    assert verify_webhook_signature(b"tampered body", _sign(BODY), SECRET) is False
