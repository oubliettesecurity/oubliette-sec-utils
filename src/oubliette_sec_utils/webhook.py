"""Webhook signature verification (fail-closed HMAC-SHA256).

Shared primitive consolidated from the per-repo copies in oubliette-shield and
oubliette-dungeon so the merchant-of-record webhook auth is defined in exactly
one place.
"""

import hashlib
import hmac

__all__ = ["verify_webhook_signature"]


def verify_webhook_signature(raw_body: bytes, signature: str | None, secret: str | None) -> bool:
    """Constant-time HMAC-SHA256 verification of a webhook body.

    Fail-closed: a valid signature over the exact raw request body is REQUIRED.
    A missing/blank ``secret``, or a missing/blank/wrong ``signature``, returns
    ``False`` — verification never succeeds without a configured secret.

    Accepts an optional ``sha256=`` prefix and is case-insensitive on the hex
    digest, matching how merchant-of-record providers format signature headers.
    """
    if not secret:
        return False
    if not signature:
        return False
    expected = hmac.new(secret.encode(), raw_body or b"", hashlib.sha256).hexdigest()
    provided = signature.split("=", 1)[-1].strip().lower()
    return hmac.compare_digest(expected, provided)
