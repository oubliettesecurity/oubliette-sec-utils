"""Shared security helpers for Oubliette products.

These utilities consolidate patterns that were previously duplicated
across oubliette-shield / sentinel / oubliette-dungeon / oubliette-trap /
sift-guard -- path-scope checks, argument-injection validation, SSRF
IP classification, and URL validation. Extracting them here lets the
products share a single well-tested implementation and stops the same
bug from being re-found and re-fixed in each repo.

Nothing in this module imports any of those repos; callers depend on
this package, not the other way round.
"""

from oubliette_sec_utils.argv import (
    ALLOWLIST_IDENTIFIER,
    ALLOWLIST_STRICT,
    Decision,
    validate_allowlist,
    validate_argument,
)
from oubliette_sec_utils.paths import (
    contained_in,
    safe_realpath,
)
from oubliette_sec_utils.ssrf import (
    FLY_IO_ULA,
    UrlDecision,
    is_ip_safe,
    validate_outbound_url,
)

__version__ = "0.1.1"

__all__ = [
    "ALLOWLIST_IDENTIFIER",
    "ALLOWLIST_STRICT",
    "FLY_IO_ULA",
    "Decision",
    "UrlDecision",
    "__version__",
    "contained_in",
    "is_ip_safe",
    "safe_realpath",
    "validate_allowlist",
    "validate_argument",
    "validate_outbound_url",
]
