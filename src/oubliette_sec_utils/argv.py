"""Argument-injection validation for user strings that reach ``subprocess``.

``shell=False`` does NOT protect against argument injection -- it only
protects against shell-metachar expansion. An attacker supplying
``hive="SYSTEM --plugins /tmp/evil.pl"`` as a positional argument gets
their string split by the callee and may load attacker plugin code.
Validate every user string at the tool boundary.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Characters forbidden in any user-controlled string passed to a
# subprocess argv. Whitespace is rejected separately so individual
# callers may opt to allow spaces via ``allow_spaces=True``.
_FORBIDDEN_CHARS = re.compile(r"[;|&`$(){}<>\n\r\t\\*?\[\]\x00\"']")

# Common allowlists callers re-use.
ALLOWLIST_IDENTIFIER = re.compile(r"^[A-Za-z0-9_\-]{1,128}$")
ALLOWLIST_STRICT = re.compile(r"^[A-Za-z0-9._:\-/]{1,128}$")


@dataclass
class Decision:
    """Outcome of a validate_* call."""

    blocked: bool
    reason: str = ""


def validate_argument(
    value: object,
    *,
    allow_spaces: bool = False,
    max_len: int = 512,
) -> Decision:
    """Return a blocked/allowed decision for a single argv string.

    Rejects:
      - non-string values
      - strings longer than ``max_len``
      - embedded nul byte
      - strings that begin with ``-`` (flag-prefixed argv injection)
      - whitespace unless ``allow_spaces=True``
      - shell metachars / quotes / backslash / glob chars
    """
    if not isinstance(value, str):
        return Decision(blocked=True, reason="Argument must be a string")
    if len(value) > max_len:
        return Decision(blocked=True, reason=f"Argument too long ({len(value)} > {max_len})")
    if "\x00" in value:
        return Decision(blocked=True, reason="Argument contains nul byte")
    stripped = value.lstrip()
    if stripped.startswith("-"):
        return Decision(
            blocked=True,
            reason=f"Argument injection detected: flag-prefixed '{value}'",
        )
    if not allow_spaces and re.search(r"[ \t]", value):
        return Decision(
            blocked=True,
            reason=f"Argument injection detected: whitespace in '{value}'",
        )
    if _FORBIDDEN_CHARS.search(value):
        return Decision(
            blocked=True,
            reason=f"Argument injection detected: forbidden character in '{value}'",
        )
    return Decision(blocked=False)


def validate_allowlist(
    value: object,
    allowlist,
    *,
    case_insensitive: bool = True,
) -> Decision:
    """Check ``value`` against a strict allowlist (e.g. registry hive names).

    Use this for parameters with a known-finite set of legal values rather
    than :func:`validate_argument` which applies a looser character-class
    rule.
    """
    if not isinstance(value, str):
        return Decision(blocked=True, reason="Allowlisted argument must be a string")
    candidate = value.upper() if case_insensitive else value
    normalised_allow = {a.upper() for a in allowlist} if case_insensitive else set(allowlist)
    if candidate not in normalised_allow:
        return Decision(blocked=True, reason=f"Value '{value}' not in allowlist")
    return Decision(blocked=False)
