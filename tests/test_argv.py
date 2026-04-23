"""Tests for argv validation helpers."""

import pytest

from oubliette_sec_utils.argv import (
    ALLOWLIST_IDENTIFIER,
    validate_allowlist,
    validate_argument,
)


class TestValidateArgument:
    def test_simple_safe(self):
        assert validate_argument("SYSTEM").blocked is False

    def test_non_string_rejected(self):
        assert validate_argument(123).blocked is True

    def test_too_long_rejected(self):
        assert validate_argument("a" * 513).blocked is True

    def test_nul_byte_rejected(self):
        assert validate_argument("abc\x00def").blocked is True

    @pytest.mark.parametrize(
        "hostile",
        [
            "-v",
            "--plugins",
            "--plugins /tmp/evil.pl",
            "   --recursive   ",  # leading whitespace still strips to a flag
        ],
    )
    def test_flag_prefix_blocked(self, hostile):
        # Flag-prefix check fires on strings that BEGIN with ``-`` (even if
        # preceded by whitespace, since lstrip is applied first). Strings
        # that happen to embed ``--`` inside a larger single argv are NOT
        # caught here -- use validate_allowlist for finite-set parameters
        # like hive names to close that vector.
        assert validate_argument(hostile, allow_spaces=True).blocked is True

    def test_embedded_flag_not_blocked_when_spaces_allowed(self):
        # ``SYSTEM --plugins /tmp/evil.pl`` is one argv entry -- subprocess
        # will pass it whole to the callee. If the callee then splits it,
        # that's a callee bug OR the caller should have used an allowlist.
        assert (
            validate_argument("SYSTEM --plugins /tmp/evil.pl", allow_spaces=True).blocked is False
        )

    @pytest.mark.parametrize(
        "metachar",
        ["foo;bar", "foo|bar", "foo&bar", "foo`bar`", "foo$(x)", "foo>bar", "foo<bar"],
    )
    def test_metachars_blocked(self, metachar):
        assert validate_argument(metachar).blocked is True

    def test_whitespace_default_blocked(self):
        assert validate_argument("foo bar").blocked is True

    def test_whitespace_allowed_opt_in(self):
        assert validate_argument("foo bar", allow_spaces=True).blocked is False


class TestValidateAllowlist:
    def test_case_insensitive_hit(self):
        assert validate_allowlist("system", ["SYSTEM", "SOFTWARE"]).blocked is False

    def test_case_sensitive_miss(self):
        assert validate_allowlist("system", ["SYSTEM"], case_insensitive=False).blocked is True

    def test_injection_attempt_blocked(self):
        assert (
            validate_allowlist(
                "SYSTEM --plugins /tmp/evil.pl",
                ["SYSTEM", "SOFTWARE"],
            ).blocked
            is True
        )
