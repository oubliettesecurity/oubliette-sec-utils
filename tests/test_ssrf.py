"""Tests for SSRF validation helpers."""

import pytest

from oubliette_sec_utils.ssrf import is_ip_safe, validate_outbound_url


class TestIsIpSafe:
    @pytest.mark.parametrize(
        "addr",
        [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",  # AWS IMDS
            "::1",
            "fe80::1",
            "fc00::1",
            "fdaa::1",  # Fly.io 6PN
            "fdaa:abcd:ef01::dead:beef",
            "::ffff:127.0.0.1",  # IPv4-mapped IPv6
            "::ffff:10.0.0.1",
            "224.0.0.1",  # multicast
            "0.0.0.0",
        ],
    )
    def test_unsafe_addresses_rejected(self, addr):
        assert is_ip_safe(addr) is False

    @pytest.mark.parametrize(
        "addr",
        [
            "1.1.1.1",  # Cloudflare DNS
            "8.8.8.8",  # Google DNS
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ],
    )
    def test_public_addresses_safe(self, addr):
        assert is_ip_safe(addr) is True

    def test_invalid_returns_false(self):
        assert is_ip_safe("not-an-ip") is False


class TestValidateOutboundUrl:
    @pytest.mark.parametrize(
        "url,reason_contains",
        [
            ("", "required"),
            ("not a url", "scheme"),
            ("ftp://example.com", "scheme"),
            ("http://localhost/", "internal"),
            ("http://localhost.localdomain/", "internal"),
            ("http://169.254.169.254/", "internal"),
            ("http://foo.internal/", "internal"),
            ("http://foo.corp/", "internal"),
            ("http://127.0.0.1/", "private"),
            ("http://10.0.0.5/", "private"),
            ("http://[fdaa::1]/", "private"),
        ],
    )
    def test_blocked_urls(self, url, reason_contains):
        d = validate_outbound_url(url)
        assert d.safe is False
        assert reason_contains.lower() in d.reason.lower()

    def test_public_ip_literal_allowed(self):
        d = validate_outbound_url("http://1.1.1.1/")
        assert d.safe is True
