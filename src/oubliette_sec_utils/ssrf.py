"""SSRF validation utilities.

The helpers here decide whether an outbound URL or IP is safe to contact.
Every SSRF validator across the Oubliette codebase converges on the same
checklist: private ranges, loopback, link-local, reserved, IPv6-mapped
IPv4, and the Fly.io 6PN ULA range (not caught by
``ipaddress.IPv6Address.is_private``).
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

# Fly.io's 6PN private range. ``ipaddress.IPv6Address.is_private`` does NOT
# cover RFC 4193 ULAs, so leaving ``fdaa::/16`` reachable on Fly deployments
# lets an authenticated user pivot to neighbouring apps.
FLY_IO_ULA = ipaddress.ip_network("fdaa::/16")

_BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "169.254.169.254",
    }
)

_BLOCKED_DOMAIN_SUFFIXES = (".local", ".internal", ".corp", ".lan")


@dataclass
class UrlDecision:
    """Outcome of an outbound URL check."""

    safe: bool
    reason: str = ""


def is_ip_safe(addr: str) -> bool:
    """Return True if ``addr`` is a safe outbound destination.

    Rejects: private / loopback / link-local / reserved / multicast /
    IPv6-mapped IPv4 (``::ffff:x.x.x.x``) of private-range IPs, and the
    Fly.io 6PN ULA range.
    """
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    # Collapse IPv6-mapped IPv4 (``::ffff:127.0.0.1``) to its v4 form so
    # the private-range check applies.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        return False
    if ip.is_multicast or ip.is_unspecified:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip in FLY_IO_ULA:
        return False
    return True


def _resolve_and_check(hostname: str) -> tuple[bool, str]:
    """Resolve ``hostname`` and verify every A/AAAA result is safe.

    Defends against DNS rebinding: an attacker registers a hostname that
    resolves to a public IP on the first query and a private IP on the
    second. Iterating every ``addrinfo`` result means a single private
    answer blocks the whole URL.
    """
    try:
        addrinfos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        return False, f"DNS resolution failed for {hostname}: {e}"
    except Exception as e:  # pragma: no cover -- defensive
        return False, f"DNS resolution error for {hostname}: {e}"

    if not addrinfos:
        return False, f"No DNS results for {hostname}"

    for _family, _type, _proto, _canonname, sockaddr in addrinfos:
        # sockaddr[0] is typed as ``str | int`` by typeshed (AF_INET /
        # AF_INET6 returns str; AF_UNIX / AF_PACKET returns int). We
        # explicitly requested AF_UNSPEC + SOCK_STREAM above which only
        # yields str, but cast defensively so mypy sees it.
        ip_str = str(sockaddr[0])
        if not is_ip_safe(ip_str):
            return False, (f"Hostname {hostname} resolves to private/reserved IP {ip_str}")
    return True, ""


def validate_outbound_url(url: str) -> UrlDecision:
    """Return a safe/blocked decision for an outbound URL.

    Blocks: non-http(s) schemes, missing hostname, known internal names
    (``localhost``, IMDS, ``*.internal``/``.corp``/``.lan``/``.local``),
    private / loopback / link-local / reserved IPs, and hostnames whose
    DNS resolution contains any private IP (rebinding defence).
    """
    if not url:
        return UrlDecision(safe=False, reason="URL is required")
    try:
        parsed = urlparse(url)
    except Exception:
        return UrlDecision(safe=False, reason="Invalid URL format")
    if parsed.scheme not in ("http", "https"):
        return UrlDecision(safe=False, reason=f"Invalid URL scheme: {parsed.scheme}")
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return UrlDecision(safe=False, reason="URL has no hostname")
    if hostname in _BLOCKED_HOSTNAMES:
        return UrlDecision(safe=False, reason=f"Blocked internal hostname: {hostname}")
    if hostname.endswith(_BLOCKED_DOMAIN_SUFFIXES):
        return UrlDecision(safe=False, reason=f"Blocked internal domain: {hostname}")
    # Literal IP in the hostname slot bypasses DNS -- check directly.
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        # Not an IP literal -- continue to DNS resolution.
        ok, err = _resolve_and_check(hostname)
        return UrlDecision(safe=ok, reason=err)
    if not is_ip_safe(hostname):
        return UrlDecision(safe=False, reason=f"Blocked private/reserved IP: {hostname}")
    return UrlDecision(safe=True)
