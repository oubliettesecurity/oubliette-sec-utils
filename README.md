# oubliette-sec-utils

Shared security helpers for the Oubliette product family (Shield, Sentinel,
Dungeon, Trap, sift-guard).

Extracted from duplicated inline code that was flagged in the 2026-04-22
red-team audit as the source of recurring cross-repo security fixes:

- **Path scope** — `contained_in()` + `safe_realpath()` replace the broken
  `startswith` / `normpath` pattern. A sibling directory like
  `/evidence-stolen` no longer passes the scope check for `/evidence`.
- **Argument injection** — `validate_argument()` / `validate_allowlist()`
  reject strings that start with `-`, contain shell metacharacters, or
  aren't in a whitelisted set. `shell=False` does NOT protect against
  argv-level injection.
- **SSRF** — `is_ip_safe()` / `validate_outbound_url()` reject private,
  loopback, link-local, reserved, multicast, IPv6-mapped IPv4, and the
  Fly.io 6PN ULA range (`fdaa::/16`), which `ipaddress.is_private`
  misses. URL validation performs DNS resolution and checks every
  resolved IP (rebinding defence).

## Install

```bash
pip install oubliette-sec-utils
```

## Usage

```python
from oubliette_sec_utils import (
    contained_in, safe_realpath,
    validate_argument, validate_allowlist,
    is_ip_safe, validate_outbound_url,
)

# Path scope
assert contained_in("/evidence/disk.E01", "/evidence") is True
assert contained_in("/evidence-stolen/disk.E01", "/evidence") is False

# Argv injection -- validate_argument catches flag-prefixed strings
assert validate_argument("--plugins /tmp/evil.pl", allow_spaces=True).blocked is True

# validate_argument does NOT catch flags embedded mid-string (by design;
# a single argv entry is passed whole to the callee). For finite-set
# parameters like registry hive names, use validate_allowlist:
assert validate_allowlist(
    "SYSTEM --plugins /tmp/evil.pl", ["SYSTEM", "SOFTWARE"]
).blocked is True

# SSRF
d = validate_outbound_url("http://169.254.169.254/latest/meta-data/")
assert d.safe is False
```

## Scope and non-goals

This package is a **helper library**, not a framework. It does not know
about Flask, FastAPI, MCP, or any specific subsystem — callers wrap these
helpers into their own request pipelines. That separation is deliberate:
Shield, Sentinel, Dungeon, Trap, and sift-guard all have different
framework shapes, but they share the same underlying validation needs.

## License

Apache 2.0
