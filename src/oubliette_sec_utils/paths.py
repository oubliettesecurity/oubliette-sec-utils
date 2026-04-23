"""Path-scope utilities.

The guiding invariant: "path P is inside base B" is only safe when both
sides are resolved through ``realpath`` AND the comparison uses
``commonpath`` (not ``startswith``). ``startswith`` is broken by
prefix-sibling directories (``/evidence-stolen`` vs ``/evidence``) and
``normpath`` alone does not collapse symlinks.
"""

from __future__ import annotations

import os


def safe_realpath(path: str) -> str:
    """Best-effort ``realpath`` with a ``normpath`` fallback.

    ``os.path.realpath`` raises on Windows for certain malformed inputs and
    on all platforms for some non-existent symlink chains. Fall back to
    ``normpath`` so the caller still gets a deterministic string to compare.
    """
    try:
        return os.path.normpath(os.path.realpath(path))
    except (OSError, ValueError):
        return os.path.normpath(path)


def contained_in(candidate: str, base: str) -> bool:
    """Return True iff ``candidate`` is equal to or nested inside ``base``.

    Resolves both sides through :func:`safe_realpath` first so POSIX-style
    inputs, Windows drive-letter paths, and symlink chains all normalise to
    the same canonical form before comparison. Uses ``os.path.commonpath``
    so prefix-sibling directories (e.g. ``/evidence-stolen`` vs
    ``/evidence``) are correctly rejected -- unlike ``startswith``.
    """
    candidate = safe_realpath(candidate)
    base = safe_realpath(base)
    try:
        return os.path.commonpath([candidate, base]) == base
    except ValueError:
        # commonpath raises on mixed drives or empty paths -- treat as out-of-scope.
        return False
