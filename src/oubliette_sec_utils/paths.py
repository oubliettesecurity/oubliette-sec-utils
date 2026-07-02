"""Path-scope utilities.

The guiding invariant: "path P is inside base B" is only safe when both
sides are resolved through ``realpath`` AND the comparison uses
``commonpath`` (not ``startswith``). ``startswith`` is broken by
prefix-sibling directories (``/evidence-stolen`` vs ``/evidence``) and
``normpath`` alone does not collapse symlinks.
"""

from __future__ import annotations

import os


def safe_realpath(path: str) -> str | None:
    """Resolve ``path`` through ``realpath``, or ``None`` on failure.

    ``os.path.realpath`` raises on Windows for certain malformed inputs and
    on all platforms for some non-existent / malicious symlink chains (and
    ``ValueError`` for embedded NULs). We deliberately do NOT fall back to a
    lexical ``normpath``: a lexical string cannot honour the symlink
    resolution that containment checks depend on, so silently returning one
    degrades the guarantee (an attacker-influenced broken symlink chain that
    resolves outside base would still compare as inside it). Fail closed by
    returning ``None`` so callers can treat resolution failure as
    "not resolvable" rather than comparing unresolved paths.
    """
    try:
        return os.path.normpath(os.path.realpath(path))
    except (OSError, ValueError):
        return None


def contained_in(candidate: str, base: str) -> bool:
    """Return True iff ``candidate`` is equal to or nested inside ``base``.

    Resolves both sides through :func:`safe_realpath` first so POSIX-style
    inputs, Windows drive-letter paths, and symlink chains all normalise to
    the same canonical form before comparison. Uses ``os.path.commonpath``
    so prefix-sibling directories (e.g. ``/evidence-stolen`` vs
    ``/evidence``) are correctly rejected -- unlike ``startswith``.

    Fails closed: if either side cannot be resolved through ``realpath``
    (:func:`safe_realpath` returns ``None``), containment is rejected rather
    than comparing unresolved, symlink-unaware paths.
    """
    resolved_candidate = safe_realpath(candidate)
    resolved_base = safe_realpath(base)
    if resolved_candidate is None or resolved_base is None:
        # Resolution failure -- cannot prove containment, so deny.
        return False
    try:
        return os.path.commonpath([resolved_candidate, resolved_base]) == resolved_base
    except ValueError:
        # commonpath raises on mixed drives or empty paths -- treat as out-of-scope.
        return False
