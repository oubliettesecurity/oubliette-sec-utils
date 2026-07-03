"""Tests for path-scope helpers."""

import os

import pytest

from oubliette_sec_utils.paths import contained_in, safe_realpath


class TestContainedIn:
    def test_exact_match(self, tmp_path):
        assert contained_in(str(tmp_path), str(tmp_path)) is True

    def test_child_is_contained(self, tmp_path):
        child = tmp_path / "a" / "b"
        assert contained_in(str(child), str(tmp_path)) is True

    def test_sibling_prefix_rejected(self, tmp_path):
        base = tmp_path / "evidence"
        sibling = tmp_path / "evidence-stolen" / "file"
        base.mkdir()
        sibling.parent.mkdir()
        assert contained_in(str(sibling), str(base)) is False

    def test_unrelated_path_rejected(self, tmp_path):
        other = tmp_path.parent / "unrelated"
        assert contained_in(str(other), str(tmp_path)) is False

    def test_resolution_failure_is_not_contained(self, tmp_path, monkeypatch):
        # A candidate whose ``realpath`` resolution fails must FAIL CLOSED,
        # even though it is lexically nested inside base. The old normpath
        # fallback compared the unresolved (symlink-unaware) path and could
        # return True. ``realpath`` raising is platform-dependent (broken
        # symlink chains, malformed Windows inputs, embedded NULs), so we
        # force the failure deterministically.
        child = os.path.join(str(tmp_path), "child", "evil")
        real = os.path.realpath

        def flaky_realpath(p, *a, **k):
            if "evil" in str(p):
                raise OSError("simulated broken symlink chain")
            return real(p, *a, **k)

        monkeypatch.setattr(os.path, "realpath", flaky_realpath)
        assert contained_in(child, str(tmp_path)) is False

    def test_resolution_failure_base_is_not_contained(self, tmp_path, monkeypatch):
        # Resolution failure on the *base* side must also fail closed.
        real = os.path.realpath

        def flaky_realpath(p, *a, **k):
            if str(p) == str(tmp_path):
                raise ValueError("simulated malformed base")
            return real(p, *a, **k)

        monkeypatch.setattr(os.path, "realpath", flaky_realpath)
        child = os.path.join(str(tmp_path), "child")
        assert contained_in(child, str(tmp_path)) is False

    def test_symlink_escaping_base_rejected(self, tmp_path):
        base = tmp_path / "base"
        base.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        secret = outside / "secret.txt"
        secret.write_text("x")
        link = base / "escape"
        try:
            link.symlink_to(secret)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks not supported / not permitted on this platform")
        # The symlink lexically lives inside base but resolves outside it.
        assert contained_in(str(link), str(base)) is False


class TestSafeRealpath:
    def test_basic_normalise(self, tmp_path):
        path = str(tmp_path / "a" / ".." / "b")
        resolved = safe_realpath(path)
        assert resolved == os.path.normpath(os.path.realpath(path))

    def test_nonexistent_returns_normpath(self, tmp_path):
        path = str(tmp_path / "does" / "not" / "exist")
        # Should not raise.
        result = safe_realpath(path)
        assert isinstance(result, str)
        assert result  # non-empty

    def test_resolution_failure_returns_sentinel(self, tmp_path, monkeypatch):
        # When ``realpath`` raises, ``safe_realpath`` must return the failure
        # sentinel (None) rather than a lexical normpath fallback.
        def boom(p, *a, **k):
            raise OSError("simulated resolution failure")

        monkeypatch.setattr(os.path, "realpath", boom)
        assert safe_realpath(str(tmp_path)) is None
