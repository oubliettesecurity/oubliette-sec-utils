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
