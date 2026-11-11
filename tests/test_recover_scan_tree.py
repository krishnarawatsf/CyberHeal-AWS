"""Read-only full-tree scanner rejects extra files and unsafe links."""

import pytest

from cyberheal_recover.scan import collect_tree_sha256


def test_tree_hashing_is_deterministic(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "one.txt").write_text("known good", encoding="utf8")
    first = collect_tree_sha256(tmp_path)
    assert list(first) == ["data/one.txt"]
    assert first == collect_tree_sha256(tmp_path)
    (tmp_path / "data" / "extra.txt").write_text("unexpected", encoding="utf8")
    assert set(collect_tree_sha256(tmp_path)) == {"data/one.txt", "data/extra.txt"}
    assert first != collect_tree_sha256(tmp_path)


def test_tree_rejects_special_links(tmp_path):
    (tmp_path / "sample.txt").write_text("sample", encoding="utf8")
    (tmp_path / "shortcut").symlink_to(tmp_path / "sample.txt")
    with pytest.raises(ValueError, match="symlink"):
        collect_tree_sha256(tmp_path)


def test_tree_rejects_large_data(tmp_path):
    (tmp_path / "sample.txt").write_text("a" * 30, encoding="utf8")
    with pytest.raises(ValueError, match="maximum"):
        collect_tree_sha256(tmp_path, max_total_bytes=10)


def test_tree_rejects_empty_directory(tmp_path):
    with pytest.raises(ValueError, match="no files"):
        collect_tree_sha256(tmp_path)


def test_tree_rejects_too_many_files(tmp_path):
    (tmp_path / "1").write_text("a")
    (tmp_path / "2").write_text("b")
    with pytest.raises(ValueError, match="too many"):
        collect_tree_sha256(tmp_path, max_files=1)
