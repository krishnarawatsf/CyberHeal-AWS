"""Read-only hashing of an explicitly approved, local sample-data directory."""

import hashlib
from pathlib import Path


def collect_sha256(root: Path, relative_files: tuple[str, ...]) -> dict[str, str]:
    """Only read files strictly inside `root`; refuse symlinks and traversal.

    Run this on a dedicated isolated verification VM, not on production volumes.
    The expected baseline must be captured and preserved before the simulation.
    """
    root = root.resolve(strict=True)
    if not root.is_dir() or not relative_files:
        raise ValueError("nonempty sample directory and file list required")
    hashes: dict[str, str] = {}
    for relative in relative_files:
        rel = Path(relative)
        if rel.is_absolute() or ".." in rel.parts or relative in hashes:
            raise ValueError("invalid or duplicate relative path")
        candidate = root / rel
        if any(p.is_symlink() for p in (candidate, *candidate.parents) if p != root):
            raise ValueError("symlink paths are not permitted")
        resolved = candidate.resolve(strict=True)
        if not resolved.is_relative_to(root) or not resolved.is_file():
            raise ValueError("file outside approved sample directory")
        digest = hashlib.sha256()
        with resolved.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        hashes[relative] = digest.hexdigest()
    return hashes


def collect_tree_sha256(
    root: Path, *, max_files: int = 500, max_total_bytes: int = 256 * 1024 * 1024
) -> dict[str, str]:
    """Hash *all* files under a trusted sandbox directory.

    Unlike `collect_sha256`, which hashes named files, this rejects extra
    unexpected files at verification time. Symlinks are rejected rather than
    followed, and limits prevent a compromised clone exhausting the verifier.
    Keep the mount read-only and run this as an unprivileged verifier process.
    """
    root = Path(root)
    if root.is_symlink():
        raise ValueError("sample-data root cannot be a symlink")
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("sample-data root must be an existing directory")
    entries: list[str] = []
    bytes_total = 0
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("symlink found in sample-data tree")
        if not path.is_file() and not path.is_dir():
            raise ValueError("special file found in sample-data tree")
        if path.is_file():
            bytes_total += path.stat().st_size
            if bytes_total > max_total_bytes:
                raise ValueError("sample-data exceeds maximum scan size")
            entries.append(path.relative_to(root).as_posix())
            if len(entries) > max_files:
                raise ValueError("sample-data contains too many files")
    if not entries:
        raise ValueError("sample-data tree contains no files")
    return collect_sha256(root, tuple(sorted(entries)))
