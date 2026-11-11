"""Safe, reversible anomaly simulators for the designated sample-data root."""

from pathlib import Path
from secrets import token_hex
from typing import Any


def _safe_root(root: Path) -> Path:
    """Resolve and validate a simulator root."""
    resolved = root.expanduser().resolve()
    if resolved == Path(resolved.anchor):
        raise ValueError("simulator root cannot be a filesystem root")
    return resolved


def _guard_path(root: Path, path: Path) -> Path:
    """Reject paths outside the designated simulator root."""
    safe_root = _safe_root(root)
    resolved = path.expanduser().resolve()
    if safe_root not in (resolved, *resolved.parents):
        raise ValueError("simulator path is outside the designated sample-data root")
    return resolved


def simulate_file_activity(
    root: Path, *, suffix: str = ".cyberheal-test"
) -> list[dict[str, Any]]:
    """Apply a reversible XOR transformation and rename files below ``root``."""
    safe_root = _safe_root(root)
    if not safe_root.exists() or not safe_root.is_dir():
        raise ValueError("sample-data root must be an existing directory")
    events: list[dict[str, Any]] = []
    for source in sorted(safe_root.rglob("*")):
        if not source.is_file() or source.name.endswith(suffix):
            continue
        safe_source = _guard_path(safe_root, source)
        data = safe_source.read_bytes()
        safe_source.write_bytes(bytes(byte ^ 0xAA for byte in data))
        target = _guard_path(
            safe_root, safe_source.with_name(safe_source.name + suffix)
        )
        safe_source.rename(target)
        events.extend(
            [
                {
                    "event_type": "modified",
                    "path": str(safe_source.relative_to(safe_root)),
                },
                {"event_type": "renamed", "path": str(target.relative_to(safe_root))},
            ]
        )
    return events


def simulate_credential_anomaly(
    *,
    username: str = "cyberheal-demo",
    failed_attempts: int = 5,
) -> list[dict[str, Any]]:
    """Create synthetic failed-login and privilege-change telemetry only."""
    if not username or failed_attempts < 1:
        raise ValueError("username and a positive failed-attempt count are required")
    event_id = token_hex(8)
    return [
        {
            "event_type": "auth_failure",
            "username": username,
            "attempt_id": f"{event_id}-{index}",
        }
        for index in range(failed_attempts)
    ] + [
        {
            "event_type": "privilege_change",
            "username": username,
            "change": "demo-role-added",
        }
    ]
