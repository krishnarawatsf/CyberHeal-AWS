"""Pure feature extraction functions for telemetry events."""

from collections.abc import Iterable
from math import log2
from typing import Any


def shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy in bits per byte for ``data``."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    size = len(data)
    return -sum((count / size) * log2(count / size) for count in counts if count)


def entropy_change(before: bytes, after: bytes) -> float:
    """Return the absolute entropy increase between two byte sequences."""
    return max(0.0, shannon_entropy(after) - shannon_entropy(before))


def modification_frequency(events: Iterable[dict[str, Any]]) -> float:
    """Count file modification events per event record."""
    return float(sum(event.get("event_type") == "modified" for event in events))


def rename_frequency(events: Iterable[dict[str, Any]]) -> float:
    """Count file rename events per event record."""
    return float(sum(event.get("event_type") == "renamed" for event in events))


def hash_change_count(events: Iterable[dict[str, Any]]) -> float:
    """Count events where a file hash changed."""
    return float(sum(bool(event.get("hash_changed", False)) for event in events))


def failed_auth_count(events: Iterable[dict[str, Any]]) -> float:
    """Count failed authentication events."""
    return float(sum(event.get("event_type") == "auth_failure" for event in events))


def privilege_change_count(events: Iterable[dict[str, Any]]) -> float:
    """Count privilege or account changes."""
    change_types = {"privilege_change", "account_change"}
    return float(sum(event.get("event_type") in change_types for event in events))


def abnormal_admin_api_count(events: Iterable[dict[str, Any]]) -> float:
    """Count administrative actions marked abnormal by the telemetry source."""
    return float(
        sum(
            event.get("event_type") == "admin_api"
            and bool(event.get("abnormal", False))
            for event in events
        )
    )


FEATURE_NAMES = (
    "entropy_change",
    "modification_frequency",
    "rename_frequency",
    "hash_change_count",
    "failed_auth_count",
    "privilege_change_count",
    "abnormal_admin_api_count",
)


def extract_features(
    events: list[dict[str, Any]],
    *,
    before: bytes = b"",
    after: bytes = b"",
) -> dict[str, float]:
    """Extract the complete model feature vector from telemetry events."""
    return {
        "entropy_change": entropy_change(before, after),
        "modification_frequency": modification_frequency(events),
        "rename_frequency": rename_frequency(events),
        "hash_change_count": hash_change_count(events),
        "failed_auth_count": failed_auth_count(events),
        "privilege_change_count": privilege_change_count(events),
        "abnormal_admin_api_count": abnormal_admin_api_count(events),
    }
