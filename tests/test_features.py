from cyberheal_detect.features import (
    entropy_change,
    extract_features,
)


def test_extract_features_counts_supported_events() -> None:
    events = [
        {"event_type": "modified", "hash_changed": True},
        {"event_type": "renamed"},
        {"event_type": "auth_failure"},
        {"event_type": "privilege_change"},
        {"event_type": "admin_api", "abnormal": True},
    ]
    features = extract_features(events, before=b"\0" * 8, after=bytes(range(8)))
    assert features["modification_frequency"] == 1
    assert features["rename_frequency"] == 1
    assert features["hash_change_count"] == 1
    assert features["failed_auth_count"] == 1
    assert features["privilege_change_count"] == 1
    assert features["abnormal_admin_api_count"] == 1
    assert features["entropy_change"] == entropy_change(b"\0" * 8, bytes(range(8)))


def test_empty_entropy_is_zero() -> None:
    assert entropy_change(b"", b"") == 0.0
