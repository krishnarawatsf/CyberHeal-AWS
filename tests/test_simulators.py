from pathlib import Path

import pytest

from cyberheal_detect.simulators import (
    simulate_credential_anomaly,
    simulate_file_activity,
)


def test_file_simulator_is_reversible_and_scoped(tmp_path: Path) -> None:
    sample = tmp_path / "sample-data"
    sample.mkdir()
    source = sample / "safe.txt"
    original = b"safe sample data"
    source.write_bytes(original)
    events = simulate_file_activity(sample)
    transformed = sample / "safe.txt.cyberheal-test"
    assert transformed.read_bytes() != original
    assert len(events) == 2
    transformed.write_bytes(bytes(byte ^ 0xAA for byte in transformed.read_bytes()))
    assert transformed.read_bytes() == original


def test_file_simulator_rejects_filesystem_root(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        simulate_file_activity(Path("/"))


def test_credential_simulator_is_synthetic() -> None:
    events = simulate_credential_anomaly(failed_attempts=3)
    assert sum(event["event_type"] == "auth_failure" for event in events) == 3
    assert events[-1]["event_type"] == "privilege_change"
    assert all("password" not in event for event in events)
