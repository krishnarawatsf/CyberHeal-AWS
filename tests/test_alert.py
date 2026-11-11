import pytest
from pydantic import ValidationError

from cyberheal_detect.models import Resource, ThreatAlert


def test_alert_contract() -> None:
    alert = ThreatAlert(
        resource=Resource(vm_id="vm-1", volume_id="volume-1"),
        alert_type="ransomware_like",
        confidence=0.9,
        features={"rename_frequency": 4.0},
        evidence_refs=["wazuh:event:123"],
    )
    payload = alert.model_dump()
    assert payload["schema_version"] == "1.0"
    assert payload["resource"]["vm_id"] == "vm-1"


def test_alert_rejects_secret_evidence() -> None:
    with pytest.raises(ValidationError):
        ThreatAlert(
            resource=Resource(vm_id="vm-1", volume_id="volume-1"),
            alert_type="credential_anomaly",
            confidence=0.9,
            evidence_refs=["password:raw"],
        )
