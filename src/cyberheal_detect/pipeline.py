"""Orchestration from telemetry features to validated threat alerts."""

from typing import Literal

from .detector import AnomalyDetector
from .models import Resource, ThreatAlert


def create_alert(
    detector: AnomalyDetector,
    *,
    features: dict[str, float],
    resource: Resource,
    alert_type: Literal["ransomware_like", "credential_anomaly"],
    evidence_refs: list[str],
) -> ThreatAlert | None:
    """Create an alert when the detector confidence exceeds its configured floor."""
    anomaly, confidence = detector.predict(features)
    if not anomaly or confidence < detector.minimum_confidence:
        return None
    return ThreatAlert(
        resource=resource,
        alert_type=alert_type,
        confidence=confidence,
        features=features,
        evidence_refs=evidence_refs,
    )
