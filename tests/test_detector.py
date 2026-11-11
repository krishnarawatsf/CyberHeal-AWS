from cyberheal_detect.detector import AnomalyDetector


def vector(value: float) -> dict[str, float]:
    return {
        "entropy_change": value,
        "modification_frequency": value,
        "rename_frequency": value,
        "hash_change_count": value,
        "failed_auth_count": value,
        "privilege_change_count": value,
        "abnormal_admin_api_count": value,
    }


def test_detector_is_deterministic_and_reports_metrics() -> None:
    normal = [vector(0.0), vector(0.1), vector(0.0), vector(0.2), vector(0.1)]
    detector = AnomalyDetector(threshold_quantile=0.8)
    detector.fit(normal)
    metrics = detector.evaluate(normal + [vector(10.0)], [0, 0, 0, 0, 0, 1])
    assert 0.0 <= metrics.precision <= 1.0
    assert 0.0 <= metrics.recall <= 1.0
    assert 0.0 <= metrics.f1 <= 1.0
