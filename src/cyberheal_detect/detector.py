"""Deterministic scikit-learn anomaly detector and threshold evaluation."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import f1_score, precision_score, recall_score

from .features import FEATURE_NAMES


@dataclass(frozen=True)
class Evaluation:
    """Binary classification metrics for a labelled simulation set."""

    precision: float
    recall: float
    f1: float


class AnomalyDetector:
    """Isolation Forest detector with a configurable score threshold."""

    def __init__(
        self,
        *,
        contamination: float = 0.1,
        random_state: int = 42,
        threshold_quantile: float = 0.95,
        minimum_confidence: float = 0.5,
    ) -> None:
        self.model = IsolationForest(
            contamination=contamination,
            random_state=random_state,
        )
        self.threshold_quantile = threshold_quantile
        self.minimum_confidence = minimum_confidence
        self.threshold: float | None = None

    def fit(self, normal_samples: list[dict[str, float]]) -> None:
        """Fit on known-normal feature vectors and tune the anomaly threshold."""
        matrix = self._matrix(normal_samples)
        self.model.fit(matrix)
        scores = -self.model.score_samples(matrix)
        self.threshold = float(np.quantile(scores, self.threshold_quantile))

    def predict(self, sample: dict[str, float]) -> tuple[bool, float]:
        """Return anomaly status and a bounded confidence score."""
        if self.threshold is None:
            raise RuntimeError("detector must be fitted before prediction")
        score = float(-self.model.score_samples(self._matrix([sample]))[0])
        confidence = min(1.0, max(0.0, score / max(self.threshold, 1e-12)))
        return score >= self.threshold, confidence

    def evaluate(
        self,
        samples: list[dict[str, float]],
        labels: list[int],
    ) -> Evaluation:
        """Evaluate predictions and report precision, recall, and F1."""
        if len(samples) != len(labels):
            raise ValueError("samples and labels must have equal lengths")
        predictions = [int(self.predict(sample)[0]) for sample in samples]
        return Evaluation(
            precision=float(precision_score(labels, predictions, zero_division=0)),
            recall=float(recall_score(labels, predictions, zero_division=0)),
            f1=float(f1_score(labels, predictions, zero_division=0)),
        )

    def save(self, path: Path) -> None:
        """Persist the fitted detector."""
        if self.threshold is None:
            raise RuntimeError("cannot save an unfitted detector")
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)

    @staticmethod
    def load(path: Path) -> "AnomalyDetector":
        """Load a persisted detector."""
        detector = joblib.load(path)
        if not isinstance(detector, AnomalyDetector):
            raise TypeError("model file does not contain an AnomalyDetector")
        return detector

    @staticmethod
    def _matrix(samples: list[dict[str, float]]) -> np.ndarray[Any, Any]:
        return np.asarray(
            [
                [float(sample.get(name, 0.0)) for name in FEATURE_NAMES]
                for sample in samples
            ],
            dtype=float,
        )
