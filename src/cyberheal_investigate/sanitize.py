"""Only numeric detector features and opaque event pointers cross the boundary."""

import re

from cyberheal_detect.features import FEATURE_NAMES

FEATURES = frozenset(FEATURE_NAMES) | {"rename_rate", "entropy_delta"}
REFERENCE = re.compile(r"^(?:event|simulation):[A-Za-z0-9_-]{1,80}$")
FORBIDDEN = ("password", "passwd", "secret", "token", "api_key", "credential", "akia")


def sanitize(alert):
    result = alert.model_dump(mode="json")
    result["features"] = {k: v for k, v in alert.features.items() if k in FEATURES}
    result["evidence_refs"] = [
        ref
        for ref in alert.evidence_refs
        if REFERENCE.fullmatch(ref) and not any(s in ref.lower() for s in FORBIDDEN)
    ]
    return result


def prompt_data(alert):
    # Never send free-form evidence, identifiers, or operator credentials to the model.
    return {
        key: alert[key] for key in ("timestamp", "alert_type", "confidence", "features")
    }
