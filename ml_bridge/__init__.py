"""Thin ML → quantum adapter: turns an NSL-KDD model artifact into a float.

REAL ML integration boundary:

    ~/Quantum-Cryptography/ (train_classifier.py / predict.py — UNTOUCHED)
            │  joblib pipeline artifact (default: ml/model.joblib)
            ▼
    ml_bridge.NSLKDDThreatScorer.score_record(record) -> float
            │  plain float | None — the ONLY thing quantum/ sees
            ▼
    quantum SecurityController.evaluate(..., threat_score=...)
            └── risk_fusion.combined_risk(threat_score, qber)

Semantics: the float is ``model.predict_proba(X)[:, 1]`` — the RandomForest
pipeline's *uncalibrated* positive-class score. Call it the **ML threat
score**, never a calibrated probability of attack.

This package lives OUTSIDE the quantum/ package on purpose: quantum has no
ML dependency and stays fully usable with ``threat_score=None`` when no
model exists. Preprocessing is NOT duplicated here — it lives inside the
saved sklearn Pipeline; the adapter only loads the artifact, orders feature
columns exactly as ``predict.py`` does (single source of truth: its
``COLUMNS``), and returns one float.

Artifact status: a trained NSL-KDD pipeline artifact and the genuine
KDDTrain+.txt / KDDTest+.txt data now exist in ~/Quantum-Cryptography
(verified Phase 5: ``ml/model.joblib``). ``load_threat_model()`` still
raises ``ModelUnavailableError`` if the artifact disappears, and
``try_load_scorer()`` returns ``None`` — callers then fall back to
clearly labeled ``SyntheticThreatScore`` demo inputs or
``threat_score=None``. Genuine records are read via
``load_nsl_kdd_records`` (same reader and COLUMNS as ``predict.py``).
"""

from ml_bridge.threat_source import (
    DatasetUnavailableError,
    ModelUnavailableError,
    NSLKDDThreatScorer,
    SyntheticThreatScore,
    find_nsl_kdd_data,
    load_nsl_kdd_records,
    load_threat_model,
    nsl_kdd_feature_columns,
    try_load_scorer,
)

__all__ = [
    "DatasetUnavailableError",
    "ModelUnavailableError",
    "NSLKDDThreatScorer",
    "SyntheticThreatScore",
    "find_nsl_kdd_data",
    "load_nsl_kdd_records",
    "load_threat_model",
    "nsl_kdd_feature_columns",
    "try_load_scorer",
]
