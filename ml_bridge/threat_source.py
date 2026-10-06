"""Implementation of the ML → quantum threat-score adapter (see package doc).

Stdlib-only at import time; joblib/pandas are imported lazily inside
functions so that environments without ML dependencies can still import
this module (and the quantum package never needs it anyway).
"""

from __future__ import annotations

import importlib.util
import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_ML_REPO = Path.home() / "Quantum-Cryptography"
# train_classifier.py writes --output ml/model.joblib by default (cwd-relative).
DEFAULT_MODEL_CANDIDATES = (
    DEFAULT_ML_REPO / "ml" / "model.joblib",
    DEFAULT_ML_REPO / "model.joblib",
)
PREDICT_SCRIPT = DEFAULT_ML_REPO / "predict.py"
_IGNORED_FEATURES = ("label", "difficulty")


class ModelUnavailableError(RuntimeError):
    """No loadable trained model artifact — never fabricate a substitute."""


def _predict_columns() -> list[str]:
    """Read COLUMNS from predict.py (single source of truth, not copied)."""
    if not PREDICT_SCRIPT.exists():
        raise ModelUnavailableError(
            f"predict.py not found at {PREDICT_SCRIPT}; cannot determine "
            "NSL-KDD feature columns")
    spec = importlib.util.spec_from_file_location(
        "_ml_bridge_nslkdd_predict", PREDICT_SCRIPT)
    if spec is None or spec.loader is None:
        raise ModelUnavailableError(f"cannot import {PREDICT_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)  # main() is __main__-guarded
    except Exception as exc:  # missing joblib/pandas, syntax, ...
        raise ModelUnavailableError(
            f"cannot import {PREDICT_SCRIPT}: {exc}") from exc
    return list(module.COLUMNS)


def nsl_kdd_feature_columns() -> list[str]:
    """The 41 NSL-KDD feature columns the trained pipeline expects."""
    return [c for c in _predict_columns()
            if c not in _IGNORED_FEATURES]


def load_threat_model(model_path: str | Path | None = None):
    """Load the trained NSL-KDD pipeline artifact, or raise loudly.

    Returns ``(model, path)``. Raises ``ModelUnavailableError`` when no
    artifact exists — this adapter NEVER fabricates model outputs.
    """
    import joblib  # lazy: ML dependency, not needed to import this module
    candidates = ([Path(model_path)] if model_path
                  else list(DEFAULT_MODEL_CANDIDATES))
    for path in candidates:
        if path.exists():
            return joblib.load(path), path
    raise ModelUnavailableError(
        "no trained NSL-KDD model artifact found (looked for: "
        + ", ".join(str(c) for c in candidates)
        + "). Train one with: python train_classifier.py --train "
        "<NSL-KDD train csv> --test <NSL-KDD test csv> "
        "[--output ml/model.joblib]")


@dataclass(frozen=True)
class SyntheticThreatScore:
    """A SYNTHETIC demo value — explicitly NOT an ML model prediction."""

    value: float
    source: str = "SYNTHETIC-DEMO (not an NSL-KDD model output)"

    def __post_init__(self) -> None:
        if not 0.0 <= self.value <= 1.0:
            raise ValueError("threat score must be in [0, 1]")

    @property
    def score(self) -> float:
        return self.value


class NSLKDDThreatScorer:
    """Scores one NSL-KDD feature record with the trained pipeline.

    ``score_record`` returns ``model.predict_proba(X)[:, 1]`` — the ML
    threat score (uncalibrated, NOT a probability of attack).
    """

    def __init__(self, model, model_path: str | Path,
                 feature_columns: list[str] | None = None) -> None:
        self._model = model
        self.model_path = Path(model_path)
        self.feature_columns = list(
            feature_columns if feature_columns is not None
            else nsl_kdd_feature_columns())

    @property
    def threat_score_source(self) -> str:
        return f"NSL-KDD model artifact {self.model_path}"

    def score_record(self, record: dict) -> float:
        missing = [c for c in self.feature_columns if c not in record]
        if missing:
            raise ValueError(
                f"record missing {len(missing)} required NSL-KDD "
                f"features, e.g. {missing[:5]}")
        import pandas as pd  # lazy ML dependency
        # Column order comes from predict.py's COLUMNS — preprocessing
        # (one-hot + numeric passthrough) happens inside the pipeline.
        frame = pd.DataFrame(
            [{c: record[c] for c in self.feature_columns}])
        score = float(self._model.predict_proba(frame)[0, 1])
        if not 0.0 <= score <= 1.0:  # defensive; predict_proba contract
            raise ValueError(f"model returned out-of-range score {score}")
        return score


class DatasetUnavailableError(ModelUnavailableError):
    """Genuine NSL-KDD data file not found — never substitute other data."""


def find_nsl_kdd_data(name: str = "KDDTest+.txt") -> "Path | None":
    """Locate a genuine NSL-KDD data file. Returns ``None`` when absent.

    Search order: ``$NSL_KDD_DATA/<name>``, the ML repo's ``data/`` dir
    (where ``KDDTrain+.txt`` / ``KDDTest+.txt`` live), the ML repo root,
    then this project's ``data/`` dir.
    """
    env = os.environ.get("NSL_KDD_DATA", "")
    name_env = ""
    if name.startswith("KDDTest"):
        name_env = os.environ.get("NSL_KDD_TEST", "")
    elif name.startswith("KDDTrain"):
        name_env = os.environ.get("NSL_KDD_TRAIN", "")
    candidates = []
    for e in (env, name_env):
        if e:
            candidates.append(Path(e) / name)
    candidates += [
        DEFAULT_ML_REPO / "data" / name,
        DEFAULT_ML_REPO / name,
        Path(__file__).resolve().parent.parent / "data" / name,
    ]
    return next((c for c in candidates if c.is_file()), None)


def load_nsl_kdd_records(path: str | Path | None = None,
                         limit: int | None = None) -> list[dict]:
    """Read genuine NSL-KDD rows exactly as ``predict.py`` does.

    Uses ``pd.read_csv(header=None, names=COLUMNS)`` with the COLUMNS
    imported from ``predict.py`` (single source of truth) — NO
    preprocessing is duplicated here; feature transformation lives
    inside the saved sklearn Pipeline. Each returned dict has all 43
    fields (41 features + ``label`` + ``difficulty``); scoring via
    ``NSLKDDThreatScorer.score_record`` selects the 41 features
    automatically. Raises ``DatasetUnavailableError`` when the file
    does not exist.
    """
    if path is None:
        found = find_nsl_kdd_data()
        if found is None:
            raise DatasetUnavailableError(
                "genuine NSL-KDD data not found (looked for KDDTest+.txt in "
                "$NSL_KDD_DATA, ~/Quantum-Cryptography/data/, "
                "~/Quantum-Cryptography/, ./data/)")
        path = found
    path = Path(path)
    if not path.is_file():
        raise DatasetUnavailableError(f"NSL-KDD data file not found: {path}")
    import pandas as pd  # lazy ML dependency (same reader as predict.py)
    columns = _predict_columns()
    frame = pd.read_csv(path, header=None, names=columns, nrows=limit)
    return frame.to_dict(orient="records")


def try_load_scorer(model_path: str | Path | None = None
                    ) -> "NSLKDDThreatScorer | None":
    """Real scorer when artifact + ML deps exist, else ``None``.

    Never raises: absence of ML capability must not break callers
    (the quantum side then runs QKD-only with threat_score=None).
    """
    try:
        model, path = load_threat_model(model_path)
        return NSLKDDThreatScorer(model, path)
    except Exception:  # ModelUnavailableError, missing joblib, ...
        return None
