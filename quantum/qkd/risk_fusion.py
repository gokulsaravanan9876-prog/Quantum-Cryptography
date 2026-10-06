"""Combined Risk Score fusion layer (project-defined display heuristic).

Combines two deliberately separate security signals for dashboard /
visualization purposes only:

1. ``threat_score`` — classical network-ML attack-likeness score in [0, 1],
   supplied by an external caller (the NSL-KDD model is NOT integrated in
   this prototype; nothing here computes ML scores).
2. ``qber`` — quantum bit error rate from the BB84 simulation (an error
   rate over the sifted block, NOT a probability).

What a Combined Risk Score IS:
    * A project-defined heuristic scalar in [0, 1] used for display.
    * Produced by MAX fusion: ``max(threat_score, qber_normalized)`` where
      ``qber_normalized = min(qber / QBER_REF, 1.0)``.
    * ``QBER_REF`` is derived from ``SecurityPolicy.monitor_threshold``
      (the project policy's MONITOR bound) — there is NO independent
      hard-coded 0.10 constant in this module.

What it is NOT (hard limitations):
    * NOT a probability of compromise. The ML score is an uncalibrated
      classifier score and QBER is an error rate; their max is not a
      posterior probability.
    * NOT a replacement for QBER, not a replacement for the raw
      threat_score, and not a replacement for ``SecurityController``.
      All three remain separately visible.
    * NOT a decision function. ACCEPT / MONITOR / REJECT come exclusively
      from ``SecurityController.evaluate``. The combined score never
      overrides QBER rejection, ``key_success`` failure, or
      ``endpoint_keys_match`` failure in the application layer.
    * NOT reconciliation, privacy amplification, or any QKD
      post-processing claim.

Only the MAX method is implemented. Weighted (alpha) and noisy-OR fusion
are documented future experimental alternatives and are intentionally NOT
present in this production/demo path.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from quantum.qkd.security import SecurityPolicy


class FusionMethod(Enum):
    """Fusion strategies. Only MAX is implemented (see module docstring)."""

    MAX = "MAX"


@dataclass(frozen=True)
class RiskFusionConfig:
    """Fusion configuration.

    ``qber_ref`` is always derived from a ``SecurityPolicy`` so the fusion
    scale tracks the project's documented MONITOR threshold instead of a
    magic constant.
    """

    policy: SecurityPolicy | None = None
    method: FusionMethod = FusionMethod.MAX

    @property
    def qber_ref(self) -> float:
        """QBER normalization reference (= policy monitor_threshold)."""
        ref = (self.policy or SecurityPolicy()).monitor_threshold
        if not ref > 0.0:
            raise ValueError(
                "QBER_REF (policy.monitor_threshold) must be > 0")
        return ref


def normalize_qber(
    qber: float | None,
    config: RiskFusionConfig | None = None,
) -> float | None:
    """Map raw QBER onto [0, 1] where 1.0 == policy MONITOR bound reached.

    ``qber_normalized = min(qber / QBER_REF, 1.0)`` with
    ``QBER_REF = config.qber_ref`` (derived from
    ``SecurityPolicy.monitor_threshold``). Monotone: higher QBER is never
    less alarming. Returns ``None`` when there is no quantum observation
    (``qber is None``).
    """
    if qber is None:
        return None
    if qber < 0.0:
        raise ValueError("qber must be >= 0")
    cfg = config or RiskFusionConfig()
    return min(qber / cfg.qber_ref, 1.0)


def combined_risk(
    qber: float | None,
    threat_score: float | None = None,
    config: RiskFusionConfig | None = None,
) -> float | None:
    """Compute the display-only Combined Risk Score (MAX fusion).

    ``combined_risk = max(threat_score, normalize_qber(qber))``.

    Heuristic status: project-defined visualization metric in [0, 1].
    NOT a probability of compromise and NOT used for any security
    decision — the ``SecurityController`` remains the sole authority for
    ACCEPT / MONITOR / REJECT.

    None handling:
        * ``qber is None`` -> ``None`` (no quantum observation; fusion is
          undefined even if a threat_score exists).
        * ``threat_score is None`` -> ``normalize_qber(qber)`` (QKD-only
          mode, backward compatible with all existing scenarios).
    Raises ValueError for ``threat_score`` outside [0, 1] or negative
    QBER, matching ``SecurityController`` validation.
    Raises NotImplementedError for any non-MAX method.
    """
    cfg = config or RiskFusionConfig()
    if cfg.method is not FusionMethod.MAX:
        raise NotImplementedError(
            "only MAX fusion is implemented; weighted/noisy-OR are future "
            "experimental alternatives (see module docstring)")
    if threat_score is not None and not 0.0 <= threat_score <= 1.0:
        raise ValueError("threat_score must be in [0, 1]")
    qber_normalized = normalize_qber(qber, cfg)
    if qber_normalized is None:
        return None
    if threat_score is None:
        return qber_normalized
    return max(threat_score, qber_normalized)
