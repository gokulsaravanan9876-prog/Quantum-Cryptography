"""Security decision layer: ACCEPT / MONITOR / REJECT.

The controller maps QKD observations (QBER, channel conditions, optional
ML threat score) onto a project security decision. Thresholds below are an
*experimental project policy* for this hackathon prototype -- they are NOT
claimed to be universal QKD standards.

Prototype vs production (honesty note):
    Regenerating a key or applying these thresholds is NOT equivalent to
    production QKD post-processing (authenticated classical channel,
    information reconciliation, privacy amplification, key management,
    finite-key security analysis). A real deployment would require all of
    those; this module only gates prototype behaviour.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class SecurityDecision(Enum):
    ACCEPT = "ACCEPT"
    MONITOR = "MONITOR"
    REJECT = "REJECT"


@dataclass(frozen=True)
class SecurityPolicy:
    """Experimental project policy (NOT a universal QKD standard)."""

    accept_threshold: float = 0.03
    monitor_threshold: float = 0.10
    # Threat-score escalation (reserved for future NSL-KDD integration).
    threat_escalate_threshold: float = 0.80

    def __post_init__(self) -> None:
        if not 0.0 <= self.accept_threshold <= self.monitor_threshold <= 1.0:
            raise ValueError(
                "require 0 <= accept_threshold <= monitor_threshold <= 1"
            )


@dataclass(frozen=True)
class SecurityObservation:
    """Inputs to one security evaluation."""

    qber: float | None
    key_success: bool = True
    eavesdropping_indicated: bool = False
    noise_probability: float = 0.0
    threat_score: float | None = None  # future ML hook; None = QKD only


@dataclass
class SecurityAssessment:
    decision: SecurityDecision
    reasons: list[str] = field(default_factory=list)
    qber: float | None = None
    threat_score: float | None = None
    # Display-only Combined Risk Score (project-defined MAX heuristic, see
    # quantum.qkd.risk_fusion). NEVER used to choose `decision`. None when
    # there is no quantum observation (qber is None).
    combined_risk_score: float | None = None


class SecurityController:
    """Evaluates QKD observations against a SecurityPolicy."""

    def __init__(self, policy: SecurityPolicy | None = None) -> None:
        self.policy = policy or SecurityPolicy()

    def evaluate(
        self,
        qber: float | None,
        threat_score: float | None = None,
        key_success: bool = True,
        eavesdropping_indicated: bool = False,
        noise_probability: float = 0.0,
    ) -> SecurityAssessment:
        """Produce ACCEPT / MONITOR / REJECT (works with threat_score=None)."""
        reasons: list[str] = []
        if threat_score is not None and not 0.0 <= threat_score <= 1.0:
            raise ValueError("threat_score must be in [0, 1]")

        # Display-only Combined Risk Score (project-defined MAX heuristic;
        # local import avoids a module import cycle). Computed purely for
        # observability — the decision logic below is completely unaffected.
        from quantum.qkd.risk_fusion import combined_risk as _combined_risk
        combined = _combined_risk(qber, threat_score)

        if not key_success or qber is None:
            reasons.append("key establishment failed; no usable key material")
            return SecurityAssessment(
                SecurityDecision.REJECT, reasons, qber, threat_score,
                combined
            )

        if qber <= self.policy.accept_threshold:
            decision = SecurityDecision.ACCEPT
            reasons.append(
                f"QBER {qber:.4f} within ACCEPT bound "
                f"(<= {self.policy.accept_threshold:.2f}, project policy)"
            )
        elif qber <= self.policy.monitor_threshold:
            decision = SecurityDecision.MONITOR
            reasons.append(
                f"QBER {qber:.4f} within MONITOR band "
                f"(<= {self.policy.monitor_threshold:.2f}, project policy)"
            )
        else:
            decision = SecurityDecision.REJECT
            reasons.append(
                f"QBER {qber:.4f} exceeds MONITOR bound "
                f"(> {self.policy.monitor_threshold:.2f}, project policy)"
            )

        if eavesdropping_indicated:
            reasons.append("channel flagged: eavesdropping scenario active")
        if noise_probability > 0.0:
            reasons.append(f"configured channel noise p={noise_probability:.3f}")

        # Future ML hook: high threat score escalates one level.
        if threat_score is not None:
            reasons.append(f"network threat score={threat_score:.2f}")
            if threat_score >= self.policy.threat_escalate_threshold:
                if decision is SecurityDecision.ACCEPT:
                    decision = SecurityDecision.MONITOR
                    reasons.append("threat score escalated ACCEPT -> MONITOR")
                elif decision is SecurityDecision.MONITOR:
                    decision = SecurityDecision.REJECT
                    reasons.append("threat score escalated MONITOR -> REJECT")

        if combined is not None:
            reasons.append(
                f"combined risk score={combined:.4f} "
                "(project-defined display heuristic; not a probability; "
                "does not affect the decision)")

        logger.debug("security assessment: %s (%s)", decision, "; ".join(reasons))
        return SecurityAssessment(decision, reasons, qber, threat_score,
                                  combined)
