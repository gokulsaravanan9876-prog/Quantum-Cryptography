"""Network security scenario configurations (no duplicated BB84 logic)."""

from dataclasses import dataclass

from quantum.qkd.bb84_engine import QKDResult
from quantum.qkd.security import SecurityAssessment, SecurityDecision

__all__ = ["ScenarioResult"]


@dataclass
class ScenarioResult:
    """Structured outcome of one scenario run."""

    scenario_name: str
    channel_condition: str
    qber: float | None
    security_decision: SecurityDecision
    assessment: SecurityAssessment
    qkd_result: QKDResult
