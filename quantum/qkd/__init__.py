"""Quantum key distribution (QKD) subsystem.

Professional biomedical-network security prototype (Qiskit simulation).
Alice/Bob terminology is intentionally NOT part of this architecture;
endpoint roles are sender/receiver operated by the application layer
(Hospital A, Hospital B, ...). BB84 is referenced only as the protocol name.
"""

from quantum.qkd.bb84_engine import BB84Engine, QKDRequest, QKDResult
from quantum.qkd.channel import (
    ChannelConfiguration,
    ChannelMode,
    EavesdropperConfig,
    QuantumChannel,
)
from quantum.qkd.risk_fusion import (
    FusionMethod,
    RiskFusionConfig,
    combined_risk,
    normalize_qber,
)
from quantum.qkd.security import (
    SecurityAssessment,
    SecurityController,
    SecurityDecision,
    SecurityObservation,
    SecurityPolicy,
)

__all__ = [
    "BB84Engine",
    "QKDRequest",
    "QKDResult",
    "ChannelConfiguration",
    "ChannelMode",
    "EavesdropperConfig",
    "FusionMethod",
    "QuantumChannel",
    "RiskFusionConfig",
    "SecurityAssessment",
    "SecurityController",
    "SecurityDecision",
    "SecurityObservation",
    "SecurityPolicy",
    "combined_risk",
    "normalize_qber",
]
