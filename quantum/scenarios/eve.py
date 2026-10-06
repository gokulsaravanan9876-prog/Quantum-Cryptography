"""Eavesdropping scenario: Hospital A -> channel -> Eavesdropper -> Hospital B."""

from __future__ import annotations

import logging

from quantum.qkd.bb84_engine import BB84Engine, QKDRequest
from quantum.qkd.channel import ChannelConfiguration
from quantum.qkd.security import SecurityController, SecurityPolicy
from quantum.scenarios import ScenarioResult

logger = logging.getLogger(__name__)


def run_eve_scenario(
    intercept_probability: float = 1.0,
    noise_probability: float = 0.0,
    requested_key_bits: int = 256,
    seed: int | None = None,
    policy: SecurityPolicy | None = None,
    threat_score: float | None = None,
    eve_label: str = "Eavesdropper",
) -> ScenarioResult:
    """Intercept-resend eavesdropping; QBER emerges from the simulation."""
    channel_config = ChannelConfiguration.eavesdropped(
        intercept_probability=intercept_probability,
        noise_probability=noise_probability,
        label=eve_label,
    )
    engine = BB84Engine()
    controller = SecurityController(policy)
    qkd_result = engine.establish_key(
        QKDRequest(
            requested_key_bits=requested_key_bits,
            channel_configuration=channel_config,
            seed=seed,
        )
    )
    assessment = controller.evaluate(
        qber=qkd_result.qber,
        threat_score=threat_score,
        key_success=qkd_result.success,
        eavesdropping_indicated=True,
        noise_probability=noise_probability,
    )
    return ScenarioResult(
        scenario_name="eavesdropping",
        channel_condition=channel_config.describe(),
        qber=qkd_result.qber,
        security_decision=assessment.decision,
        assessment=assessment,
        qkd_result=qkd_result,
    )
