"""Noisy-channel scenario: Hospital A -> noisy quantum channel -> Hospital B."""

from __future__ import annotations

import logging

from quantum.qkd.bb84_engine import BB84Engine, QKDRequest
from quantum.qkd.channel import ChannelConfiguration
from quantum.qkd.security import SecurityController, SecurityPolicy
from quantum.scenarios import ScenarioResult

logger = logging.getLogger(__name__)


def run_noise_scenario(
    noise_probability: float = 0.05,
    requested_key_bits: int = 256,
    seed: int | None = None,
    policy: SecurityPolicy | None = None,
    threat_score: float | None = None,
) -> ScenarioResult:
    channel_config = ChannelConfiguration.noisy(noise_probability)
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
        eavesdropping_indicated=False,
        noise_probability=noise_probability,
    )
    return ScenarioResult(
        scenario_name="noise",
        channel_condition=channel_config.describe(),
        qber=qkd_result.qber,
        security_decision=assessment.decision,
        assessment=assessment,
        qkd_result=qkd_result,
    )
