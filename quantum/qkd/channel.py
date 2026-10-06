"""Configurable quantum-channel simulation layer.

The channel object owns *channel behaviour* (disturbance policy); the
BB84 engine in :mod:`quantum.qkd.bb84_engine` owns the quantum operations
(state preparation / measurement). This keeps BB84 logic in exactly one
place while supporting normal, noisy and eavesdropped configurations,
including noise + eavesdropping combined.

Noise model (explicit, documented):
    With probability ``noise_probability`` a Pauli-X (bit-flip) disturbance
    is applied to the in-flight qubit. This is a deliberately simplified
    stand-in for physical channel disturbance, not a full device noise
    model. The resulting QBER emerges from the simulation; nothing is
    hard-coded.

Eavesdropping model:
    Intercept-resend. Per qubit, with probability ``intercept_probability``
    (when enabled) the in-flight state is measured in a random basis and a
    replacement state prepared from that outcome is forwarded. QBER emerges
    from the simulation.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from enum import Enum


class ChannelMode(Enum):
    """High-level description of the configured channel condition."""

    NORMAL = "NORMAL"
    NOISY = "NOISY"
    EAVESDROPPED = "EAVESDROPPED"
    NOISY_EAVESDROPPED = "NOISY_EAVESDROPPED"


@dataclass(frozen=True)
class EavesdropperConfig:
    """Intercept-resend eavesdropper configuration (simulation only)."""

    enabled: bool = False
    intercept_probability: float = 1.0
    label: str = "Eavesdropper"

    def __post_init__(self) -> None:
        if not 0.0 <= self.intercept_probability <= 1.0:
            raise ValueError("intercept_probability must be in [0, 1]")


@dataclass(frozen=True)
class ChannelConfiguration:
    """Channel conditions for one QKD session (simulation environment).

    A real hospital application never supplies these values; they describe
    the experimental scenario under test.
    """

    noise_probability: float = 0.0
    eavesdropper: EavesdropperConfig = field(
        default_factory=EavesdropperConfig
    )
    seed: int | None = None

    def __post_init__(self) -> None:
        if not 0.0 <= self.noise_probability <= 1.0:
            raise ValueError("noise_probability must be in [0, 1]")

    @property
    def mode(self) -> ChannelMode:
        noisy = self.noise_probability > 0.0
        eve = self.eavesdropper.enabled
        if noisy and eve:
            return ChannelMode.NOISY_EAVESDROPPED
        if eve:
            return ChannelMode.EAVESDROPPED
        if noisy:
            return ChannelMode.NOISY
        return ChannelMode.NORMAL

    @classmethod
    def normal(cls) -> ChannelConfiguration:
        return cls()

    @classmethod
    def noisy(cls, noise_probability: float) -> ChannelConfiguration:
        return cls(noise_probability=noise_probability)

    @classmethod
    def eavesdropped(
        cls,
        intercept_probability: float = 1.0,
        noise_probability: float = 0.0,
        label: str = "Eavesdropper",
    ) -> ChannelConfiguration:
        return cls(
            noise_probability=noise_probability,
            eavesdropper=EavesdropperConfig(
                enabled=True,
                intercept_probability=intercept_probability,
                label=label,
            ),
        )

    def describe(self) -> str:
        text = f"mode={self.mode.value}"
        text += f", noise_p={self.noise_probability:.3f}"
        text += f", eve={self.eavesdropper.enabled}"
        if self.eavesdropper.enabled:
            text += f"(p={self.eavesdropper.intercept_probability:.2f})"
        return text


class QuantumChannel:
    """Disturbance policy for the simulated quantum channel."""

    def __init__(self, config: ChannelConfiguration | None = None) -> None:
        self.config = config or ChannelConfiguration.normal()
        self._rng = random.Random(self.config.seed)

    def should_disturb_qubit(self) -> bool:
        """Draw whether this qubit suffers channel disturbance."""
        return self._rng.random() < self.config.noise_probability

    def should_intercept_qubit(self) -> bool:
        """Draw whether the eavesdropper intercepts this qubit."""
        eve = self.config.eavesdropper
        return eve.enabled and (
            self._rng.random() < eve.intercept_probability
        )

    def choose_intercept_basis(self) -> int:
        """Random intercept basis: 0 = Z, 1 = X."""
        return self._rng.randint(0, 1)

    def describe(self) -> str:
        return self.config.describe()
