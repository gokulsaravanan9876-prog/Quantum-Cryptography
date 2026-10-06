"""Reusable BB84 QKD engine (quantum key establishment only).

Preserves verified quantum logic from the pre-existing prototype files
(bb84.py / bb84_eve.py / bb84_noise.py at the repository root):
random bits/bases (0=Z, 1=X), BB84 state prep, single-shot AerSimulator
measurement (X via H), intercept-resend, probabilistic Pauli-X channel
disturbance, sifting (keep matching bases), QBER from the simulation.

Endpoint roles here are sender/receiver (operated by Hospital A/B etc.).
"Alice/Bob" appear only in this docstring to map BB84 terminology.
"""

from __future__ import annotations

import logging
import math
import random
from dataclasses import dataclass, field

from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator

from quantum.qkd.channel import ChannelConfiguration, QuantumChannel

logger = logging.getLogger(__name__)

Z_BASIS = 0
X_BASIS = 1
DEFAULT_SIFTING_OVERHEAD = 2.5
DEFAULT_MAX_ROUNDS = 5


@dataclass(frozen=True)
class QKDRequest:
    """Application request for shared key material."""

    requested_key_bits: int = 256
    channel_configuration: ChannelConfiguration = field(
        default_factory=ChannelConfiguration.normal
    )
    max_rounds: int = DEFAULT_MAX_ROUNDS
    sifting_overhead: float = DEFAULT_SIFTING_OVERHEAD
    seed: int | None = None

    def __post_init__(self) -> None:
        if self.requested_key_bits <= 0:
            raise ValueError("requested_key_bits must be positive")
        if self.max_rounds <= 0:
            raise ValueError("max_rounds must be positive")
        if self.sifting_overhead < 1.0:
            raise ValueError("sifting_overhead must be >= 1.0")


@dataclass
class QKDResult:
    """Outcome with INDEPENDENT endpoint keys (no silent copying).

    sender_key_material: Hospital A endpoint sifted key (transmitter bits).
    receiver_key_material: Hospital B endpoint sifted key (receiver
    measurements after sifting). Both come from the same paired sift;
    receiver list is NEVER assigned from the sender list.
    Prototype honesty: no information reconciliation / error correction,
    so the two lists may differ whenever QBER > 0.
    """

    success: bool
    requested_key_bits: int
    generated_key_bits: int
    internal_qubits: int
    sifted_bits: int
    qber: float | None
    mismatches: int | None
    rounds_used: int
    channel_mode: str
    sender_key_material: list[int] | None = field(default=None, repr=False)
    receiver_key_material: list[int] | None = field(default=None, repr=False)
    failure_reason: str | None = None

    @staticmethod
    def _pack(bits: list[int] | None) -> bytes | None:
        if not bits:
            return None
        out = bytearray()
        for i in range(0, len(bits), 8):
            chunk = bits[i:i + 8]
            value = 0
            for b in chunk:
                value = (value << 1) | (b & 1)
            value <<= 8 - len(chunk)
            out.append(value)
        return bytes(out)

    @property
    def sender_key_bytes(self) -> bytes | None:
        """Hospital A endpoint key bytes (encryption side)."""
        return self._pack(self.sender_key_material)

    @property
    def receiver_key_bytes(self) -> bytes | None:
        """Hospital B endpoint key bytes (decryption side)."""
        return self._pack(self.receiver_key_material)

    @property
    def endpoint_keys_match(self) -> bool:
        """True only if both endpoint keys exist and are bit-identical."""
        return (
            self.sender_key_material is not None
            and self.receiver_key_material is not None
            and len(self.sender_key_material) > 0
            and self.sender_key_material == self.receiver_key_material
        )


class BB84Engine:
    """BB84 key-establishment engine (Qiskit Aer simulation)."""

    def __init__(self, simulator: AerSimulator | None = None) -> None:
        self._simulator = simulator or AerSimulator()

    @staticmethod
    def generate_bits(count: int, rng: random.Random) -> list[int]:
        return [rng.randint(0, 1) for _ in range(count)]

    @staticmethod
    def generate_bases(count: int, rng: random.Random) -> list[int]:
        """Random bases: 0 = Z, 1 = X."""
        return [rng.randint(0, 1) for _ in range(count)]

    @staticmethod
    def encode_qubit(bit: int, basis: int) -> QuantumCircuit:
        """Prepare one BB84 qubit: Z -> {|0>,|1>}, X -> {|+>,|->}."""
        circuit = QuantumCircuit(1, 1)
        if basis == Z_BASIS:
            if bit == 1:
                circuit.x(0)
        else:
            if bit == 1:
                circuit.x(0)
            circuit.h(0)
        return circuit

    @staticmethod
    def apply_channel_disturbance(
        circuit: QuantumCircuit, disturb: bool
    ) -> QuantumCircuit:
        """Simplified channel disturbance: probabilistic Pauli-X flip."""
        if disturb:
            circuit.x(0)
        return circuit

    def measure_qubit(self, circuit: QuantumCircuit, basis: int) -> int:
        """Measure in requested basis (X via H, single Aer shot)."""
        if basis == X_BASIS:
            circuit.h(0)
        circuit.measure(0, 0)
        result = self._simulator.run(circuit, shots=1).result()
        counts = result.get_counts()
        return int(next(iter(counts)), 2)

    def intercept_resend(
        self, circuit: QuantumCircuit, eve_basis: int
    ) -> QuantumCircuit:
        """Intercept-resend: measure, forward replacement state."""
        eve_bit = self.measure_qubit(circuit, eve_basis)
        return self.encode_qubit(eve_bit, eve_basis)

    @staticmethod
    def sift(sender_bits, sender_bases, receiver_bases,
             receiver_bits):
        sk, rk = [], []
        for bit, sb, rb, rbit in zip(
                sender_bits, sender_bases, receiver_bases, receiver_bits):
            if sb == rb:
                sk.append(bit)
                rk.append(rbit)
        return sk, rk

    @staticmethod
    def calculate_qber(sender_key, receiver_key):
        if not sender_key:
            return None, None
        mism = sum(a != b for a, b in zip(sender_key, receiver_key))
        return mism / len(sender_key), mism

    @staticmethod
    def estimate_qubits(remaining_bits: int, overhead: float) -> int:
        return max(8, math.ceil(remaining_bits * overhead))

    def _transmit(self, qubit_count, channel, rng):
        sbits = self.generate_bits(qubit_count, rng)
        sbases = self.generate_bases(qubit_count, rng)
        rbases = self.generate_bases(qubit_count, rng)
        rbits = []
        for i in range(qubit_count):
            circuit = self.encode_qubit(sbits[i], sbases[i])
            circuit = self.apply_channel_disturbance(
                circuit, channel.should_disturb_qubit())
            if channel.should_intercept_qubit():
                circuit = self.intercept_resend(
                    circuit, channel.choose_intercept_basis())
            rbits.append(self.measure_qubit(circuit, rbases[i]))
        return self.sift(sbits, sbases, rbases, rbits)

    def establish_key(self, request: QKDRequest) -> QKDResult:
        """Run BB84 until requested bits exist or rounds are exhausted."""
        rng = random.Random(request.seed)
        channel = QuantumChannel(request.channel_configuration)
        channel._rng = rng  # reproducible draws, frozen config untouched
        collected_s, collected_r = [], []
        internal_qubits, rounds_used = 0, 0
        for round_no in range(1, request.max_rounds + 1):
            rounds_used = round_no
            remaining = request.requested_key_bits - len(collected_s)
            if remaining <= 0:
                break
            n = self.estimate_qubits(remaining, request.sifting_overhead)
            internal_qubits += n
            sk, rk = self._transmit(n, channel, rng)
            collected_s.extend(sk)
            collected_r.extend(rk)
            logger.debug("QKD round %d: %d qubits -> %d sifted",
                         round_no, n, len(sk))
        sifted = len(collected_s)
        qber, mism = self.calculate_qber(collected_s, collected_r)
        # Independent endpoint keys: trim BOTH paired sifted lists to the
        # requested length. Receiver key is never copied from sender key.
        trim_s = collected_s[:request.requested_key_bits]
        trim_r = collected_r[:request.requested_key_bits]
        success = qber is not None and len(trim_s) >= request.requested_key_bits
        reason = None
        if not success:
            reason = ("no sifted key material" if qber is None
                      else "insufficient sifted bits for requested key length")
        return QKDResult(
            success=success,
            requested_key_bits=request.requested_key_bits,
            generated_key_bits=len(trim_s) if success else 0,
            internal_qubits=internal_qubits,
            sifted_bits=sifted,
            qber=qber, mismatches=mism, rounds_used=rounds_used,
            channel_mode=request.channel_configuration.mode.value,
            sender_key_material=list(trim_s) if success else None,
            receiver_key_material=list(trim_r) if success else None,
            failure_reason=reason,
        )
