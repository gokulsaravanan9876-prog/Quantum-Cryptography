# Quantum-Secure Biomedical Network (QKD Subsystem)

Track 2 prototype: Hospital A → secure communication session → Hospital B.
QKD establishes shared key material; the biomedical application provides the
data; accepted key material drives AES-GCM packet encryption.

## Layout

- `quantum/qkd/bb84_engine.py` — reusable BB84 engine (`QKDRequest` /
  `QKDResult`, Qiskit Aer, sifting, QBER from simulation).
- `quantum/qkd/channel.py` — `ChannelConfiguration` / `QuantumChannel`
  (normal / noisy / intercept-resend eavesdropping, combinable).
- `quantum/qkd/security.py` — `SecurityController` → ACCEPT / MONITOR /
  REJECT under an explicit **project policy** (accept ≤ 0.03, monitor ≤
  0.10; NOT universal QKD standards). Accepts optional future
  `threat_score` from the ML/NSL-KDD layer (`None` = QKD-only).
- `quantum/scenarios/{normal,noise,eve}.py` — thin scenario configs over
  the shared engine (no duplicated BB84).
- `quantum/application/secure_communication.py` — `Hospital`,
  `SecureSession` (guarded states), `BiomedicalMessage`, AES-GCM
  `SecurePacket`, `SecureCommunicationService`.
- `quantum/main.py` — prototype demonstration.
- `quantum/tests/test_quantum.py` — validation (23 checks).

## Run

```bash
./bin/python -m quantum.main
./bin/python -m quantum.tests.test_quantum
# or: ./bin/python quantum/tests/test_quantum.py
```

Requires `qiskit==2.5.2`, `qiskit-aer`, and `cryptography` (AES-GCM).
Without `cryptography` the service raises
`MissingCryptoDependencyError` — no insecure fallback cipher is used.

## Preserved quantum logic

From root `bb84.py` / `bb84_eve.py` / `bb84_noise.py`: random bits & bases
(0=Z, 1=X), BB84 state prep (`Z`: X-gate; `X`: X then H), X-basis readout
via H + single-shot Aer run, intercept-resend (measure + replacement
state), probabilistic Pauli-X channel disturbance, sifting on matching
bases, QBER = mismatches / sifted bits. Refactored to sender/receiver
roles; no hard-coded keys, hospitals, or QBER values in quantum code.

## Honesty notes (prototype, not production QKD)

This is a Qiskit simulation. Production deployment would additionally need
authenticated classical channel, information reconciliation, privacy
amplification (here only a SHA-256 prototype KDF), secure key management,
finite-key analysis, physical quantum hardware, and operational safeguards.
Regenerating keys / applying thresholds here is NOT equivalent to that
post-processing. Secret key material is never printed or placed in packets.

Two-endpoint honesty: `QKDResult` carries independent `sender_key_material`
(Hospital A) and `receiver_key_material` (Hospital B) from the paired sift;
the receiver key is never copied from the sender key. No reconciliation is
implemented, so keys may differ whenever QBER > 0. The application encrypts
only on exact endpoint-key equality (`endpoint_keys_match`); otherwise the
session parks in `KEY_RECONCILIATION_REQUIRED` and no packet is produced.
