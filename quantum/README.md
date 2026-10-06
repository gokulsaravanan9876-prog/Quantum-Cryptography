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
- `quantum/qkd/risk_fusion.py` — display-only **Combined Risk Score**
  (MAX fusion of `threat_score` and normalized QBER; see section below).
- `quantum/scenarios/{normal,noise,eve}.py` — thin scenario configs over
  the shared engine (no duplicated BB84).
- `quantum/application/secure_communication.py` — `Hospital`,
  `SecureSession` (guarded states), `BiomedicalMessage`, AES-GCM
  `SecurePacket`, `SecureCommunicationService`.
- `quantum/main.py` — prototype demonstration.
- `quantum/tests/test_quantum.py` — validation (24 checks).
- `quantum/tests/test_risk_fusion.py` — risk-fusion validation
  (23 checks).

## Run

```bash
./bin/python -m quantum.main
./bin/python -m quantum.tests.test_quantum
./bin/python -m quantum.tests.test_risk_fusion
# or: ./bin/python quantum/tests/test_quantum.py
```

Requires `qiskit==2.5.2`, `qiskit-aer`, and `cryptography` (AES-GCM).
Without `cryptography` the service raises
`MissingCryptoDependencyError` — no insecure fallback cipher is used.

## Combined Risk Score (risk fusion, display-only)

Formula (MAX method, the only method implemented):

```
QBER_REF          = SecurityPolicy.monitor_threshold   (project policy, 0.10)
qber_normalized   = min(qber / QBER_REF, 1.0)
combined_risk     = max(threat_score, qber_normalized)     # in [0, 1]
```

**Exact meaning.** It is a **project-defined heuristic scalar for
display/dashboard purposes**, fusing two incommensurable signals — an
externally supplied ML `threat_score` (NSL-KDD model *not* integrated;
the quantum side only accepts the score as an input, `None` = QKD-only
mode) and the quantum QBER scaled by the policy's MONITOR bound. Example
calculations: threat=0.90, QBER=0.010 → 0.90; threat=0.05, QBER=0.240 →
1.00; threat=0.10, QBER=0.010 → 0.10; threat=None, QBER=0.05 → 0.50.

**Limitations (what it is NOT).**

- **NOT a probability of compromise.** The ML score is an uncalibrated
  classifier score and QBER is an error rate; their max is neither a
  posterior probability nor a calibrated risk estimate.
- **NOT a replacement for QBER** and **NOT a replacement for the
  `SecurityController`.** QBER, `threat_score`, and the combined score
  are all displayed separately.
- **NOT a decision function.** ACCEPT / MONITOR / REJECT come
  exclusively from `SecurityController`'s rule matrix. The combined
  score can never override QBER rejection, `key_success` failure, or
  `endpoint_keys_match` failure, and never changes reconciliation,
  privacy-amplification, or AES-GCM behaviour. On disagreement, the
  controller's decision wins.
- Weighted (alpha) and noisy-OR fusion are **future experimental
  alternatives only** — not implemented in this production/demo path.

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
