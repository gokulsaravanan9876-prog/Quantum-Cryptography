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
- `quantum/tests/test_ml_integration.py` — ML → quantum integration
  validation (33 checks; R1–R8 exercise the REAL artifact + genuine
  records and auto-skip honestly without them).
- `ml_bridge/` — thin adapter OUTSIDE the quantum package: loads the
  NSL-KDD model artifact from `~/Quantum-Cryptography/ml/model.joblib`
  when present, locates genuine `KDDTest+.txt` records
  (`find_nsl_kdd_data` / `load_nsl_kdd_records`, same reader + COLUMNS
  as `predict.py`), and yields a plain `threat_score: float | None`
  (see Integration section).

## Run

```bash
./bin/python -m quantum.main
./bin/python -m quantum.tests.test_quantum
./bin/python -m quantum.tests.test_risk_fusion
./bin/python -m quantum.tests.test_ml_integration
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
display/dashboard purposes**, fusing two incommensurable signals — the
ML `threat_score` supplied by the `ml_bridge` adapter (see Integration
section; `None` = QKD-only mode) and the quantum QBER scaled by the
policy's MONITOR bound. Example
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

## ML → quantum integration (`ml_bridge/`, the threat_score path)

```
NSL-KDD data → train_classifier.py → model.joblib (artifact)
      → ml_bridge.NSLKDDThreatScorer.score_record(record) → float
      → SecurityController.evaluate(qber=..., threat_score=...)
      → SecurityAssessment { decision, combined_risk_score }
      → Hospital A → B (endpoint-key gate + AES-GCM unchanged)
```

- **Interface.** `threat_score: float | None` is the only value crossing
  into `quantum/`. The adapter lives in `ml_bridge/`, outside the quantum
  package; the quantum core (`qkd/`, `application/`, `scenarios/`) has
  zero ML imports (asserted by integration check B6) and behaves exactly
  as before when `threat_score=None`.
- **threat_score semantics.** The value is `model.predict_proba(X)[:, 1]`
  — the RandomForest pipeline's *uncalibrated* positive-class score.
  Call it the **ML threat score**, never a probability of attack.
  Preprocessing (one-hot + numeric passthrough) lives inside the saved
  sklearn Pipeline, so nothing is duplicated in `quantum/`; feature
  column order comes from `predict.py`'s `COLUMNS`, imported at runtime
  (single source of truth). The ML files in `~/Quantum-Cryptography/`
  are never modified.
- **Artifact status (honest).** NO trained `model.joblib` and NO
  NSL-KDD dataset currently exist in `~/Quantum-Cryptography/`
  (verified). Therefore:
  - REAL integration interface: yes — `ml_bridge` with checks B1–B6,
    including a real joblib artifact round-trip through the adapter
    (toy pipeline test fixture, explicitly not NSL-KDD training).
  - REAL trained NSL-KDD model execution: NOT possible today.
    `load_threat_model()` raises `ModelUnavailableError` rather than
    fabricating outputs; `try_load_scorer()` returns `None`.
  - SYNTHETIC demo inputs: the four integration cases in
    `quantum/main.py` use explicitly labeled synthetic literals
    (0.05 / 0.90) — NOT NSL-KDD predictions.
  To go live: place genuine NSL-KDD files (canonical names
  `KDDTrain+.txt` / `KDDTest+.txt`, 43 comma-separated fields, no
  header: 41 features + `label` + `difficulty`), then run
  `python train_classifier.py --train <KDDTrain+.txt>
  --test <KDDTest+.txt>` (writes `ml/model.joblib`), then score records
  with `NSLKDDThreatScorer.score_record`. No genuine NSL-KDD dataset
  exists anywhere in the local project locations (verified by filename
  and content scan), so no real training has been possible yet.
- **MAX rationale / sensor distinction.** QBER is a quantum-channel
  error rate measured in the actual BB84 run; the threat score is a
  network-traffic classifier output. They are incommensurable, so the
  fusion takes the max: display stays monotone in both inputs and
  reports "the worst sensor wins" without inventing a joint
  distribution.
- **Safety.** Threat escalation only ever tightens decisions
  (ACCEPT → MONITOR → REJECT) and can never relax a QBER-based
  decision, rescue a `key_success` failure, or unlock the
  endpoint-key gate. This is not production security.

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
