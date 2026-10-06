"""Biomedical-network security prototype demo (NOT a classroom BB84 demo)."""

from __future__ import annotations

import logging

from quantum.application.secure_communication import (
    Hospital,
    SecureCommunicationService,
)
from quantum.qkd.channel import ChannelConfiguration
from quantum.qkd.risk_fusion import normalize_qber
from quantum.scenarios.eve import run_eve_scenario
from quantum.scenarios.noise import run_noise_scenario
from quantum.scenarios.normal import run_normal_scenario

logging.basicConfig(level=logging.WARNING)


def _fmt_qber(qber) -> str:
    return f"{qber * 100:.2f}%" if qber is not None else "N/A"


def _fmt_threat(threat) -> str:
    return f"{threat:.4f}" if threat is not None else "N/A (not supplied)"


def _fmt_risk(score) -> str:
    if score is None:
        return "N/A"
    return f"{score:.4f} (project-defined heuristic, NOT a probability)"


def _fmt_norm(qber) -> str:
    norm = normalize_qber(qber)
    return f"{norm:.4f}" if norm is not None else "N/A"


def _ml_status() -> list[str]:
    """Report real trained-artifact availability (honest, never faked)."""
    try:
        from ml_bridge import try_load_scorer
    except Exception as exc:  # ML deps missing entirely
        return [f"REAL NSL-KDD MODEL: UNAVAILABLE ({type(exc).__name__})",
                "Using synthetic demonstration inputs only."]
    scorer = try_load_scorer()
    if scorer is not None:
        return [f"REAL NSL-KDD MODEL: available ({scorer.model_path})"]
    return ["REAL NSL-KDD MODEL: UNAVAILABLE",
            "Using synthetic demonstration inputs only."]


def _real_case_inputs():
    """Real low/high-threat records from genuine KDDTest+.txt, or None.

    Returns ``(scorer, data_path, low, high)`` where ``low``/``high`` are
    ``(score, row_index, record)`` chosen as min/max over the first 500
    genuine records — deterministic given the fixed artifact + dataset.
    """
    try:
        from ml_bridge import find_nsl_kdd_data, load_nsl_kdd_records, \
            try_load_scorer
        scorer = try_load_scorer()
        data = find_nsl_kdd_data()
        if scorer is None or data is None:
            return None
        records = load_nsl_kdd_records(data, limit=500)
        scored = [(scorer.score_record(rec), i, rec)
                  for i, rec in enumerate(records)]
        low, high = min(scored), max(scored)
        if not low[0] < high[0]:
            return None
        return scorer, data, low, high
    except Exception:  # missing deps/data -> honest synthetic fallback
        return None


def _print_real_cases(real) -> None:
    """Four required cases using REAL NSL-KDD model outputs."""
    _scorer, data, low, high = real
    print(f"  REAL records from  : {data} (first 500 rows scanned)")
    print("  ML threat scores below are REAL model outputs "
          "(RandomForest predict_proba[:,1] —")
    print("  UNCALIBRATED attack-likeness score, NOT a calibrated "
          "probability).")
    print("  QKD conditions are SIMULATED (Qiskit Aer BB84); Combined "
          "Risk Score is a")
    print("  project-defined MAX heuristic, NOT a probability; every "
          "Final Decision")
    print("  comes ONLY from SecurityController.")
    cases = [
        ("CASE R1 — low-threat record + CLEAN QKD",
         run_normal_scenario, 7, low),
        ("CASE R2 — high-threat record + CLEAN QKD (escalation)",
         run_normal_scenario, 7, high),
        ("CASE R3 — low-threat record + EAVESDROPPED QKD",
         run_eve_scenario, 23, low),
        ("CASE R4 — high-threat record + EAVESDROPPED QKD",
         run_eve_scenario, 23, high),
    ]
    for title, run, seed, (score, idx, rec) in cases:
        res = run(requested_key_bits=128, seed=seed, threat_score=score)
        a = res.assessment
        print(f"\n  {title}")
        print(f"    Record              : KDDTest+.txt row {idx} "
              f"(ground-truth label: {rec.get('label')})")
        print(f"    ML Threat Score     : {a.threat_score:.4f}  "
              f"[REAL NSL-KDD MODEL, uncalibrated]")
        print(f"    QBER                : {_fmt_qber(res.qber)}  "
              f"[SIMULATED QKD]")
        print(f"    Normalized QBER     : {_fmt_norm(res.qber)}")
        print(f"    Combined Risk Score : "
              f"{_fmt_risk(a.combined_risk_score)}")
        print(f"    Final Decision      : {res.security_decision.value}")


def _print_assessment(title, result, extra="") -> None:
    assessment = result.assessment
    print(f"\n{title}\n{extra}")
    print(f"  Channel condition : {result.channel_condition}")
    print(f"  ML Threat Score    : "
          f"{_fmt_threat(assessment.threat_score if assessment else None)}")
    print(f"  QBER               : {_fmt_qber(result.qber)}")
    print(f"  Normalized QBER    : {_fmt_norm(result.qber)}")
    print(f"  Combined Risk Score: "
          f"{_fmt_risk(assessment.combined_risk_score if assessment else None)}")
    print(f"  Final Decision     : {result.security_decision.value}")
    print(f"  Endpoint keys     : "
          f"{'MATCH' if result.qkd_result.endpoint_keys_match else 'DIFFER '
          f'(reconciliation not implemented)'}")
    print(f"  Key establishment : "
          f"{'SUCCESS' if result.qkd_result.success else 'FAILED'} "
          f"({result.qkd_result.generated_key_bits}/"
          f"{result.qkd_result.requested_key_bits} bits, "
          f"{result.qkd_result.internal_qubits} qubits)")


def main() -> None:
    print("=" * 60)
    print("QUANTUM-SECURE BIOMEDICAL NETWORK")
    print("=" * 60)
    print("\nNETWORK ENDPOINTS")
    print("  Source      : Hospital A")
    print("  Destination : Hospital B")
    print("\n--------------------------------------------------------")
    print("QKD SECURITY ASSESSMENT")
    print("--------------------------------------------------------")
    _print_assessment("Scenario 1: Normal Quantum Channel",
                      run_normal_scenario(requested_key_bits=128))
    _print_assessment("Scenario 2: Noisy Quantum Channel",
                      run_noise_scenario(noise_probability=0.05,
                                         requested_key_bits=128),
                      "  Noise level       : 0.05")
    _print_assessment("Scenario 3: Potential Eavesdropping",
                      run_eve_scenario(requested_key_bits=128),
                      "  Eavesdropper      : intercept-resend (simulated)")

    print("\n--------------------------------------------------------")
    print("ML x QUANTUM INTEGRATION CASES")
    print("--------------------------------------------------------")
    _status = _ml_status()
    print(f"  {_status[0]}")
    for _line in _status[1:]:
        print(f"  {_line}")
    print("  REAL interface : ml_bridge.NSLKDDThreatScorer"
          ".score_record(record) -> float")
    real = _real_case_inputs()
    if real is not None:
        _print_real_cases(real)
    else:
        print("  Threat scores below are SYNTHETIC demo literals —")
        print("  NOT NSL-KDD model predictions. Combined Risk Score is a")
        print("  project-defined MAX heuristic, NOT a probability; every")
        print("  Final Decision comes ONLY from SecurityController.")
        for title, run, threat in [
            ("CASE 1 — Normal (low ML threat, low QBER)",
             run_normal_scenario, 0.05),
            ("CASE 2 — ML-hot / quantum-clean (escalation)",
             run_normal_scenario, 0.90),
            ("CASE 3 — ML-clean / quantum-hot",
             run_eve_scenario, 0.05),
            ("CASE 4 — Both high",
             run_eve_scenario, 0.90),
        ]:
            res = run(requested_key_bits=128, threat_score=threat)
            a = res.assessment
            print(f"\n  {title}")
            print(f"    ML Threat Score     : {a.threat_score:.2f}  "
                  f"[SYNTHETIC demo input]")
            print(f"    QBER                : {_fmt_qber(res.qber)}")
            print(f"    Normalized QBER     : {_fmt_norm(res.qber)}")
            print(f"    Combined Risk Score : "
                  f"{_fmt_risk(a.combined_risk_score)}")
            print(f"    Final Decision      : {res.security_decision.value}")

    print("\n--------------------------------------------------------")
    print("SECURE BIOMEDICAL TRANSMISSION")
    print("--------------------------------------------------------")
    hosp_a = Hospital(hospital_id="HOSP-A", name="Hospital A")
    hosp_b = Hospital(hospital_id="HOSP-B", name="Hospital B")
    payload = {"patient_id": "P1024", "blood_pressure": "120/80",
               "heart_rate": 78, "diagnosis": "routine follow-up"}
    service = SecureCommunicationService()
    sent = service.send_biomedical_data(
        hosp_a, hosp_b, payload,
        channel_config=ChannelConfiguration.normal(),
        requested_key_bits=128)
    print(f"\nSource      : {hosp_a.name}\nDestination : {hosp_b.name}")
    print("Biomedical payload: <protected health data — not displayed>")
    print(f"QKD status        : "
          f"{'SUCCESS' if sent.session.qkd_result.success else 'FAILED'}")
    _assessment = sent.assessment
    print(f"ML Threat Score    : "
          f"{_fmt_threat(_assessment.threat_score if _assessment else None)}")
    print(f"QBER               : {_fmt_qber(sent.session.qber)}")
    print(f"Normalized QBER    : {_fmt_norm(sent.session.qber)}")
    print(f"Combined Risk Score: "
          f"{_fmt_risk(_assessment.combined_risk_score if _assessment else None)}")
    print(f"Final Decision     : {sent.session.security_decision.value}")
    print(f"Endpoint keys     : "
          f"{'MATCH' if sent.session.qkd_result.endpoint_keys_match
            else 'DIFFER (KEY_RECONCILIATION_REQUIRED)'}")
    if sent.packet is None:
        print(f"Encryption    : SKIPPED ({sent.session.failure_reason})")
        print(f"Session state : {sent.session.state.value}")
        print("Final status: REJECTED / HELD — no data transmitted")
        return
    received = service.receive_packet(sent.packet, sent.session)
    print(f"Encryption    : {sent.session.encryption_status}")
    print("Transmission  : DELIVERED (simulated secure packet)")
    print(f"Decryption    : {received.session.delivery_status}")
    ok = (received.delivered_payload is not None
          and received.delivered_payload.record == payload
          and received.integrity_verified)
    print(f"Integrity verification: {'PASS' if ok else 'FAIL'}")
    print("\nFinal status: "
          + ("SECURE TRANSMISSION SUCCESS" if ok else "FAILED"))


if __name__ == "__main__":
    main()
