"""Biomedical-network security prototype demo (NOT a classroom BB84 demo)."""

from __future__ import annotations

import logging

from quantum.application.secure_communication import (
    Hospital,
    SecureCommunicationService,
)
from quantum.qkd.channel import ChannelConfiguration
from quantum.qkd.risk_fusion import combined_risk
from quantum.qkd.security import SecurityController
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


def _print_assessment(title, result, extra="") -> None:
    assessment = result.assessment
    print(f"\n{title}\n{extra}")
    print(f"  Channel condition : {result.channel_condition}")
    print(f"  ML Threat Score    : "
          f"{_fmt_threat(assessment.threat_score if assessment else None)}")
    print(f"  QBER               : {_fmt_qber(result.qber)}")
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
    print("RISK FUSION (Combined Risk Score = project-defined MAX heuristic)")
    print("--------------------------------------------------------")
    print("  NOT a probability of compromise; never overrides QBER,")
    print("  key_success, or endpoint-key checks. Decisions below come")
    print("  ONLY from SecurityController. NSL-KDD model NOT integrated:")
    print("  threat_score values below are ILLUSTRATIVE external inputs.")
    for label, threat, qber in [
        ("ML hot / quantum clean", 0.90, 0.010),
        ("quantum hot / ML clean", 0.05, 0.240),
        ("both calm (typical)", 0.10, 0.010),
        ("both high", 0.90, 0.240),
    ]:
        combined = combined_risk(qber, threat)
        decision = SecurityController().evaluate(
            qber, threat_score=threat).decision.value
        print(f"  {label:<24} ML={threat:.2f} QBER={qber:.3f} "
              f"-> Combined={combined:.4f}  Decision={decision}")

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
