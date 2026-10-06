"""Validation: QKD + security + encrypt/decrypt + tamper + rejected-key."""

from quantum.application.secure_communication import (
    Hospital, SecureCommunicationService, BiomedicalMessage, SessionState,
)
from quantum.qkd.bb84_engine import BB84Engine, QKDRequest
from quantum.qkd.channel import ChannelConfiguration
from quantum.qkd.security import (
    SecurityController, SecurityDecision, SecurityPolicy,
)
from quantum.scenarios.eve import run_eve_scenario
from quantum.scenarios.noise import run_noise_scenario
from quantum.scenarios.normal import run_normal_scenario

PASS, FAIL = "PASS", "FAIL"
results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    print(f"[{PASS if cond else FAIL}] {name} {detail}")


def test_normal():
    r = run_normal_scenario(requested_key_bits=64, seed=7)
    check("1.normal channel works",
          r.qkd_result.success and r.qber is not None and r.qber <= 0.03,
          f"(qber={r.qber})")
    check("5a.accept decision", r.security_decision == SecurityDecision.ACCEPT)


def test_noise():
    r = run_noise_scenario(noise_probability=0.05, requested_key_bits=64,
                           seed=11)
    check("2.noise channel runs", r.qkd_result.qber is not None,
          f"(qber={r.qber}, decision={r.security_decision.value})")


def test_eve():
    r = run_eve_scenario(requested_key_bits=64, seed=23)
    check("3.eavesdropping detected via QBER",
          r.qber is not None and r.qber > 0.10,
          f"(qber={r.qber}, decision={r.security_decision.value})")
    check("7.reject decision", r.security_decision == SecurityDecision.REJECT)


def test_qber_math():
    q, m = BB84Engine.calculate_qber([0, 1, 1, 0], [0, 0, 1, 0])
    check("4.qber calculation", q == 0.25 and m == 1, f"(qber={q})")


def test_decisions():
    c = SecurityController(SecurityPolicy(0.03, 0.10))
    a = c.evaluate(0.01).decision == SecurityDecision.ACCEPT
    m = c.evaluate(0.07).decision == SecurityDecision.MONITOR
    r = c.evaluate(0.30).decision == SecurityDecision.REJECT
    t = (c.evaluate(0.01, threat_score=0.9).decision
         == SecurityDecision.MONITOR)  # ML escalation hook
    check("5/6/7.accept-monitor-reject + threat hook", a and m and r and t)
    try:
        c.evaluate(0.01, threat_score=9.0)
        check("threat bounds", False)
    except ValueError:
        check("threat bounds", True)


def test_app_flow():
    svc = SecureCommunicationService()
    a = Hospital("HOSP-A", "Hospital A")
    b = Hospital("HOSP-B", "Hospital B")
    payload = {"patient_id": "P1024", "heart_rate": 78}
    sent = svc.send_biomedical_data(a, b, payload,
                                    channel_config=ChannelConfiguration
                                    .normal(),
                                    requested_key_bits=64, seed=3)
    qr = sent.session.qkd_result
    check("8.qkd key length", qr.generated_key_bits == 64
          and len(qr.sender_key_bytes) == 8
          and len(qr.receiver_key_bytes) == 8)
    check("packet hides plaintext+key",
          sent.packet is not None
          and b"P1024" not in sent.packet.ciphertext
          and sent.packet.ciphertext != qr.sender_key_bytes)
    got = svc.receive_packet(sent.packet, sent.session)
    check("9.encrypt/decrypt round-trip",
          got.delivered_payload.record == payload
          and got.integrity_verified)
    # 10. tampered ciphertext must fail
    sent2 = svc.send_biomedical_data(a, b, payload,
                                     channel_config=ChannelConfiguration
                                     .normal(),
                                     requested_key_bits=64, seed=4)
    bad = bytearray(sent2.packet.ciphertext)
    bad[0] ^= 0xFF
    from dataclasses import replace
    tampered = replace(sent2.packet, ciphertext=bytes(bad))
    try:
        svc.receive_packet(tampered, sent2.session)
        check("10.tamper detection", False)
    except ValueError:
        check("10.tamper detection", True)
    # 11. rejected key must never transmit/decrypt. Endpoint-key gate runs
    # before the security-decision branch, so an eavesdropped session with
    # mismatched endpoint keys legitimately parks in
    # KEY_RECONCILIATION_REQUIRED instead of QKD_REJECTED. The invariant is
    # BLOCKED + no packet + decrypt refused.
    eve_sent = svc.send_biomedical_data(
        a, b, payload,
        channel_config=ChannelConfiguration.eavesdropped(),
        requested_key_bits=64, seed=23)
    check("11.rejected key blocked",
          eve_sent.packet is None
          and eve_sent.session.state in (SessionState.QKD_REJECTED,
                                         SessionState.KEY_RECONCILIATION_REQUIRED),
          f"(state={eve_sent.session.state.value})")
    try:
        svc.receive_packet(eve_sent.packet, eve_sent.session)
        check("11.rejected decrypt refused", False)
    except Exception:
        check("11.rejected decrypt refused", True)


def test_states():
    from quantum.application.secure_communication import SecureSession
    s = SecureSession("x", Hospital("A", "A"), Hospital("B", "B"), 64)
    try:
        s.transition(SessionState.ENCRYPTED)
        check("session guards transitions", False)
    except ValueError:
        check("session guards transitions", True)


def test_endpoint_keys():
    """1-3: independent endpoint keys; mismatch blocks sender-key reuse."""
    from quantum.qkd.bb84_engine import QKDRequest
    eng = BB84Engine()
    # 1. Noiseless BB84 -> endpoints match -> app may proceed.
    r = eng.establish_key(QKDRequest(
        requested_key_bits=64,
        channel_configuration=ChannelConfiguration.normal(), seed=7))
    check("E1.noiseless endpoints match",
          r.success and r.endpoint_keys_match
          and r.sender_key_bytes == r.receiver_key_bytes,
          f"(qber={r.qber})")
    check("E1.receiver not copied: independent sift lists",
          r.sender_key_material is not r.receiver_key_material)
    svc = SecureCommunicationService()
    a = Hospital("HOSP-A", "Hospital A")
    b = Hospital("HOSP-B", "Hospital B")
    sent = svc.send_biomedical_data(
        a, b, {"patient_id": "P1024"},
        channel_config=ChannelConfiguration.normal(),
        requested_key_bits=64, seed=7)
    check("E1.matched keys allow transmission",
          sent.packet is not None
          and sent.session.state == SessionState.DELIVERED)
    got = svc.receive_packet(sent.packet, sent.session)
    check("E1.receiver-key decrypt verifies",
          got.integrity_verified
          and got.delivered_payload.record == {"patient_id": "P1024"})
    # 2. Perturbed case: flip one receiver bit -> keys differ -> blocked.
    bad_qr = QKDRequest(requested_key_bits=64,
                        channel_configuration=ChannelConfiguration.normal(),
                        seed=7)
    r2 = eng.establish_key(bad_qr)
    tampered_recv = list(r2.receiver_key_material)
    tampered_recv[0] ^= 1  # simulate one unreconciled error
    from dataclasses import replace as _replace
    drifted = _replace(r2, receiver_key_material=tampered_recv)
    check("E2.mismatch detected, not equal",
          not drifted.endpoint_keys_match
          and drifted.sender_key_bytes != drifted.receiver_key_bytes)
    # Application must not silently use sender key for Hospital B: the
    # service derives Hospital B's AES key from the receiver endpoint
    # only, and _run_qkd parks mismatches in KEY_RECONCILIATION_REQUIRED.
    noisy = svc.send_biomedical_data(
        a, b, {"patient_id": "P1024"},
        channel_config=ChannelConfiguration.noisy(0.45),
        requested_key_bits=64, seed=11)
    if noisy.session.qkd_result.endpoint_keys_match:
        check("E2.noisy run happened to match; gate consistent",
              noisy.packet is not None)
    else:
        check("E2.mismatched keys never transmitted",
              noisy.packet is None
              and noisy.session.state
              == SessionState.KEY_RECONCILIATION_REQUIRED
              and "reconciliation" in
              (noisy.session.failure_reason or "").lower())
    # Direct guard: receive_packet takes NO key argument, so a caller
    # cannot smuggle the sender key in for Hospital B. Inspect the
    # unbound class method: `svc.receive_packet` is bound, so `self`
    # is already omitted from its signature.
    import inspect as _inspect
    params = list(_inspect.signature(
        SecureCommunicationService.receive_packet).parameters)
    check("E2.no sender-key parameter on receive",
          params == ["self", "packet", "session"]
          and not any("key" in p.lower() or "secret" in p.lower()
                      for p in params),
          f"({params})")
    # 3. Rejected/invalid material unusable: eve session + forced mismatch.
    eve = svc.send_biomedical_data(
        a, b, {"x": 1},
        channel_config=ChannelConfiguration.eavesdropped(),
        requested_key_bits=64, seed=23)
    check("E3.rejected material blocked",
          eve.packet is None
          and eve.session.state in (SessionState.QKD_REJECTED,
                                    SessionState.KEY_RECONCILIATION_REQUIRED))
    try:
        svc.receive_packet(eve.packet, eve.session)
        check("E3.rejected decrypt refused", False)
    except Exception:
        check("E3.rejected decrypt refused", True)


if __name__ == "__main__":
    for fn in (test_normal, test_noise, test_eve, test_qber_math,
               test_decisions, test_app_flow, test_states,
               test_endpoint_keys):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            check(fn.__name__, False, f"raised {exc!r}")
    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    raise SystemExit(1 if failed else 0)
