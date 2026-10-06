"""Validation: REAL ML → threat_score → quantum risk-fusion integration.

Covers the eight required cases:
 1. threat_score=None  -> existing QKD-only behaviour unchanged
 2. low threat + low QBER -> normal behaviour (ACCEPT)
 3. high threat + low QBER -> ML escalation (MONITOR via threat hook)
 4. low threat + high QBER -> QBER REJECT (fusion cannot rescue)
 5. high threat + high QBER -> REJECT
 6. endpoint-key mismatch -> communication blocked regardless of fusion
 7. invalid threat_score -> validation error
 8. existing suites (test_quantum, test_risk_fusion) run separately green

Plus the REAL ml_bridge interface: NSL-KDD feature columns imported from
predict.py, joblib artifact round-trip (toy pipeline = TEST FIXTURE, not
NSL-KDD training), missing-artifact handling, and the invariant that the
quantum runtime package has zero ML imports.
"""

from ml_bridge import (
    ModelUnavailableError,
    NSLKDDThreatScorer,
    SyntheticThreatScore,
    find_nsl_kdd_data,
    load_nsl_kdd_records,
    load_threat_model,
    nsl_kdd_feature_columns,
    try_load_scorer,
)
from quantum.application.secure_communication import (
    BiomedicalMessage,
    Hospital,
    SecureCommunicationService,
    SessionState,
)
from quantum.qkd.channel import ChannelConfiguration
from quantum.qkd.risk_fusion import normalize_qber
from quantum.qkd.security import (
    SecurityController,
    SecurityDecision,
    SecurityPolicy,
)
from quantum.scenarios.eve import run_eve_scenario
from quantum.scenarios.noise import run_noise_scenario
from quantum.scenarios.normal import run_normal_scenario

PASS, FAIL = "PASS", "FAIL"
results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    print(f"[{PASS if cond else FAIL}] {name} {detail}")


def approx(a, b, tol=1e-9):
    return a is not None and b is not None and abs(a - b) <= tol


def _raises(fn, exc_types=(ValueError, NotImplementedError)):
    try:
        fn()
        return False
    except exc_types:
        return True


def test_qkd_only_default():
    """Case 1: threat_score=None -> QKD-only behaviour, unchanged."""
    c = SecurityController(SecurityPolicy(0.03, 0.10))
    a = c.evaluate(0.01)
    check("T1.controller QKD-only unchanged",
          a.decision is SecurityDecision.ACCEPT
          and a.threat_score is None
          and approx(a.combined_risk_score, normalize_qber(0.01)),
          f"(combined={a.combined_risk_score})")
    r = run_normal_scenario(requested_key_bits=64, seed=7)
    check("T2.scenario default QKD-only",
          r.security_decision is SecurityDecision.ACCEPT
          and r.assessment.threat_score is None
          and approx(r.assessment.combined_risk_score, normalize_qber(r.qber)))
    svc = SecureCommunicationService()
    sent = svc.send_biomedical_data(
        Hospital("HA", "Hospital A"), Hospital("HB", "Hospital B"),
        {"patient_id": "P1"}, requested_key_bits=64, seed=7)
    check("T3.application default QKD-only delivers",
          sent.packet is not None
          and sent.assessment.threat_score is None
          and sent.session.state is SessionState.DELIVERED,
          f"(state={sent.session.state.value})")


def test_four_cases():
    """Cases 2-5 at the controller boundary (authoritative decisions)."""
    c = SecurityController(SecurityPolicy(0.03, 0.10))
    # CASE 1: low threat (0.05) + low QBER (0.01) -> ACCEPT, low combined.
    a1 = c.evaluate(0.01, threat_score=0.05)
    check("K1.low threat + low QBER -> ACCEPT",
          a1.decision is SecurityDecision.ACCEPT
          and approx(a1.combined_risk_score, 0.10),  # max(0.05, 0.01/0.10)
          f"(combined={a1.combined_risk_score})")
    # CASE 2: high threat (0.90) + low QBER -> threat hook escalates.
    a2 = c.evaluate(0.01, threat_score=0.90)
    check("K2.high threat + low QBER -> MONITOR",
          a2.decision is SecurityDecision.MONITOR
          and approx(a2.combined_risk_score, 0.90),
          f"(decision={a2.decision.value})")
    # CASE 3: low threat + high QBER (0.24) -> QBER REJECT, combined 1.0.
    a3 = c.evaluate(0.24, threat_score=0.05)
    check("K3.low threat + high QBER -> REJECT",
          a3.decision is SecurityDecision.REJECT
          and approx(a3.combined_risk_score, 1.0))
    # CASE 4: both high -> REJECT (worst sensor wins).
    a4 = c.evaluate(0.24, threat_score=0.90)
    check("K4.high threat + high QBER -> REJECT",
          a4.decision is SecurityDecision.REJECT
          and approx(a4.combined_risk_score, 1.0))


def test_scenario_wiring():
    """threat_score flows through the scenario layer into evaluate()."""
    r1 = run_normal_scenario(requested_key_bits=64, seed=7,
                             threat_score=0.90)
    check("W1.normal + hot ML -> MONITOR escalation",
          r1.security_decision is SecurityDecision.MONITOR
          and approx(r1.assessment.combined_risk_score, 0.90),
          f"(decision={r1.security_decision.value})")
    r2 = run_eve_scenario(requested_key_bits=64, seed=23, threat_score=0.05)
    check("W2.eve + cool ML -> REJECT (QBER wins)",
          r2.security_decision is SecurityDecision.REJECT
          and approx(r2.assessment.combined_risk_score, 1.0),
          f"(qber={r2.qber})")
    r3 = run_normal_scenario(requested_key_bits=64, seed=7,
                             threat_score=0.05)
    check("W3.normal + cool ML -> ACCEPT",
          r3.security_decision is SecurityDecision.ACCEPT
          and approx(r3.assessment.combined_risk_score,
                     max(0.05, normalize_qber(r3.qber))))
    r4 = run_noise_scenario(noise_probability=0.05, requested_key_bits=64,
                            seed=11, threat_score=0.90)
    check("W4.noise + hot ML never stays ACCEPT",
          r4.security_decision is not SecurityDecision.ACCEPT
          and r4.assessment.combined_risk_score >= 0.90,
          f"(decision={r4.security_decision.value}, "
          f"combined={r4.assessment.combined_risk_score})")


def test_application_layer():
    """Hospital A -> B path: fusion feeds display; gates stay supreme."""
    svc = SecureCommunicationService()
    a = Hospital("HA", "Hospital A")
    b = Hospital("HB", "Hospital B")
    # A1: real threat_score rides the full QKD -> encrypt -> deliver path.
    sent = svc.send_biomedical_data(
        a, b, BiomedicalMessage(record={"patient_id": "P9"}),
        requested_key_bits=64, seed=7, threat_score=0.05)
    check("A1.threat_score reaches assessment, delivery works",
          sent.packet is not None
          and approx(sent.assessment.threat_score, 0.05)
          and approx(sent.assessment.combined_risk_score,
                     max(0.05, normalize_qber(sent.session.qber))),
          f"(combined={sent.assessment.combined_risk_score})")
    # A6: endpoint-key mismatch blocks even with a BENIGN threat score
    # (fusion must never unblock the endpoint gate).
    blocked = svc.send_biomedical_data(
        a, b, {"patient_id": "P2"},
        channel_config=ChannelConfiguration.noisy(0.45),
        requested_key_bits=64, seed=11, threat_score=0.0)
    if blocked.session.qkd_result.endpoint_keys_match:
        check("A2.mismatch gate consistent (run matched)",
              blocked.packet is not None)
    else:
        check("A2.mismatch blocks despite benign threat",
              blocked.packet is None
              and blocked.session.state
              is SessionState.KEY_RECONCILIATION_REQUIRED,
              f"(state={blocked.session.state.value}, "
              f"combined={blocked.assessment.combined_risk_score})")
    # A3: QBER REJECT with cool ML cannot be rescued by fusion.
    eve = svc.send_biomedical_data(
        a, b, {"patient_id": "P3"},
        channel_config=ChannelConfiguration.eavesdropped(),
        requested_key_bits=64, seed=23, threat_score=0.0)
    check("A3.cool ML cannot rescue QBER REJECT",
          eve.packet is None
          and eve.assessment.decision is SecurityDecision.REJECT,
          f"(qber={eve.session.qber}, "
          f"state={eve.session.state.value})")
    try:
        svc.receive_packet(eve.packet, eve.session)
        refused = False
    except ValueError:
        refused = True
    check("A4.decrypt refused for rejected session", refused)


def test_validation():
    """Invalid threat_score fails fast, everywhere it can enter."""
    c = SecurityController()
    check("V1.out-of-range threat raises at controller",
          _raises(lambda: c.evaluate(0.01, threat_score=1.5))
          and _raises(lambda: c.evaluate(0.01, threat_score=-0.1)))
    check("V2.out-of-range threat raises in scenario",
          _raises(lambda: run_normal_scenario(threat_score=9.9)))
    svc = SecureCommunicationService()
    check("V3.out-of-range threat raises in application",
          _raises(lambda: svc.send_biomedical_data(
              Hospital("HA", "A"), Hospital("HB", "B"), {"id": "x"},
              requested_key_bits=64, seed=1, threat_score=1.5)))


def test_ml_bridge_interface():
    """REAL adapter mechanics; toy pipeline is a TEST FIXTURE, not NSL-KDD."""
    # B1: synthetic scores are explicitly labeled and range-validated.
    syn = SyntheticThreatScore(0.90)
    check("B1.synthetic clearly labeled + validated",
          approx(syn.score, 0.90) and "SYNTHETIC" in syn.source
          and _raises(lambda: SyntheticThreatScore(1.5))
          and _raises(lambda: SyntheticThreatScore(-0.1)))
    # B2: missing artifact -> loud error / graceful None, NEVER fake scores.
    check("B2.missing artifact raises; try_load_scorer degrades to None",
          _raises(lambda: load_threat_model("/nonexistent/model.joblib"),
                  (ModelUnavailableError,))
          and (try_load_scorer() is None
               or isinstance(try_load_scorer(), NSLKDDThreatScorer)))
    # B3: feature columns come from predict.py (single source of truth).
    try:
        cols = nsl_kdd_feature_columns()
    except ModelUnavailableError as exc:
        cols = None
        check("B3.41 NSL-KDD features imported from predict.py", True,
              f"SKIPPED — predict.py unavailable ({exc})")
    if cols is None:
        # B4/B5 need the real COLUMNS; skip them honestly (B6 below still
        # runs — it needs no ML repo).
        check("B4.joblib round-trip via adapter", True,
              "SKIPPED — feature columns unavailable")
        check("B5.missing feature rejected with ValueError", True,
              "SKIPPED — feature columns unavailable")
    else:
        check("B3.41 NSL-KDD features imported from predict.py",
              len(cols) == 41 and "label" not in cols
              and "difficulty" not in cols, f"(n={len(cols)})")
        # B4/B5: REAL joblib round-trip through the adapter.
        try:
            import os
            import tempfile

            import joblib
            import pandas as pd
            from sklearn.compose import ColumnTransformer
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.pipeline import Pipeline
            from sklearn.preprocessing import OneHotEncoder

            cats = ["protocol_type", "service", "flag"]
            nums = [c for c in cols if c not in cats]
            rows = []
            labels = []
            for i in range(32):
                row = {c: 0.0 for c in cols}
                row["protocol_type"] = ["tcp", "udp", "icmp"][i % 3]
                row["service"] = ["http", "ftp", "smtp", "dns"][i % 4]
                row["flag"] = ["SF", "REJ", "S0"][i % 3]
                row["src_bytes"] = float((i * 137) % 900)
                row["count"] = float(i % 20)
                rows.append(row)
                labels.append(int(row["src_bytes"] > 450))
            frame = pd.DataFrame(rows, columns=cols)
            pipe = Pipeline([
                ("preprocessor", ColumnTransformer([
                    ("categorical", OneHotEncoder(handle_unknown="ignore"),
                     cats),
                    ("numerical", "passthrough", nums)])),
                ("classifier",
                 RandomForestClassifier(n_estimators=10, random_state=42)),
            ])
            pipe.fit(frame, labels)
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "toy_model.joblib")
                joblib.dump(pipe, path)
                scorer = NSLKDDThreatScorer(joblib.load(path), path,
                                            feature_columns=cols)
                score = scorer.score_record(rows[0])
                partial = {k: rows[0][k] for k in cols[:-3]}
                try:
                    scorer.score_record(partial)
                    missing_ok = False
                except ValueError:
                    missing_ok = True
            check("B4.joblib round-trip via adapter -> float in [0,1]",
                  isinstance(score, float) and 0.0 <= score <= 1.0
                  and "toy_model.joblib" in scorer.threat_score_source,
                  f"(score={score:.4f}; TEST FIXTURE, not NSL-KDD)")
            check("B5.missing feature rejected with ValueError", missing_ok)
        except ImportError as exc:
            check("B4.joblib round-trip via adapter", True,
                  f"SKIPPED, ML deps unavailable ({exc})")
            check("B5.missing feature rejected with ValueError", True,
                  "SKIPPED, ML deps unavailable")
    # B6: quantum CORE (qkd/application/scenarios) has zero ML coupling.
    import pathlib

    qroot = pathlib.Path(__file__).resolve().parents[1]
    offenders = []
    needles = ("import ml_bridge", "from ml_bridge", "import joblib",
               "import sklearn", "from sklearn", "predict_proba")
    for sub in ("qkd", "application", "scenarios"):
        for p in sorted((qroot / sub).rglob("*.py")):
            src = p.read_text(encoding="utf-8")
            for needle in needles:
                if needle in src:
                    offenders.append(f"{p.name}:{needle}")
    check("B6.quantum core free of ML imports", not offenders,
          str(offenders))


def test_real_artifact_smoke():
    """Phase 4 smoke: exercise the REAL model.joblib when it exists.

    Skips (honestly, as a passing SKIP) when no trained artifact is
    present — the deterministic checks above must stay runnable without
    the dataset or model.
    """
    scorer = try_load_scorer()
    if scorer is None:
        check("R1.real NSL-KDD artifact smoke", True,
              "SKIPPED — REAL NSL-KDD MODEL: UNAVAILABLE (no model.joblib; "
              "needs verified KDDTrain+.txt / KDDTest+.txt)")
        return
    # Artifact present: structural checks + real end-to-end record scoring.
    model, path = load_threat_model()
    try:
        from sklearn.pipeline import Pipeline

        step_names = [n for n, _ in getattr(model, "steps", [])]
        check("R1.real artifact is sklearn Pipeline "
              "(preprocessor + classifier)",
              isinstance(model, Pipeline)
              and hasattr(model, "predict_proba")
              and step_names == ["preprocessor", "classifier"],
              f"(path={path}, steps={step_names})")
    except ImportError as exc:
        check("R1.real artifact smoke", False, f"sklearn missing: {exc}")
        return
    # Score a real record only if genuine NSL-KDD test data is available
    # (located via ml_bridge.find_nsl_kdd_data — honest SKIP if absent).
    found = find_nsl_kdd_data("KDDTest+.txt")
    dataset = None if found is None else str(found)
    if dataset is None:
        check("R2.real NSL-KDD record scoring", True,
              "SKIPPED — no verified KDDTest+.txt found for record input")
        return
    import pandas as pd

    from ml_bridge.threat_source import _predict_columns

    all_cols = _predict_columns()
    df = pd.read_csv(dataset, header=None, names=all_cols, nrows=1)
    record = {c: df.iloc[0][c]
              for c in nsl_kdd_feature_columns()}
    score = scorer.score_record(record)
    check("R2.real NSL-KDD record scoring",
          isinstance(score, float) and 0.0 <= score <= 1.0,
          f"(ML Threat Score={score:.4f} from {dataset} — REAL NSL-KDD MODEL, "
          "uncalibrated)")


def test_real_end_to_end():
    """Phase 5: REAL artifact path NSL-KDD -> threat_score -> SecurityController
    -> combined risk -> decision, using genuine KDDTest+.txt records.

    Deterministic (fixed artifact random_state=42, fixed dataset, fixed
    scenario seeds). Skips honestly as SKIP when the trained artifact or
    the genuine test data are unavailable — never fabricates either.
    """
    scorer = try_load_scorer()
    if scorer is None:
        check("R3a.real artifact loads", True,
              "SKIPPED — no real model artifact; nothing real to prove")
        return
    check("R3a.real artifact loads", True,
          f"(artifact={scorer.model_path})")
    found = find_nsl_kdd_data("KDDTest+.txt")
    if found is None:
        check("R3b.genuine KDDTest+.txt located", True,
              "SKIPPED — no verified NSL-KDD test data; nothing real to score")
        return
    check("R3b.genuine KDDTest+.txt located", True, f"({found})")

    # Real records -> real scores through the adapter. NO duplicated
    # preprocessing: score_record uses the Pipeline inside model.joblib.
    records = load_nsl_kdd_records(found, limit=500)
    scored = [(scorer.score_record(rec), i, rec)
              for i, rec in enumerate(records)]
    low, high = min(scored), max(scored)
    check("R4.low/high real threat scores separated",
          0.0 <= low[0] < high[0] <= 1.0
          and high[0] - low[0] > 0.5,
          f"(low={low[0]:.4f}@row {low[1]}, label={low[2].get('label')}; "
          f"high={high[0]:.4f}@row {high[1]}, label={high[2].get('label')})")

    # Controller-level E2E: real scores + real QKD QBER values.
    controller = SecurityController()
    a1 = controller.evaluate(0.01, threat_score=low[0])
    check("R5.low real score + clean QBER -> ACCEPT",
          a1.decision is SecurityDecision.ACCEPT
          and approx(a1.threat_score, low[0])
          and approx(a1.combined_risk_score,
                     max(low[0], normalize_qber(0.01))),
          f"(score={low[0]:.4f}, combined={a1.combined_risk_score})")
    a2 = controller.evaluate(0.01, threat_score=high[0])
    check("R6.high real score + clean QBER -> MONITOR escalation",
          a2.decision is SecurityDecision.MONITOR
          and approx(a2.combined_risk_score,
                     max(high[0], normalize_qber(0.01))),
          f"(score={high[0]:.4f}, decision={a2.decision.value})")

    # Scenario-level E2E: simulated QKD conditions + REAL threat scores.
    r1 = run_normal_scenario(requested_key_bits=64, seed=7,
                             threat_score=high[0])
    check("R7.clean QKD + high real score -> MONITOR",
          r1.security_decision is SecurityDecision.MONITOR
          and approx(r1.assessment.combined_risk_score,
                     max(high[0], normalize_qber(r1.qber))),
          f"(score={high[0]:.4f}, qber={r1.qber})")
    r2 = run_eve_scenario(requested_key_bits=64, seed=23,
                          threat_score=low[0])
    check("R8.eve QKD + low real score -> REJECT (QBER wins; real score "
          "cannot rescue)",
          r2.security_decision is SecurityDecision.REJECT
          and approx(r2.assessment.combined_risk_score, 1.0),
          f"(score={low[0]:.4f}, qber={r2.qber})")


if __name__ == "__main__":  # pragma: no cover
    for fn in (test_qkd_only_default, test_four_cases, test_scenario_wiring,
               test_application_layer, test_validation,
               test_ml_bridge_interface, test_real_artifact_smoke,
               test_real_end_to_end):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            check(fn.__name__, False, f"raised {exc!r}")
    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    raise SystemExit(1 if failed else 0)



