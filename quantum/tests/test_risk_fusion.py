"""Validation for quantum.qkd.risk_fusion (Combined Risk Score, MAX only).

Covers: QBER normalization, MAX fusion, bounds, monotonicity, None
handling, high-threat/low-QBER, low-threat/high-QBER, both-high, normal
low-risk, config validation, and SecurityController integration (the
display-only score must never change existing decisions).
"""

from quantum.qkd.risk_fusion import (
    FusionMethod,
    RiskFusionConfig,
    combined_risk,
    normalize_qber,
)
from quantum.qkd.security import (
    SecurityController,
    SecurityDecision,
    SecurityPolicy,
)

PASS, FAIL = "PASS", "FAIL"
results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    print(f"[{PASS if cond else FAIL}] {name} {detail}")


def approx(a, b, tol=1e-9):
    return a is not None and b is not None and abs(a - b) <= tol


def _raises(fn):
    try:
        fn()
        return False
    except (ValueError, NotImplementedError):
        return True


def test_normalize_qber():
    # Default QBER_REF derived from SecurityPolicy.monitor_threshold (0.10).
    cfg = RiskFusionConfig()
    check("N1.qber_ref derived from policy (no magic constant)",
          approx(cfg.qber_ref, SecurityPolicy().monitor_threshold),
          f"(qber_ref={cfg.qber_ref})")
    check("N2.scale points",
          approx(normalize_qber(0.00, cfg), 0.00)
          and approx(normalize_qber(0.03, cfg), 0.30)
          and approx(normalize_qber(0.064, cfg), 0.64)
          and approx(normalize_qber(0.10, cfg), 1.00)
          and approx(normalize_qber(0.25, cfg), 1.00),
          f"(0.03->{normalize_qber(0.03, cfg)}, 0.064->"
          f"{normalize_qber(0.064, cfg)})")
    check("N3.clip at 1.0 / None passthrough / negative raises",
          normalize_qber(9.9, cfg) == 1.0
          and normalize_qber(None, cfg) is None
          and _raises(lambda: normalize_qber(-0.01, cfg)))
    # Custom policy proves QBER_REF follows the policy object.
    custom = RiskFusionConfig(policy=SecurityPolicy(0.05, 0.20))
    check("N4.custom policy qber_ref respected",
          approx(custom.qber_ref, 0.20)
          and approx(normalize_qber(0.10, custom), 0.50))


def test_max_fusion():
    # M1: MAX semantics — worst sensor wins.
    check("M1.max semantics",
          approx(combined_risk(0.010, 0.90), 0.90)   # threat dominates
          and approx(combined_risk(0.240, 0.05), 1.00)  # qber clipped to 1
          and approx(combined_risk(0.05, 0.50), 0.50))
    grid_ok = all(
        combined_risk(q, t) is not None and 0.0 <= combined_risk(q, t) <= 1.0
        for q in (0.0, 0.03, 0.064, 0.10, 0.30)
        for t in (None, 0.0, 0.2, 0.5, 0.8, 1.0))
    check("M2.bounds in [0,1]", grid_ok)
    mono_q = all(combined_risk(q2, 0.5) >= combined_risk(q1, 0.5)
                 for q1, q2 in zip((0.0, 0.03, 0.064, 0.10),
                                   (0.03, 0.064, 0.10, 0.30)))
    mono_t = all(combined_risk(0.03, t2) >= combined_risk(0.03, t1)
                 for t1, t2 in zip((0.0, 0.2, 0.5), (0.2, 0.5, 0.9)))
    check("M3.monotone in qber and threat", mono_q and mono_t)


def test_none_handling():
    check("H1.qber None -> None even with threat",
          combined_risk(None, 0.9) is None)
    check("H2.threat None -> qber-normalized (QKD-only mode)",
          approx(combined_risk(0.05, None), 0.50)
          and approx(combined_risk(0.0, None), 0.00))
    check("H3.both None -> None", combined_risk(None, None) is None)
    check("H4.threat out of range raises",
          _raises(lambda: combined_risk(0.01, 9.0))
          and _raises(lambda: combined_risk(0.01, -1.0)))


def test_scenarios():
    # S1: high ML threat + low QBER -> threat dominates.
    check("S1.high threat + low QBER",
          approx(combined_risk(0.010, 0.82), 0.82),
          f"(qber_n={normalize_qber(0.010)})")
    # S2: low ML threat + high QBER -> QBER dominates (always bad).
    check("S2.low threat + high QBER",
          approx(combined_risk(0.240, 0.05), 1.00),
          f"(qber_n={normalize_qber(0.240)})")
    # S3: both high -> 1.0 (worst case visible).
    check("S3.both high", approx(combined_risk(0.240, 0.90), 1.00))
    # S4: normal low-risk -> low score.
    check("S4.normal low-risk",
          approx(combined_risk(0.0, 0.02), 0.02)
          and combined_risk(0.0, 0.02) < 0.30)


def test_config_and_method():
    check("C1.default method is MAX",
          RiskFusionConfig().method is FusionMethod.MAX)
    # Only MAX exists in the enum -> non-MAX cannot even be constructed.
    check("C2.only MAX method available (no noisy-OR/weighted)",
          [m.value for m in FusionMethod] == ["MAX"])
    check("C3.non-positive qber_ref rejected",
          _raises(lambda: RiskFusionConfig(
              policy=SecurityPolicy(0.0, 0.0)).qber_ref))


def test_controller_integration():
    """The display score must never change existing decisions."""
    c = SecurityController(SecurityPolicy(0.03, 0.10))
    # Semantics identical to the pre-existing test_decisions expectations.
    check("I1.decisions unchanged by fusion",
          c.evaluate(0.01).decision is SecurityDecision.ACCEPT
          and c.evaluate(0.07).decision is SecurityDecision.MONITOR
          and c.evaluate(0.30).decision is SecurityDecision.REJECT
          and c.evaluate(0.01, threat_score=0.9).decision
          is SecurityDecision.MONITOR)
    a = c.evaluate(0.064, threat_score=0.82)
    check("I2.combined attached to assessment",
          approx(a.combined_risk_score, 0.82)
          and approx(a.qber, 0.064) and approx(a.threat_score, 0.82),
          f"(combined={a.combined_risk_score})")
    # QKD-only (threat None) still gets a display score from QBER alone.
    a2 = c.evaluate(0.05)
    check("I3.QKD-only combined from qber",
          approx(a2.combined_risk_score, 0.50))
    # key_success failure: REJECT regardless; no quantum observation.
    a3 = c.evaluate(None, threat_score=0.0, key_success=False)
    check("I4.key failure still REJECT, no score",
          a3.decision is SecurityDecision.REJECT
          and a3.combined_risk_score is None)
    # Display score alone must never escalate or de-escalate a decision.
    a4 = c.evaluate(0.01, threat_score=0.50)
    check("I5.display score alone never escalates",
          a4.decision is SecurityDecision.ACCEPT
          and approx(a4.combined_risk_score, 0.50))


if __name__ == "__main__":
    for fn in (test_normalize_qber, test_max_fusion, test_none_handling,
               test_scenarios, test_config_and_method,
               test_controller_integration):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            check(fn.__name__, False, f"raised {exc!r}")
    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    raise SystemExit(1 if failed else 0)
