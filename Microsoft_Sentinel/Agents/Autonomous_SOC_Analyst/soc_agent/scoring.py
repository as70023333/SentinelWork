"""Triage math: turns agent evidence into score, verdict, confidence, severity and class.

Deliberately deterministic. The LLM writes the narrative report, but it never decides
the verdict or whether containment happens. That keeps decisions explainable,
testable, and immune to prompt injection hidden in attacker-controlled data.
"""
from __future__ import annotations

from .models import (
    AlertClass,
    Incident,
    IndicatorReputation,
    Severity,
    TISourceResult,
    TIVerdict,
    Verdict,
)
from .policy import Policy


def aggregate_reputation(rep: IndicatorReputation, policy: Policy) -> IndicatorReputation:
    """Combine per-source results for one indicator into a single score and verdict."""
    th = policy.cfg.thresholds
    if rep.allowlisted:
        rep.verdict, rep.score = TIVerdict.CLEAN, 0
        return rep
    scored: list[TISourceResult] = [s for s in rep.sources if s.verdict != TIVerdict.UNKNOWN]
    if not scored:
        rep.verdict, rep.score = TIVerdict.UNKNOWN, 0
        return rep
    malicious = [s for s in scored if s.verdict == TIVerdict.MALICIOUS]
    # Worst credible source dominates, and agreement between sources adds confidence.
    top = max(s.score for s in scored)
    agreement_bonus = 5 * max(0, len(malicious) - 1)
    rep.score = min(100, top + agreement_bonus)
    if rep.score >= th.indicator_malicious_score:
        rep.verdict = TIVerdict.MALICIOUS
    elif rep.score >= th.indicator_suspicious_score:
        rep.verdict = TIVerdict.SUSPICIOUS
    else:
        rep.verdict = TIVerdict.CLEAN
    families = [s.malware_family for s in scored if s.malware_family]
    if families and not rep.malware_family:
        rep.malware_family = max(set(families), key=families.count)
    return rep


def assess(incident: Incident, policy: Policy) -> None:
    """Populate assessment, verdict, severity and alert_class on the incident in place."""
    cfg = policy.cfg
    th, sc = cfg.thresholds, cfg.scoring
    rationale: list[str] = []

    reps = [r for r in incident.reputations if not r.allowlisted]
    malicious = [r for r in reps if r.verdict == TIVerdict.MALICIOUS]
    clean = [r for r in incident.reputations if r.verdict == TIVerdict.CLEAN]
    ti_max = max((r.score for r in reps), default=0)
    ti_points = round(ti_max * sc.threat_intel_weight)
    if ti_max:
        worst = max(reps, key=lambda r: r.score)
        rationale.append(f"Threat intel: worst indicator {worst.indicator.value} scored {worst.score}/100 "
                         f"({worst.verdict.value}) -> +{ti_points}")

    behavior = [s for s in incident.signals if s.category == "behavior"]
    identity = [s for s in incident.signals if s.category == "identity"]
    benign = [s for s in incident.signals if s.category == "benign"]
    behavior_pts = min(sc.behavior_cap, sum(s.weight for s in behavior))
    identity_pts = min(sc.identity_cap, sum(s.weight for s in identity))
    benign_pts = sum(s.weight for s in benign)  # weights are negative
    spread_pts = sc.lateral_spread_points if incident.related_hosts else 0
    base_pts = sc.provider_severity_points.get(incident.provider_severity, 0)

    if behavior_pts:
        rationale.append(f"Endpoint behavior: {', '.join(s.name for s in behavior)} -> +{behavior_pts}")
    if identity_pts:
        rationale.append(f"Identity signals: {', '.join(s.name for s in identity)} -> +{identity_pts}")
    if spread_pts:
        rationale.append(f"Lateral spread: indicator also seen on {', '.join(incident.related_hosts)} "
                         f"-> +{spread_pts}")
    if benign_pts:
        rationale.append(f"Exculpatory evidence: {', '.join(s.name for s in benign)} -> {benign_pts}")
    rationale.append(f"Provider severity {incident.provider_severity.value} -> +{base_pts}")

    score = max(0, min(100, ti_points + behavior_pts + identity_pts + spread_pts + benign_pts + base_pts))

    corroborating = sum([bool(malicious), bool(behavior_pts), bool(identity_pts), bool(spread_pts)])
    multi_source = any(sum(1 for s in r.sources if s.verdict == TIVerdict.MALICIOUS) >= 2 for r in malicious)
    clean_sources = sum(sum(1 for s in r.sources if s.verdict == TIVerdict.CLEAN) for r in clean)

    # ---- verdict
    if score >= th.true_positive_score and corroborating >= 1:
        verdict = Verdict.TRUE_POSITIVE
        confidence = min(0.97, 0.50 + 0.12 * corroborating + (0.10 if multi_source else 0.0))
    elif score <= th.false_positive_score and not malicious and (benign or clean_sources >= 2):
        verdict = Verdict.FALSE_POSITIVE
        confidence = 0.92 if (benign and clean_sources >= 2) else 0.80
    else:
        verdict = Verdict.UNDETERMINED
        confidence = 0.45 if corroborating else 0.35

    # ---- class (uses malware families from threat intel as extra keywords)
    families = [r.malware_family for r in incident.reputations if r.malware_family]
    alert_class = policy.classify(incident, families)

    # ---- severity = impact (class baseline + escalators), not confidence
    order = [Severity.INFORMATIONAL, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    baseline = cfg.severity_by_class.get(alert_class, Severity.MEDIUM)
    protected_host = next((h.hostname for h in incident.entities.hosts
                           if policy.protected_host_pattern(h.hostname, h.fqdn)), None)
    if verdict == Verdict.FALSE_POSITIVE:
        severity = Severity.LOW
    elif verdict == Verdict.TRUE_POSITIVE:
        severity = baseline
        rationale.append(f"Severity baseline for confirmed {alert_class.value}: {baseline.value}")
        cw = cfg.critical_when
        if cw.lateral_spread and incident.related_hosts and severity != Severity.CRITICAL:
            severity = Severity.CRITICAL
            rationale.append("Policy: confirmed threat on multiple hosts is critical")
        if cw.privileged_identity and incident.user_context.get("privileged") and severity != Severity.CRITICAL:
            severity = Severity.CRITICAL
            rationale.append("Policy: confirmed threat involving a privileged identity is critical")
        if cw.protected_asset_bumps_one_level and protected_host and severity != Severity.CRITICAL:
            severity = order[min(len(order) - 1, order.index(severity) + 1)]
            rationale.append(f"Policy: protected asset {protected_host} raises severity to {severity.value}")
    else:
        # not confirmed: never louder than what the detection itself claimed
        severity = min(baseline, incident.provider_severity, key=lambda s: s.rank)
        if severity == Severity.INFORMATIONAL:
            severity = Severity.LOW

    incident.assessment.score = score
    incident.assessment.confidence = round(confidence, 2)
    incident.assessment.rationale = rationale
    incident.verdict = verdict
    incident.severity = severity
    incident.alert_class = alert_class if alert_class else AlertClass.SUSPICIOUS_ACTIVITY
