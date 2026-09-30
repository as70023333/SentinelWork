"""IR policy engine and the Policy & Guardrail agent logic.

The policy file (config/ir_policy.yaml) is validated on load so that a typo fails
fast at startup instead of silently changing agent behaviour at 3 a.m.
"""
from __future__ import annotations

import fnmatch
import ipaddress
from pathlib import Path
from typing import Callable, Literal, Optional, Union

import yaml
from pydantic import BaseModel, Field, field_validator

from .models import (
    ActionStatus,
    ActionType,
    AlertClass,
    Disposition,
    Incident,
    Indicator,
    IndicatorType,
    Severity,
    Verdict,
)

AutonomyMode = Literal["autonomous", "approval", "recommend", "disabled"]
GateMode = Literal["deny", "approval", "recommend"]


# --------------------------------------------------------------------------- schema
class AutonomyCfg(BaseModel):
    enabled: bool = True
    actions: dict[ActionType, AutonomyMode] = Field(default_factory=dict)


class ThresholdsCfg(BaseModel):
    true_positive_score: int = 60
    false_positive_score: int = 25
    min_confidence_to_contain: float = 0.70
    indicator_malicious_score: int = 70
    indicator_suspicious_score: int = 30


class ScoringCfg(BaseModel):
    provider_severity_points: dict[Severity, int] = Field(
        default_factory=lambda: {Severity.CRITICAL: 20, Severity.HIGH: 15, Severity.MEDIUM: 10,
                                 Severity.LOW: 5, Severity.INFORMATIONAL: 0})
    threat_intel_weight: float = 0.6
    behavior_cap: int = 40
    identity_cap: int = 30
    lateral_spread_points: int = 15


def _default_severity_by_class() -> dict[AlertClass, Severity]:
    return {
        AlertClass.RANSOMWARE: Severity.CRITICAL, AlertClass.CREDENTIAL_ACCESS: Severity.HIGH,
        AlertClass.IDENTITY_COMPROMISE: Severity.HIGH, AlertClass.PHISHING: Severity.HIGH,
        AlertClass.LATERAL_MOVEMENT: Severity.HIGH, AlertClass.COMMAND_AND_CONTROL: Severity.HIGH,
        AlertClass.EXFILTRATION: Severity.HIGH, AlertClass.MALWARE: Severity.MEDIUM,
        AlertClass.BRUTE_FORCE: Severity.MEDIUM, AlertClass.SUSPICIOUS_ACTIVITY: Severity.LOW,
    }


class CriticalWhenCfg(BaseModel):
    lateral_spread: bool = True
    privileged_identity: bool = True
    protected_asset_bumps_one_level: bool = True


class BenignEvidenceCfg(BaseModel):
    trusted_signers: list[str] = Field(default_factory=list)
    common_software_min_devices: int = 25


class ClassRule(BaseModel):
    class_: AlertClass = Field(alias="class")
    keywords: list[str]

    @field_validator("keywords")
    @classmethod
    def _lower(cls, v: list[str]) -> list[str]:
        return [k.lower() for k in v]


ClassList = Union[Literal["all"], list[AlertClass]]


class ContainmentCfg(BaseModel):
    isolate_host: ClassList = Field(default_factory=list)
    av_scan: ClassList = Field(default_factory=list)
    block_hash: ClassList = "all"
    block_ip: ClassList = "all"
    block_domain: ClassList = "all"
    block_url: ClassList = "all"
    disable_user: ClassList = Field(default_factory=list)
    revoke_sessions: ClassList = Field(default_factory=list)
    related_hosts: Literal["autonomous", "approval", "recommend"] = "approval"

    def allows(self, action: ActionType, alert_class: AlertClass) -> bool:
        classes = getattr(self, action.value)
        return classes == "all" or alert_class in classes


class AllowlistCfg(BaseModel):
    ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)


class GuardrailsCfg(BaseModel):
    protected_hosts: list[str] = Field(default_factory=list)
    protected_host_action: GateMode = "deny"
    tier0_accounts: list[str] = Field(default_factory=list)
    tier0_account_action: GateMode = "approval"
    privileged_role_action: GateMode = "approval"
    internal_networks: list[str] = Field(default_factory=list)
    allowlist: AllowlistCfg = Field(default_factory=AllowlistCfg)
    rate_limits_per_hour: dict[ActionType, int] = Field(default_factory=dict)
    block_expiry_hours: int = 72

    @field_validator("internal_networks")
    @classmethod
    def _valid_networks(cls, v: list[str]) -> list[str]:
        for net in v:
            ipaddress.ip_network(net, strict=False)  # raises ValueError on typos
        return v


class EscalationWhen(BaseModel):
    severity: Optional[list[Severity]] = None
    verdict: Optional[list[Verdict]] = None
    alert_class: Optional[list[AlertClass]] = None
    protected_asset: Optional[bool] = None
    containment_incomplete: Optional[bool] = None

    model_config = {"extra": "forbid"}


class EscalationRule(BaseModel):
    name: str
    when: EscalationWhen = Field(default_factory=EscalationWhen)
    disposition: Disposition


class PolicyCfg(BaseModel):
    version: int = 1
    autonomy: AutonomyCfg = Field(default_factory=AutonomyCfg)
    thresholds: ThresholdsCfg = Field(default_factory=ThresholdsCfg)
    scoring: ScoringCfg = Field(default_factory=ScoringCfg)
    severity_by_class: dict[AlertClass, Severity] = Field(default_factory=_default_severity_by_class)
    critical_when: CriticalWhenCfg = Field(default_factory=CriticalWhenCfg)
    benign_evidence: BenignEvidenceCfg = Field(default_factory=BenignEvidenceCfg)
    classification: list[ClassRule] = Field(default_factory=list)
    containment: ContainmentCfg = Field(default_factory=ContainmentCfg)
    guardrails: GuardrailsCfg = Field(default_factory=GuardrailsCfg)
    escalation: list[EscalationRule]

    @field_validator("escalation")
    @classmethod
    def _has_default(cls, v: list[EscalationRule]) -> list[EscalationRule]:
        if not v:
            raise ValueError("escalation must contain at least one rule")
        return v


# --------------------------------------------------------------------------- engine
class GateDecision(BaseModel):
    status: ActionStatus
    note: str
    protected: bool = False     # True when a guardrail (not just autonomy mode) intervened


# Maps an ActionStatus produced by a gate mode.
_GATE_STATUS = {
    "deny": ActionStatus.DENIED_BY_POLICY,
    "approval": ActionStatus.PENDING_APPROVAL,
    "recommend": ActionStatus.RECOMMENDED,
}


class Policy:
    def __init__(self, cfg: PolicyCfg):
        self.cfg = cfg
        self._internal = [ipaddress.ip_network(n, strict=False) for n in cfg.guardrails.internal_networks]
        self._allow_ips = [ipaddress.ip_network(n, strict=False) for n in cfg.guardrails.allowlist.ips]

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return cls(PolicyCfg.model_validate(data))

    # ----------------------------------------------------------- classification
    def classify(self, incident: Incident, malware_families: list[str] | None = None) -> AlertClass:
        haystack = " ".join([
            incident.title, incident.description, " ".join(incident.tactics),
            " ".join(malware_families or []),
        ]).lower()
        for rule in self.cfg.classification:
            if any(k in haystack for k in rule.keywords):
                return rule.class_
        return AlertClass.SUSPICIOUS_ACTIVITY

    # ----------------------------------------------------------- asset checks
    @staticmethod
    def _glob_any(value: str, patterns: list[str]) -> Optional[str]:
        v = value.lower()
        for p in patterns:
            if fnmatch.fnmatchcase(v, p.lower()):
                return p
        return None

    def protected_host_pattern(self, hostname: str, fqdn: str | None = None) -> Optional[str]:
        for name in filter(None, [hostname, fqdn, hostname.split(".")[0] if hostname else None]):
            hit = self._glob_any(name, self.cfg.guardrails.protected_hosts)
            if hit:
                return hit
        return None

    def tier0_pattern(self, upn: str) -> Optional[str]:
        return self._glob_any(upn, self.cfg.guardrails.tier0_accounts)

    def is_internal_ip(self, value: str) -> bool:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return False
        return any(ip in net for net in self._internal)

    def is_allowlisted(self, ind: Indicator) -> bool:
        al = self.cfg.guardrails.allowlist
        v = ind.value.lower().strip()
        if ind.type == IndicatorType.IP:
            try:
                ip = ipaddress.ip_address(v)
            except ValueError:
                return False
            return any(ip in net for net in self._allow_ips)
        if ind.type == IndicatorType.FILE_HASH:
            return v in {h.lower() for h in al.hashes}
        if ind.type in (IndicatorType.DOMAIN, IndicatorType.URL):
            host = v
            if ind.type == IndicatorType.URL:
                from urllib.parse import urlparse
                host = (urlparse(v if "://" in v else f"http://{v}").hostname or "").lower()
            return any(host == d.lower() or host.endswith("." + d.lower()) for d in al.domains)
        return False

    # ----------------------------------------------------------- action gate
    def gate_action(
        self,
        action: ActionType,
        alert_class: AlertClass,
        *,
        target: str,
        verdict: Verdict,
        confidence: float,
        recent_count: Callable[[ActionType], int],
        protected_pattern: Optional[str] = None,
        protected_mode: Optional[GateMode] = None,
        is_related_host: bool = False,
    ) -> Optional[GateDecision]:
        """Decide what happens to a proposed action. ``None`` = don't propose it at all."""
        c = self.cfg
        mode: AutonomyMode = c.autonomy.actions.get(action, "recommend")
        if mode == "disabled" or not c.containment.allows(action, alert_class):
            return None
        if verdict in (Verdict.FALSE_POSITIVE, Verdict.BENIGN_POSITIVE, Verdict.PENDING):
            return None
        if verdict != Verdict.TRUE_POSITIVE:
            return GateDecision(status=ActionStatus.RECOMMENDED,
                                note=f"Verdict is {verdict.value}; containment is recommended, not executed.")

        # Guardrails that protect assets take precedence over everything else.
        if protected_pattern and protected_mode:
            return GateDecision(
                status=_GATE_STATUS[protected_mode], protected=True,
                note=f"Guardrail: '{target}' matches protected pattern '{protected_pattern}' "
                     f"(policy action: {protected_mode}).")

        if not c.autonomy.enabled:
            return GateDecision(status=ActionStatus.RECOMMENDED, note="Global autonomy switch is off.")
        if confidence < c.thresholds.min_confidence_to_contain:
            return GateDecision(
                status=ActionStatus.PENDING_APPROVAL,
                note=f"Confidence {confidence:.0%} is below the "
                     f"{c.thresholds.min_confidence_to_contain:.0%} autonomous-containment threshold.")
        if mode == "recommend":
            return GateDecision(status=ActionStatus.RECOMMENDED, note="Policy: recommend-only for this action.")
        if mode == "approval":
            return GateDecision(status=ActionStatus.PENDING_APPROVAL, note="Policy: human approval required.")
        if is_related_host and c.containment.related_hosts != "autonomous":
            return GateDecision(
                status=ActionStatus.PENDING_APPROVAL if c.containment.related_hosts == "approval"
                else ActionStatus.RECOMMENDED,
                note="Host was discovered by lateral-spread hunting, not named in the alert.")
        limit = c.guardrails.rate_limits_per_hour.get(action)
        if limit is not None and recent_count(action) >= limit:
            return GateDecision(
                status=ActionStatus.PENDING_APPROVAL, protected=True,
                note=f"Rate limit reached: {limit} autonomous '{action.value}' actions in the last hour.")
        return GateDecision(status=ActionStatus.PLANNED, note="Autonomous per IR policy.")

    # ----------------------------------------------------------- escalation
    def escalate(self, incident: Incident) -> tuple[Disposition, str]:
        protected = any(a.guardrail_hit for a in incident.actions)
        incomplete = any(a.status in {ActionStatus.PENDING_APPROVAL, ActionStatus.RECOMMENDED,
                                      ActionStatus.DENIED_BY_POLICY, ActionStatus.FAILED}
                         for a in incident.actions)
        for rule in self.cfg.escalation:
            w = rule.when
            if w.severity is not None and incident.severity not in w.severity:
                continue
            if w.verdict is not None and incident.verdict not in w.verdict:
                continue
            if w.alert_class is not None and incident.alert_class not in w.alert_class:
                continue
            if w.protected_asset is not None and protected != w.protected_asset:
                continue
            if w.containment_incomplete is not None and incomplete != w.containment_incomplete:
                continue
            return rule.disposition, rule.name
        return Disposition.QUEUE, "No escalation rule matched (default: queue)"
