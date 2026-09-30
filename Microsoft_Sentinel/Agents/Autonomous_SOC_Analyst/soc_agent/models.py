"""Core data model for the Autonomous SOC Analyst.

Everything the agents produce is attached to a single ``Incident`` object, which is
persisted as JSON and rendered by the dashboard, the CLI and the IR report.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def short_id() -> str:
    return uuid.uuid4().hex[:12]


# --------------------------------------------------------------------------- enums
class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

    @property
    def rank(self) -> int:
        return {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class Status(str, Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    REMEDIATED = "remediated"
    CLOSED = "closed"


class Verdict(str, Enum):
    PENDING = "pending"
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN_POSITIVE = "benign_positive"
    UNDETERMINED = "undetermined"


class AlertClass(str, Enum):
    RANSOMWARE = "ransomware"
    MALWARE = "malware"
    CREDENTIAL_ACCESS = "credential_access"
    IDENTITY_COMPROMISE = "identity_compromise"
    PHISHING = "phishing"
    BRUTE_FORCE = "brute_force"
    LATERAL_MOVEMENT = "lateral_movement"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"


class Disposition(str, Enum):
    PENDING = "pending"
    PAGE = "page"            # wake someone up now
    QUEUE = "queue"          # handled in the normal work queue
    AUTO_CLOSE = "auto_close"


class IndicatorType(str, Enum):
    FILE_HASH = "file_hash"
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"


class TIVerdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"


class ActionType(str, Enum):
    ISOLATE_HOST = "isolate_host"
    AV_SCAN = "av_scan"
    BLOCK_IP = "block_ip"
    BLOCK_HASH = "block_hash"
    BLOCK_DOMAIN = "block_domain"
    BLOCK_URL = "block_url"
    DISABLE_USER = "disable_user"
    REVOKE_SESSIONS = "revoke_sessions"


class ActionStatus(str, Enum):
    PLANNED = "planned"
    EXECUTED = "executed"
    PENDING_APPROVAL = "pending_approval"
    RECOMMENDED = "recommended"        # autonomy off for this action: human must do it
    DENIED_BY_POLICY = "denied_by_policy"
    REJECTED = "rejected"              # a human rejected a pending approval
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


# --------------------------------------------------------------------------- entities
class Host(BaseModel):
    hostname: str
    fqdn: Optional[str] = None
    device_id: Optional[str] = None     # Defender for Endpoint machine id, when known
    os: Optional[str] = None


class Account(BaseModel):
    upn: str
    display_name: Optional[str] = None
    object_id: Optional[str] = None     # Entra ID object id, when known
    sam_account_name: Optional[str] = None
    on_prem_sid: Optional[str] = None


class Indicator(BaseModel):
    type: IndicatorType
    value: str
    context: Optional[str] = None       # e.g. file name for a hash

    @property
    def key(self) -> str:
        return f"{self.type.value}:{self.value.lower()}"


class Entities(BaseModel):
    hosts: list[Host] = Field(default_factory=list)
    accounts: list[Account] = Field(default_factory=list)
    indicators: list[Indicator] = Field(default_factory=list)

    def of_type(self, t: IndicatorType) -> list[Indicator]:
        return [i for i in self.indicators if i.type == t]


# --------------------------------------------------------------------------- findings
class TISourceResult(BaseModel):
    source: str
    verdict: TIVerdict
    score: int = 0                      # 0-100 maliciousness for this source
    summary: str = ""
    malware_family: Optional[str] = None
    reference: Optional[str] = None
    simulated: bool = False


class IndicatorReputation(BaseModel):
    indicator: Indicator
    verdict: TIVerdict = TIVerdict.UNKNOWN
    score: int = 0
    malware_family: Optional[str] = None
    sources: list[TISourceResult] = Field(default_factory=list)
    allowlisted: bool = False


class Signal(BaseModel):
    """A single suspicious (or exculpatory) observation from an investigation agent."""
    category: str                       # behavior | identity | spread | benign
    name: str
    detail: str = ""
    weight: int = 0


class AgentRun(BaseModel):
    agent: str
    started: datetime = Field(default_factory=utcnow)
    duration_ms: int = 0
    ok: bool = True
    error: Optional[str] = None
    summary: str = ""
    queries: list[str] = Field(default_factory=list)   # KQL / API calls used as evidence


class ResponseAction(BaseModel):
    id: str = Field(default_factory=short_id)
    type: ActionType
    target: str
    params: dict[str, Any] = Field(default_factory=dict)   # what the executor needs (host, indicator, account)
    status: ActionStatus = ActionStatus.PLANNED
    reason: str = ""
    policy_note: str = ""
    guardrail_hit: bool = False         # a guardrail (protected asset, tier-0, rate limit) gated it
    result: str = ""
    rollback_ref: Optional[str] = None
    created: datetime = Field(default_factory=utcnow)
    executed_at: Optional[datetime] = None
    decided_by: Optional[str] = None


class TimelineEvent(BaseModel):
    ts: datetime = Field(default_factory=utcnow)
    actor: str
    message: str


class Assessment(BaseModel):
    score: int = 0
    confidence: float = 0.0
    rationale: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- incident
class Incident(BaseModel):
    id: str = Field(default_factory=short_id)
    external_id: Optional[str] = None          # Sentinel incident number / ARM id
    arm_id: Optional[str] = None
    source: str = "demo"
    title: str
    description: str = ""
    provider_severity: Severity = Severity.MEDIUM
    product: Optional[str] = None
    tactics: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    created: datetime = Field(default_factory=utcnow)
    entities: Entities = Field(default_factory=Entities)
    raw: dict[str, Any] = Field(default_factory=dict)

    # --- agent flow state
    status: Status = Status.NEW
    severity: Severity = Severity.MEDIUM
    verdict: Verdict = Verdict.PENDING
    alert_class: AlertClass = AlertClass.SUSPICIOUS_ACTIVITY
    disposition: Disposition = Disposition.PENDING
    disposition_reason: str = ""
    assessment: Assessment = Field(default_factory=Assessment)

    # --- evidence
    reputations: list[IndicatorReputation] = Field(default_factory=list)
    signals: list[Signal] = Field(default_factory=list)
    related_hosts: list[str] = Field(default_factory=list)
    user_context: dict[str, Any] = Field(default_factory=dict)
    sandbox: Optional[dict[str, Any]] = None
    agent_runs: list[AgentRun] = Field(default_factory=list)

    # --- response
    actions: list[ResponseAction] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    executive_summary: str = ""
    report_markdown: str = ""
    report_version: int = 0
    report_generator: str = ""
    report_narrative: Optional[str] = None          # LLM narrative, kept so updates can re-render cheaply
    report_steps: Any = None                        # list[str] (template) or markdown str (LLM)

    # --- timings
    started_at: Optional[datetime] = None
    contained_at: Optional[datetime] = None
    fast_path_seconds: Optional[float] = None
    time_to_contain_seconds: Optional[float] = None

    def log(self, actor: str, message: str) -> None:
        self.timeline.append(TimelineEvent(actor=actor, message=message))

    def action(self, action_id: str) -> Optional[ResponseAction]:
        return next((a for a in self.actions if a.id == action_id), None)
