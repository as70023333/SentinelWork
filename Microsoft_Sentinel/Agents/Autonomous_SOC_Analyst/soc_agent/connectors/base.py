"""Connector interfaces.

Every external system sits behind one of these small interfaces. Each has a LIVE
implementation (real Microsoft / threat-intel APIs) and a DEMO implementation
(simulated, offline). The agents only ever talk to the interfaces, so the exact
same investigation and decision logic runs in both modes.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from ..models import Account, Host, Incident, Indicator, IndicatorType, TISourceResult


class ConnectorError(RuntimeError):
    """Raised by connectors for any failure talking to an external system."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


# --------------------------------------------------------------------------- normalized telemetry
@dataclass
class SignIn:
    time: datetime
    ip: str
    country: str = ""
    city: str = ""
    app: str = ""
    success: bool = True
    result_code: str = "0"
    failure_reason: str = ""
    mfa_denied: bool = False
    risk: str = "none"


@dataclass
class AuditEvent:
    time: datetime
    operation: str
    target: str = ""
    detail: str = ""


@dataclass
class ProcessEvent:
    time: datetime
    process: str
    command_line: str = ""
    parent: str = ""
    sha256: str = ""
    account: str = ""
    signer: str = ""


@dataclass
class NetworkConnection:
    remote_ip: str
    remote_port: int = 0
    count: int = 1
    remote_url: str = ""
    process: str = ""


@dataclass
class UserActivity:
    signins: list[SignIn] = field(default_factory=list)
    audit: list[AuditEvent] = field(default_factory=list)
    queries: list[str] = field(default_factory=list)


@dataclass
class HostActivity:
    processes: list[ProcessEvent] = field(default_factory=list)
    connections: list[NetworkConnection] = field(default_factory=list)
    queries: list[str] = field(default_factory=list)


@dataclass
class Prevalence:
    hosts_by_indicator: dict[str, list[str]] = field(default_factory=dict)   # indicator value -> hosts
    device_count_by_indicator: dict[str, int] = field(default_factory=dict)
    queries: list[str] = field(default_factory=list)


@dataclass
class UserInfo:
    upn: str
    object_id: Optional[str] = None
    display_name: str = ""
    enabled: Optional[bool] = None
    on_prem_synced: bool = False
    sam_account_name: Optional[str] = None
    privileged_roles: list[str] = field(default_factory=list)
    risk_level: str = "none"


# --------------------------------------------------------------------------- interfaces
class IncidentSource(ABC):
    @abstractmethod
    async def fetch(self, ref: str) -> Incident:
        """Load an incident by reference (Sentinel ARM id or incident name/GUID)."""

    @abstractmethod
    async def list_new(self) -> list[str]:
        """References of incidents in status New (for polling mode)."""

    @abstractmethod
    async def write_back(self, incident: Incident) -> None:
        """Push status / severity / classification / labels back to the SIEM."""

    @abstractmethod
    async def add_comment(self, incident: Incident, markdown: str) -> None:
        """Attach a comment (the IR report) to the SIEM incident."""


class ThreatIntelProvider(ABC):
    name: str = "provider"
    supports: frozenset[IndicatorType] = frozenset()

    @abstractmethod
    async def lookup(self, indicator: Indicator) -> Optional[TISourceResult]:
        """Return a result, or None when the provider has no data for this indicator."""


class Telemetry(ABC):
    @abstractmethod
    async def user_activity(self, account: Account, hours: int) -> UserActivity: ...

    @abstractmethod
    async def host_activity(self, host: Host, hours: int) -> HostActivity: ...

    @abstractmethod
    async def prevalence(self, indicators: list[Indicator], days: int) -> Prevalence: ...


class EDR(ABC):
    @abstractmethod
    async def resolve_device(self, host: Host) -> Optional[str]: ...

    @abstractmethod
    async def isolate(self, device_id: str, comment: str) -> str:
        """Return the machine-action id."""

    @abstractmethod
    async def release(self, device_id: str, comment: str) -> str: ...

    @abstractmethod
    async def av_scan(self, device_id: str, comment: str) -> str: ...

    @abstractmethod
    async def action_status(self, action_id: str) -> str:
        """Pending | InProgress | Succeeded | Failed | TimeOut | Cancelled"""


class Blocklist(ABC):
    name: str = "blocklist"

    @abstractmethod
    async def block(self, indicator: Indicator, title: str, description: str, expires: datetime) -> str:
        """Return a reference used for rollback."""

    @abstractmethod
    async def unblock(self, ref: str) -> None: ...


class IdentityProvider(ABC):
    @abstractmethod
    async def lookup(self, account: Account) -> UserInfo: ...

    @abstractmethod
    async def disable(self, account: Account, info: UserInfo, reason: str) -> str: ...

    @abstractmethod
    async def enable(self, account: Account, info: UserInfo, reason: str) -> str: ...

    @abstractmethod
    async def revoke_sessions(self, account: Account, info: UserInfo) -> str: ...


class Sandbox(ABC):
    @abstractmethod
    async def analyze(self, indicator: Indicator) -> Optional[dict[str, Any]]:
        """Behavioral analysis for a file hash, or None if nothing is available."""


class Notifier(ABC):
    name: str = "notifier"

    @abstractmethod
    async def send(self, incident: Incident, event: str) -> None:
        """event: 'report' (first report), 'update' (report revised), 'page' (wake someone)."""


class LLM(ABC):
    name: str = "llm"

    @abstractmethod
    async def complete(self, system: str, prompt: str, max_tokens: int = 1500) -> str: ...
