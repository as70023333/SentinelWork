"""Shared context handed to every agent."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..config import Settings
from ..connectors.base import (
    EDR,
    LLM,
    Blocklist,
    IdentityProvider,
    IncidentSource,
    Notifier,
    Sandbox,
    Telemetry,
    ThreatIntelProvider,
    UserInfo,
)
from ..connectors.demo import DemoWorld, MemoryNotifier
from ..models import Incident
from ..policy import Policy
from ..store import Store


@dataclass
class Connectors:
    siem: IncidentSource
    threat_intel: list[ThreatIntelProvider]
    telemetry: Telemetry
    edr: EDR
    blocklist: Blocklist
    identity: IdentityProvider
    sandbox: Optional[Sandbox]
    notifiers: list[Notifier]
    feed: MemoryNotifier
    llm: Optional[LLM] = None
    world: Optional[DemoWorld] = None     # only in demo mode


@dataclass
class AgentContext:
    incident: Incident
    policy: Policy
    settings: Settings
    connectors: Connectors
    store: Store
    user_infos: dict[str, UserInfo] = field(default_factory=dict)   # upn(lower) -> directory info
