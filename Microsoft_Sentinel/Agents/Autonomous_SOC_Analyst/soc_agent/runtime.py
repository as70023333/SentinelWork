"""Wires settings -> connectors -> orchestrator. The only place that knows demo vs. live."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

import httpx

from .agents.context import Connectors
from .config import Settings
from .connectors.base import Blocklist, IdentityProvider, Notifier, ThreatIntelProvider
from .connectors.demo import (
    DEMO_TI_PROVIDERS,
    DemoBlocklist,
    DemoEDR,
    DemoIdentity,
    DemoIncidentSource,
    DemoSandbox,
    DemoTelemetry,
    DemoThreatIntel,
    DemoWorld,
    MemoryNotifier,
)
from .connectors.http import AzureTokenProvider, make_client
from .connectors.llm import ClaudeLLM
from .connectors.notify import ConsoleNotifier, PagerNotifier, TeamsWorkflowNotifier, WebhookNotifier
from .orchestrator import Orchestrator
from .policy import Policy
from .store import Store

log = logging.getLogger("soc_agent.runtime")


@dataclass
class Runtime:
    settings: Settings
    policy: Policy
    store: Store
    connectors: Connectors
    orchestrator: Orchestrator
    client: httpx.AsyncClient

    async def aclose(self) -> None:
        await self.client.aclose()
        self.store.close()

    def describe(self) -> dict:
        c = self.connectors
        return {
            "mode": self.settings.mode,
            "incident_source": type(c.siem).__name__,
            "threat_intel": [p.name for p in c.threat_intel],
            "telemetry": type(c.telemetry).__name__,
            "edr": type(c.edr).__name__,
            "blocklist": c.blocklist.name,
            "identity": type(c.identity).__name__,
            "sandbox": type(c.sandbox).__name__ if c.sandbox else None,
            "notifiers": [n.name for n in c.notifiers],
            "llm": c.llm.name if c.llm else "template (set ANTHROPIC_API_KEY to enable Claude)",
            "fast_path_budget_seconds": self.settings.fast_path_budget_seconds,
            "autonomy_enabled": self.policy.cfg.autonomy.enabled,
        }


def _notifiers(settings: Settings, client: httpx.AsyncClient) -> list[Notifier]:
    out: list[Notifier] = [ConsoleNotifier()]
    if settings.teams_webhook_url:
        out.append(TeamsWorkflowNotifier(settings.teams_webhook_url, client, settings.public_url))
    if settings.generic_webhook_url:
        out.append(WebhookNotifier(settings.generic_webhook_url, client, settings.public_url))
    if settings.pager_webhook_url:
        out.append(PagerNotifier(settings.pager_webhook_url, client, settings.public_url))
    return out


def _llm(settings: Settings, client: httpx.AsyncClient) -> Optional[ClaudeLLM]:
    if settings.anthropic_api_key:
        return ClaudeLLM(settings.anthropic_api_key, settings.anthropic_model, client)
    return None


def build_demo(settings: Settings, client: httpx.AsyncClient) -> Connectors:
    world = DemoWorld(settings.demo_data_dir, latency=settings.demo_latency)
    return Connectors(
        siem=DemoIncidentSource(world),
        threat_intel=[DemoThreatIntel(world, n, t) for n, t in DEMO_TI_PROVIDERS],
        telemetry=DemoTelemetry(world),
        edr=DemoEDR(world),
        blocklist=DemoBlocklist(world),
        identity=DemoIdentity(world),
        sandbox=DemoSandbox(world),
        notifiers=_notifiers(settings, client),
        feed=MemoryNotifier(),
        llm=_llm(settings, client),
        world=world,
    )


def build_live(settings: Settings, client: httpx.AsyncClient) -> Connectors:
    # Imported here so demo mode never depends on live-only modules being configured.
    from .connectors.defender import DefenderEDR, DefenderIndicatorBlocklist
    from .connectors.firewall import CompositeBlocklist, WebhookFirewall
    from .connectors.hunting import GraphHunting, LiveTelemetry, LogAnalytics, TIFromSentinel
    from .connectors.identity import EntraIdentity, HybridIdentity, OnPremADIdentity
    from .connectors.sandbox import VirusTotalSandbox
    from .connectors.sentinel import SentinelIncidentSource
    from .connectors.threat_intel import (
        AbuseIPDB,
        AlienVaultOTX,
        GreyNoise,
        MalwareBazaar,
        SentinelThreatIntel,
        URLhaus,
        VirusTotal,
    )

    tokens = AzureTokenProvider(settings.azure_tenant_id, settings.azure_client_id, settings.azure_client_secret,
                                settings.use_managed_identity, client)
    la = LogAnalytics(tokens, settings.sentinel_workspace_id, client)

    ti: list[ThreatIntelProvider] = []
    if settings.ti_use_defender:
        ti.append(SentinelThreatIntel(TIFromSentinel(la)))
    if settings.virustotal_api_key:
        ti.append(VirusTotal(settings.virustotal_api_key, client))
    if settings.abuseipdb_api_key:
        ti.append(AbuseIPDB(settings.abuseipdb_api_key, client))
    if settings.otx_api_key:
        ti.append(AlienVaultOTX(settings.otx_api_key, client))
    if settings.greynoise_api_key:
        ti.append(GreyNoise(settings.greynoise_api_key, client))
    if settings.abusech_auth_key:
        ti.append(MalwareBazaar(settings.abusech_auth_key, client))
        ti.append(URLhaus(settings.abusech_auth_key, client))

    blocklists: list[Blocklist] = []
    if settings.firewall_backend in {"defender", "both"}:
        blocklists.append(DefenderIndicatorBlocklist(tokens, client))
    if settings.firewall_backend in {"webhook", "both"}:
        blocklists.append(WebhookFirewall(settings.firewall_webhook_url, settings.firewall_webhook_token, client))
    blocklist: Blocklist = blocklists[0] if len(blocklists) == 1 else CompositeBlocklist(blocklists)

    entra = EntraIdentity(tokens, client)
    identity: IdentityProvider
    if settings.identity_backend == "entra":
        identity = entra
    elif settings.identity_backend == "onprem":
        identity = OnPremADIdentity(settings.ad_automation_webhook_url, client, lookup_delegate=entra)
    else:
        identity = HybridIdentity(entra, OnPremADIdentity(settings.ad_automation_webhook_url, client,
                                                          lookup_delegate=entra))

    return Connectors(
        siem=SentinelIncidentSource(tokens, settings.sentinel_subscription_id, settings.sentinel_resource_group,
                                    settings.sentinel_workspace_name, client, settings.write_back_to_sentinel),
        threat_intel=ti,
        telemetry=LiveTelemetry(la, GraphHunting(tokens, client)),
        edr=DefenderEDR(tokens, client),
        blocklist=blocklist,
        identity=identity,
        sandbox=VirusTotalSandbox(settings.virustotal_api_key, client) if settings.virustotal_api_key else None,
        notifiers=_notifiers(settings, client),
        feed=MemoryNotifier(),
        llm=_llm(settings, client),
        world=None,
    )


def build_runtime(settings: Settings, store: Optional[Store] = None) -> Runtime:
    problems = settings.validate()
    if problems:
        raise SystemExit("Configuration problems:\n  - " + "\n  - ".join(problems))
    policy = Policy.load(settings.policy_path)
    store = store or Store(settings.db_path)
    client = make_client(timeout=15.0)
    connectors = build_live(settings, client) if settings.is_live else build_demo(settings, client)
    if not connectors.threat_intel:
        log.warning("No threat-intel providers configured: verdicts will rely on telemetry only")
    orch = Orchestrator(settings, policy, store, connectors)
    return Runtime(settings=settings, policy=policy, store=store, connectors=connectors,
                   orchestrator=orch, client=client)
