"""Simulated environment for DEMO mode.

Nothing here touches a real system. The data lives in demo_data/*.json, is fictional
(RFC 5737 documentation IPs, made-up hashes and domains) and every threat-intel result
is flagged as simulated. The agents' decision logic is the real one.
"""
from __future__ import annotations

import asyncio
import json
import random
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from ..models import (
    Account,
    Entities,
    Host,
    Incident,
    Indicator,
    IndicatorType,
    Severity,
    TISourceResult,
    TIVerdict,
    short_id,
)
from .base import (
    AuditEvent,
    Blocklist,
    ConnectorError,
    EDR,
    HostActivity,
    IdentityProvider,
    IncidentSource,
    NetworkConnection,
    Notifier,
    Prevalence,
    ProcessEvent,
    Sandbox,
    SignIn,
    Telemetry,
    ThreatIntelProvider,
    UserActivity,
    UserInfo,
)
from .hunting import LiveTelemetry
from .notify import incident_facts

LATENCY = {
    "siem": (0.15, 0.35), "ti": (0.3, 1.2), "telemetry": (0.6, 1.8), "edr": (0.5, 1.1),
    "block": (0.3, 0.7), "identity": (0.4, 0.9), "sandbox": (4.0, 7.0),
}


def _ago(minutes: float) -> datetime:
    return datetime.now(timezone.utc) - timedelta(minutes=float(minutes))


class DemoWorld:
    """Holds demo data plus the simulated state of the environment (what is isolated/blocked)."""

    def __init__(self, data_dir: Path, latency: bool = True):
        self.data_dir = Path(data_dir)
        self.latency = latency
        self.ti: dict[str, list[dict[str, Any]]] = {
            k.lower(): v for k, v in self._load("threat_intel.json").items()}
        tel = self._load("telemetry.json")
        self.users = {k.lower(): v for k, v in tel.get("users", {}).items()}
        self.hosts = {k.lower(): v for k, v in tel.get("hosts", {}).items()}
        self.prevalence = {k.lower(): v for k, v in tel.get("prevalence", {}).items()}
        self.sandbox = {k.lower(): v for k, v in self._load("sandbox.json").items()}
        self.scenarios: dict[str, dict[str, Any]] = {}
        for f in sorted((self.data_dir / "scenarios").glob("*.json")):
            self.scenarios[f.stem] = json.loads(f.read_text(encoding="utf-8"))
        self.reset()

    def _load(self, name: str) -> dict[str, Any]:
        path = self.data_dir / name
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}

    def reset(self) -> None:
        self.isolated: dict[str, dict[str, Any]] = {}
        self.blocked: dict[str, dict[str, Any]] = {}
        self.disabled_users: dict[str, dict[str, Any]] = {}
        self.revoked_sessions: list[dict[str, Any]] = []
        self.scans: list[dict[str, Any]] = []
        self.siem_log: deque[dict[str, Any]] = deque(maxlen=50)

    async def delay(self, kind: str) -> None:
        if self.latency:
            lo, hi = LATENCY[kind]
            await asyncio.sleep(random.uniform(lo, hi))

    def state(self) -> dict[str, Any]:
        return {
            "isolated_hosts": list(self.isolated.values()),
            "blocked_indicators": list(self.blocked.values()),
            "disabled_users": list(self.disabled_users.values()),
            "revoked_sessions": self.revoked_sessions[-20:],
            "av_scans": self.scans[-20:],
            "siem_writeback": list(self.siem_log)[-20:],
        }

    def scenario_list(self) -> list[dict[str, Any]]:
        return [{"id": k, "name": v.get("name", k), "story": v.get("story", ""), "expected": v.get("expected", {})}
                for k, v in self.scenarios.items()]


# --------------------------------------------------------------------------- SIEM
class DemoIncidentSource(IncidentSource):
    def __init__(self, world: DemoWorld):
        self.world = world

    async def fetch(self, ref: str) -> Incident:
        sc = self.world.scenarios.get(ref)
        if not sc:
            raise ConnectorError(f"Unknown demo scenario {ref!r}. Available: {', '.join(self.world.scenarios)}")
        await self.world.delay("siem")
        spec = sc["incident"]
        ents = spec.get("entities", {})
        number = random.randint(1000, 9999)
        return Incident(
            source="demo",
            external_id=f"DEMO-{number}",
            title=spec["title"],
            description=spec.get("description", ""),
            provider_severity=Severity(spec.get("provider_severity", "medium")),
            product=spec.get("product"),
            tactics=spec.get("tactics", []),
            techniques=spec.get("techniques", []),
            entities=Entities(
                hosts=[Host(**h) for h in ents.get("hosts", [])],
                accounts=[Account(**a) for a in ents.get("accounts", [])],
                indicators=[Indicator(**i) for i in ents.get("indicators", [])]),
            raw={"scenario": ref, "incidentNumber": number},
        )

    async def list_new(self) -> list[str]:
        return []

    async def write_back(self, incident: Incident) -> None:
        await self.world.delay("siem")
        self.world.siem_log.append({
            "ts": datetime.now(timezone.utc).isoformat(), "incident": incident.external_id,
            "update": f"status={incident.status.value}, severity={incident.severity.value}, "
                      f"verdict={incident.verdict.value}, labels=soc-agent:{incident.disposition.value}"})

    async def add_comment(self, incident: Incident, markdown: str) -> None:
        await self.world.delay("siem")
        self.world.siem_log.append({"ts": datetime.now(timezone.utc).isoformat(),
                                    "incident": incident.external_id,
                                    "update": f"comment added: IR report v{incident.report_version} "
                                              f"({len(markdown)} chars)"})


# --------------------------------------------------------------------------- threat intel
class DemoThreatIntel(ThreatIntelProvider):
    def __init__(self, world: DemoWorld, name: str, supports: frozenset[IndicatorType]):
        self.world, self.name, self.supports = world, name, supports

    async def lookup(self, indicator: Indicator) -> Optional[TISourceResult]:
        await self.world.delay("ti")
        for entry in self.world.ti.get(indicator.value.lower(), []):
            if entry.get("source") == self.name:
                return TISourceResult(source=self.name, verdict=TIVerdict(entry["verdict"]),
                                      score=int(entry.get("score", 0)), summary=entry.get("summary", ""),
                                      malware_family=entry.get("malware_family"),
                                      reference=entry.get("reference"), simulated=True)
        return None


ALL_TYPES = frozenset(IndicatorType)
DEMO_TI_PROVIDERS: list[tuple[str, frozenset[IndicatorType]]] = [
    ("VirusTotal", ALL_TYPES),
    ("AbuseIPDB", frozenset({IndicatorType.IP})),
    ("AlienVault OTX", ALL_TYPES),
    ("GreyNoise", frozenset({IndicatorType.IP})),
    ("MalwareBazaar", frozenset({IndicatorType.FILE_HASH})),
    ("URLhaus", frozenset({IndicatorType.URL, IndicatorType.DOMAIN})),
    ("Microsoft Sentinel TI", ALL_TYPES),
]


# --------------------------------------------------------------------------- telemetry
class DemoTelemetry(Telemetry):
    def __init__(self, world: DemoWorld):
        self.world = world

    async def user_activity(self, account: Account, hours: int) -> UserActivity:
        await self.world.delay("telemetry")
        data = self.world.users.get(account.upn.lower(), {})
        out = UserActivity(queries=[LiveTelemetry.signin_kql(account.upn, hours),
                                    LiveTelemetry.audit_kql(account.upn, hours)])
        for s in data.get("signins", []):
            out.signins.append(SignIn(time=_ago(s["minutes_ago"]), ip=s["ip"], country=s.get("country", ""),
                                      city=s.get("city", ""), app=s.get("app", ""), success=s.get("success", True),
                                      result_code=s.get("result_code", "0"), failure_reason=s.get("failure_reason", ""),
                                      mfa_denied=s.get("mfa_denied", False), risk=s.get("risk", "none")))
        for a in data.get("audit", []):
            out.audit.append(AuditEvent(time=_ago(a["minutes_ago"]), operation=a["operation"],
                                        target=a.get("target", ""), detail=a.get("detail", "")))
        out.signins.sort(key=lambda s: s.time)
        return out

    async def host_activity(self, host: Host, hours: int) -> HostActivity:
        await self.world.delay("telemetry")
        data = self.world.hosts.get(host.hostname.split(".")[0].lower(), {})
        out = HostActivity(queries=[LiveTelemetry.process_kql(host.hostname, hours),
                                    LiveTelemetry.network_kql(host.hostname, hours)])
        for p in data.get("processes", []):
            out.processes.append(ProcessEvent(time=_ago(p["minutes_ago"]), process=p["process"],
                                              command_line=p.get("command_line", ""), parent=p.get("parent", ""),
                                              sha256=p.get("sha256", "").lower(), account=p.get("account", ""),
                                              signer=p.get("signer", "")))
        for c in data.get("connections", []):
            out.connections.append(NetworkConnection(remote_ip=c["remote_ip"], remote_port=c.get("remote_port", 0),
                                                     count=c.get("count", 1), remote_url=c.get("remote_url", ""),
                                                     process=c.get("process", "")))
        return out

    async def prevalence(self, indicators: list[Indicator], days: int) -> Prevalence:
        await self.world.delay("telemetry")
        out = Prevalence()
        q = LiveTelemetry.prevalence_kql(indicators, days)
        if q:
            out.queries.append(q)
        for ind in indicators:
            p = self.world.prevalence.get(ind.value.lower())
            if p:
                out.hosts_by_indicator[ind.value.lower()] = list(p.get("hosts", []))
                out.device_count_by_indicator[ind.value.lower()] = int(p.get("device_count", len(p.get("hosts", []))))
        return out


# --------------------------------------------------------------------------- containment
class DemoEDR(EDR):
    def __init__(self, world: DemoWorld):
        self.world = world
        self._actions: dict[str, str] = {}

    async def resolve_device(self, host: Host) -> Optional[str]:
        data = self.world.hosts.get(host.hostname.split(".")[0].lower())
        return host.device_id or (data or {}).get("device_id") or f"demo-{host.hostname.lower()}"

    def _hostname(self, device_id: str) -> str:
        for name, data in self.world.hosts.items():
            if data.get("device_id") == device_id:
                return name.upper()
        return device_id.removeprefix("demo-").upper()

    async def isolate(self, device_id: str, comment: str) -> str:
        await self.world.delay("edr")
        action_id = f"demo-ma-{short_id()}"
        self.world.isolated[device_id] = {"device_id": device_id, "host": self._hostname(device_id),
                                          "since": datetime.now(timezone.utc).isoformat(), "comment": comment}
        self._actions[action_id] = "Succeeded"
        return action_id

    async def release(self, device_id: str, comment: str) -> str:
        await self.world.delay("edr")
        self.world.isolated.pop(device_id, None)
        action_id = f"demo-ma-{short_id()}"
        self._actions[action_id] = "Succeeded"
        return action_id

    async def av_scan(self, device_id: str, comment: str) -> str:
        await self.world.delay("edr")
        action_id = f"demo-ma-{short_id()}"
        self.world.scans.append({"host": self._hostname(device_id), "type": "Quick",
                                 "ts": datetime.now(timezone.utc).isoformat()})
        self._actions[action_id] = "Succeeded"
        return action_id

    async def action_status(self, action_id: str) -> str:
        return self._actions.get(action_id, "Succeeded")


class DemoBlocklist(Blocklist):
    name = "Simulated firewall + EDR indicators"

    def __init__(self, world: DemoWorld):
        self.world = world

    async def block(self, indicator: Indicator, title: str, description: str, expires: datetime) -> str:
        await self.world.delay("block")
        ref = f"demo-block:{short_id()}"
        self.world.blocked[ref] = {"ref": ref, "type": indicator.type.value, "value": indicator.value,
                                   "expires": expires.isoformat(), "title": title}
        return ref

    async def unblock(self, ref: str) -> None:
        await self.world.delay("block")
        self.world.blocked.pop(ref, None)


class DemoIdentity(IdentityProvider):
    def __init__(self, world: DemoWorld):
        self.world = world

    async def lookup(self, account: Account) -> UserInfo:
        await self.world.delay("identity")
        info = self.world.users.get(account.upn.lower(), {}).get("info", {})
        return UserInfo(upn=account.upn, object_id=info.get("object_id"), display_name=info.get("display_name", ""),
                        enabled=account.upn.lower() not in self.world.disabled_users and info.get("enabled", True),
                        on_prem_synced=bool(info.get("on_prem_synced")), sam_account_name=info.get("sam_account_name"),
                        privileged_roles=list(info.get("privileged_roles", [])),
                        risk_level=info.get("risk_level", "none"))

    async def disable(self, account: Account, info: UserInfo, reason: str) -> str:
        await self.world.delay("identity")
        where = "on-prem AD (simulated)" if info.on_prem_synced else "Entra ID (simulated)"
        self.world.disabled_users[account.upn.lower()] = {"upn": account.upn, "directory": where,
                                                          "since": datetime.now(timezone.utc).isoformat()}
        return f"demo-user:{account.upn.lower()}"

    async def enable(self, account: Account, info: UserInfo, reason: str) -> str:
        await self.world.delay("identity")
        self.world.disabled_users.pop(account.upn.lower(), None)
        return f"demo-user:{account.upn.lower()}"

    async def revoke_sessions(self, account: Account, info: UserInfo) -> str:
        await self.world.delay("identity")
        self.world.revoked_sessions.append({"upn": account.upn, "ts": datetime.now(timezone.utc).isoformat()})
        return f"demo-revoke:{account.upn.lower()}"


class DemoSandbox(Sandbox):
    def __init__(self, world: DemoWorld):
        self.world = world

    async def analyze(self, indicator: Indicator) -> Optional[dict[str, Any]]:
        if indicator.type != IndicatorType.FILE_HASH:
            return None
        data = self.world.sandbox.get(indicator.value.lower())
        if not data:
            return None
        await self.world.delay("sandbox")
        return {**data, "hash": indicator.value, "simulated": True}


# --------------------------------------------------------------------------- notifications
class MemoryNotifier(Notifier):
    """Keeps the latest notifications in memory so the dashboard can show the 'pager' feed."""
    name = "dashboard feed"

    def __init__(self, maxlen: int = 100):
        self.items: deque[dict[str, Any]] = deque(maxlen=maxlen)

    async def send(self, incident: Incident, event: str) -> None:
        self.items.appendleft({
            "ts": datetime.now(timezone.utc).isoformat(), "event": event, "incident_id": incident.id,
            "title": incident.title, "severity": incident.severity.value,
            "disposition": incident.disposition.value, "summary": incident.executive_summary,
            "facts": incident_facts(incident)})
