"""Live telemetry: Log Analytics (Sentinel workspace) KQL + Defender XDR advanced hunting (Graph).

Every query that is run is returned alongside its results so the IR report can show
exactly what evidence the agent looked at, and an analyst can re-run it.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from ..models import Account, Host, Indicator, IndicatorType
from .base import (
    AuditEvent,
    ConnectorError,
    HostActivity,
    NetworkConnection,
    Prevalence,
    ProcessEvent,
    SignIn,
    Telemetry,
    UserActivity,
)
from .http import AzureTokenProvider, is_hash, kql_string, request_json, require_hostname, require_upn

LA_SCOPE = "https://api.loganalytics.io/.default"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"


def _dt(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return datetime.now(timezone.utc)


class LogAnalytics:
    def __init__(self, tokens: AzureTokenProvider, workspace_id: str, client: httpx.AsyncClient):
        self.tokens, self.workspace_id, self.client = tokens, workspace_id, client

    async def query(self, kql: str, timespan: str = "P7D") -> list[dict[str, Any]]:
        url = f"https://api.loganalytics.io/v1/workspaces/{self.workspace_id}/query"
        data = await request_json(self.client, "POST", url, headers=await self.tokens.headers(LA_SCOPE),
                                  json={"query": kql, "timespan": timespan}) or {}
        tables = data.get("tables") or []
        if not tables:
            return []
        cols = [c["name"] for c in tables[0].get("columns", [])]
        return [dict(zip(cols, row)) for row in tables[0].get("rows", [])]


class DefenderHunting:
    async def query(self, kql: str) -> list[dict[str, Any]]:  # pragma: no cover - interface
        raise NotImplementedError


class GraphHunting(DefenderHunting):
    """Defender XDR advanced hunting through Microsoft Graph (security/runHuntingQuery)."""

    def __init__(self, tokens: AzureTokenProvider, client: httpx.AsyncClient):
        self.tokens, self.client = tokens, client

    async def query(self, kql: str) -> list[dict[str, Any]]:
        data = await request_json(self.client, "POST", "https://graph.microsoft.com/v1.0/security/runHuntingQuery",
                                  headers=await self.tokens.headers(GRAPH_SCOPE), json={"Query": kql}) or {}
        return list(data.get("results") or [])


class LiveTelemetry(Telemetry):
    def __init__(self, la: LogAnalytics, hunting: DefenderHunting):
        self.la, self.hunting = la, hunting

    # ----------------------------------------------------------- queries (public for tests/docs)
    @staticmethod
    def signin_kql(upn: str, hours: int) -> str:
        u = kql_string(require_upn(upn))
        return f"""SigninLogs
| where TimeGenerated > ago({int(hours)}h)
| where UserPrincipalName =~ {u}
| project TimeGenerated, IPAddress, Country = tostring(LocationDetails.countryOrRegion),
          City = tostring(LocationDetails.city), AppDisplayName, ResultType = tostring(ResultType),
          ResultDescription, RiskLevelDuringSignIn
| order by TimeGenerated asc
| take 500"""

    @staticmethod
    def audit_kql(upn: str, hours: int) -> str:
        u = kql_string(require_upn(upn))
        return f"""union isfuzzy=true
  (AuditLogs
   | where TimeGenerated > ago({int(hours)}h)
   | where tostring(InitiatedBy.user.userPrincipalName) =~ {u}
   | project TimeGenerated, Operation = OperationName, Target = tostring(TargetResources[0].displayName),
             Detail = tostring(Result)),
  (OfficeActivity
   | where TimeGenerated > ago({int(hours)}h)
   | where UserId =~ {u}
   | where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules", "Set-Mailbox", "Add-MailboxPermission")
   | project TimeGenerated, Operation, Target = tostring(OfficeObjectId), Detail = tostring(Parameters))
| order by TimeGenerated asc
| take 200"""

    @staticmethod
    def process_kql(hostname: str, hours: int) -> str:
        h = kql_string(require_hostname(hostname.split(".")[0]).lower())
        return f"""DeviceProcessEvents
| where Timestamp > ago({int(hours)}h)
| where DeviceName =~ {h} or DeviceName startswith strcat({h}, ".")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, SHA256, AccountName,
          Signer = tostring(ProcessVersionInfoCompanyName)
| order by Timestamp desc
| take 300"""

    @staticmethod
    def network_kql(hostname: str, hours: int) -> str:
        h = kql_string(require_hostname(hostname.split(".")[0]).lower())
        return f"""DeviceNetworkEvents
| where Timestamp > ago({int(hours)}h)
| where DeviceName =~ {h} or DeviceName startswith strcat({h}, ".")
| where RemoteIPType == "Public"
| summarize Count = count(), Url = take_any(RemoteUrl), Process = take_any(InitiatingProcessFileName)
          by RemoteIP, RemotePort
| order by Count desc
| take 100"""

    @staticmethod
    def prevalence_kql(indicators: list[Indicator], days: int) -> Optional[str]:
        hashes = [i.value.lower() for i in indicators if i.type == IndicatorType.FILE_HASH and is_hash(i.value)]
        ips = [i.value for i in indicators if i.type == IndicatorType.IP]
        if not hashes and not ips:
            return None
        hs = ", ".join(kql_string(h) for h in hashes) or '""'
        ps = ", ".join(kql_string(p) for p in ips) or '""'
        return f"""let hashes = dynamic([{hs}]);
let ips = dynamic([{ps}]);
union
  (DeviceFileEvents | where Timestamp > ago({int(days)}d) | where SHA256 in~ (hashes) | project DeviceName, Indicator = tolower(SHA256)),
  (DeviceProcessEvents | where Timestamp > ago({int(days)}d) | where SHA256 in~ (hashes) | project DeviceName, Indicator = tolower(SHA256)),
  (DeviceNetworkEvents | where Timestamp > ago({int(days)}d) | where RemoteIP in (ips) | project DeviceName, Indicator = RemoteIP)
| summarize Devices = make_set(DeviceName, 50), DeviceCount = dcount(DeviceName) by Indicator"""

    # ----------------------------------------------------------- Telemetry
    async def user_activity(self, account: Account, hours: int) -> UserActivity:
        out = UserActivity()
        q1, q2 = self.signin_kql(account.upn, hours), self.audit_kql(account.upn, hours)
        out.queries += [q1, q2]
        for r in await self.la.query(q1, timespan=f"PT{int(hours)}H"):
            code = str(r.get("ResultType", "0"))
            out.signins.append(SignIn(
                time=_dt(r.get("TimeGenerated")), ip=r.get("IPAddress") or "", country=r.get("Country") or "",
                city=r.get("City") or "", app=r.get("AppDisplayName") or "", success=code == "0",
                result_code=code, failure_reason=r.get("ResultDescription") or "",
                mfa_denied=code in {"500121", "50158"}, risk=(r.get("RiskLevelDuringSignIn") or "none").lower()))
        for r in await self.la.query(q2, timespan=f"PT{int(hours)}H"):
            out.audit.append(AuditEvent(time=_dt(r.get("TimeGenerated")), operation=r.get("Operation") or "",
                                        target=r.get("Target") or "", detail=str(r.get("Detail") or "")[:500]))
        return out

    async def host_activity(self, host: Host, hours: int) -> HostActivity:
        out = HostActivity()
        q1, q2 = self.process_kql(host.hostname, hours), self.network_kql(host.hostname, hours)
        out.queries += [q1, q2]
        for r in await self.hunting.query(q1):
            out.processes.append(ProcessEvent(
                time=_dt(r.get("Timestamp")), process=r.get("FileName") or "",
                command_line=r.get("ProcessCommandLine") or "", parent=r.get("InitiatingProcessFileName") or "",
                sha256=(r.get("SHA256") or "").lower(), account=r.get("AccountName") or "",
                signer=r.get("Signer") or ""))
        for r in await self.hunting.query(q2):
            try:
                port = int(r.get("RemotePort") or 0)
            except (TypeError, ValueError):
                port = 0
            out.connections.append(NetworkConnection(
                remote_ip=r.get("RemoteIP") or "", remote_port=port, count=int(r.get("Count") or 1),
                remote_url=r.get("Url") or "", process=r.get("Process") or ""))
        return out

    async def prevalence(self, indicators: list[Indicator], days: int) -> Prevalence:
        out = Prevalence()
        q = self.prevalence_kql(indicators, days)
        if not q:
            return out
        out.queries.append(q)
        for r in await self.hunting.query(q):
            devices = r.get("Devices") or []
            if isinstance(devices, str):
                try:
                    devices = json.loads(devices)
                except ValueError:
                    devices = [devices]
            key = str(r.get("Indicator") or "").lower()
            out.hosts_by_indicator[key] = [str(d) for d in devices]
            out.device_count_by_indicator[key] = int(r.get("DeviceCount") or len(devices))
        return out


class TIFromSentinel:
    """Lookup against the Sentinel threat-intel tables (Microsoft Defender TI, MISP, TAXII feeds...)."""

    def __init__(self, la: LogAnalytics):
        self.la = la

    @staticmethod
    def kql(value: str) -> str:
        v = kql_string(value)
        return f"""ThreatIntelIndicators
| where TimeGenerated > ago(90d)
| where tobool(column_ifexists("IsDeleted", false)) == false
| where todatetime(column_ifexists("ValidUntil", datetime(2100-01-01))) > now()
| where ObservableValue =~ {v}
| order by TimeGenerated desc
| project Key = tostring(column_ifexists("ObservableKey", "")), Confidence = toint(column_ifexists("Confidence", 0)),
          Name = tostring(column_ifexists("Name", "")), Description = tostring(column_ifexists("Description", ""))
| take 10"""

    async def lookup(self, value: str) -> list[dict[str, Any]]:
        try:
            return await self.la.query(self.kql(value), timespan="P90D")
        except ConnectorError as exc:
            if exc.status in (400,):  # table not present in this workspace
                return []
            raise
