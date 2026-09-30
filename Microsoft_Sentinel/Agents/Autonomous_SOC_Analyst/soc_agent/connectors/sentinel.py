"""Microsoft Sentinel incident source (Azure Resource Manager REST API)."""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from ..models import (
    Account,
    Disposition,
    Entities,
    Host,
    Incident,
    Indicator,
    IndicatorType,
    Severity,
    Status,
    Verdict,
)
from ..render import markdown_to_safe_html
from .base import ConnectorError, IncidentSource
from .http import AzureTokenProvider, is_hash, request_json

ARM = "https://management.azure.com"
ARM_SCOPE = "https://management.azure.com/.default"
API_VERSION = "2025-09-01"
MAX_COMMENT_CHARS = 30000

_SEVERITY_IN = {"high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW,
                "informational": Severity.INFORMATIONAL}
_SEVERITY_OUT = {Severity.CRITICAL: "High", Severity.HIGH: "High", Severity.MEDIUM: "Medium",
                 Severity.LOW: "Low", Severity.INFORMATIONAL: "Informational"}
_CLASSIFICATION = {
    Verdict.TRUE_POSITIVE: ("TruePositive", "SuspiciousActivity"),
    Verdict.FALSE_POSITIVE: ("FalsePositive", "IncorrectAlertLogic"),
    Verdict.BENIGN_POSITIVE: ("BenignPositive", "SuspiciousButExpected"),
    Verdict.UNDETERMINED: ("Undetermined", None),
}
_INCIDENT_NAME_RE = re.compile(r"/incidents/([^/?]+)", re.IGNORECASE)


class SentinelIncidentSource(IncidentSource):
    def __init__(self, tokens: AzureTokenProvider, subscription_id: str, resource_group: str,
                 workspace_name: str, client: httpx.AsyncClient, write_back_enabled: bool = True):
        self.tokens = tokens
        self.client = client
        self.write_back_enabled = write_back_enabled
        self.base = (f"{ARM}/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
                     f"/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}"
                     f"/providers/Microsoft.SecurityInsights")

    # ----------------------------------------------------------- helpers
    @staticmethod
    def incident_name(ref: str) -> str:
        m = _INCIDENT_NAME_RE.search(ref)
        name = m.group(1) if m else ref.strip()
        if not re.fullmatch(r"[A-Za-z0-9-]{1,100}", name):
            raise ConnectorError(f"Not a valid Sentinel incident reference: {ref!r}")
        return name

    def _url(self, name: str, suffix: str = "") -> str:
        return f"{self.base}/incidents/{name}{suffix}?api-version={API_VERSION}"

    async def _h(self) -> dict[str, str]:
        return await self.tokens.headers(ARM_SCOPE)

    # ----------------------------------------------------------- IncidentSource
    async def fetch(self, ref: str) -> Incident:
        name = self.incident_name(ref)
        headers = await self._h()
        inc = await request_json(self.client, "GET", self._url(name), headers=headers)
        ents = await request_json(self.client, "POST", self._url(name, "/entities"), headers=headers,
                                  json={}) or {}
        try:
            alerts = await request_json(self.client, "GET", self._url(name, "/alerts"), headers=headers) or {}
        except ConnectorError:
            alerts = {}
        return self.normalize(inc, ents, alerts)

    async def list_new(self) -> list[str]:
        url = (f"{self.base}/incidents?api-version={API_VERSION}"
               "&$filter=properties/status eq 'New'&$orderby=properties/createdTimeUtc desc&$top=50")
        data = await request_json(self.client, "GET", url, headers=await self._h()) or {}
        return [item["name"] for item in data.get("value", []) if item.get("name")]

    async def write_back(self, incident: Incident) -> None:
        if not self.write_back_enabled or not incident.external_id:
            return
        name = self.incident_name(incident.arm_id or incident.external_id)
        headers = await self._h()
        current = await request_json(self.client, "GET", self._url(name), headers=headers)
        props = current.get("properties", {})

        labels = [lbl for lbl in props.get("labels", []) if not str(lbl.get("labelName", "")).startswith("soc-agent")]
        labels += [
            {"labelName": "soc-agent", "labelType": "User"},
            {"labelName": f"soc-agent:{incident.disposition.value}", "labelType": "User"},
            {"labelName": f"soc-agent:class:{incident.alert_class.value}", "labelType": "User"},
        ]
        closing = incident.status == Status.CLOSED or incident.disposition == Disposition.AUTO_CLOSE
        body_props: dict[str, Any] = {
            "title": props.get("title", incident.title),
            "description": props.get("description", ""),
            "severity": _SEVERITY_OUT[incident.severity],
            "status": "Closed" if closing else "Active",
            "labels": labels,
        }
        if props.get("owner"):
            body_props["owner"] = props["owner"]
        if closing:
            classification, reason = _CLASSIFICATION.get(incident.verdict, ("Undetermined", None))
            body_props["classification"] = classification
            if reason:
                body_props["classificationReason"] = reason
            body_props["classificationComment"] = (
                f"Closed by Autonomous SOC Analyst: {incident.verdict.value}, "
                f"confidence {incident.assessment.confidence:.0%}. {incident.disposition_reason}")[:1000]
        body: dict[str, Any] = {"properties": body_props}
        if current.get("etag"):
            body["etag"] = current["etag"]
        await request_json(self.client, "PUT", self._url(name), headers=headers, json=body)

    async def add_comment(self, incident: Incident, markdown: str) -> None:
        if not self.write_back_enabled or not incident.external_id:
            return
        name = self.incident_name(incident.arm_id or incident.external_id)
        html = markdown_to_safe_html(markdown)
        if len(html) > MAX_COMMENT_CHARS:
            html = html[: MAX_COMMENT_CHARS - 100] + "<p><em>[truncated - full report on the SOC agent dashboard]</em></p>"
        url = self._url(name, f"/comments/{uuid.uuid4()}")
        await request_json(self.client, "PUT", url, headers=await self._h(),
                           json={"properties": {"message": html}})

    # ----------------------------------------------------------- normalization
    @staticmethod
    def normalize(inc: dict[str, Any], ents: dict[str, Any], alerts: dict[str, Any]) -> Incident:
        props = inc.get("properties", {})
        add = props.get("additionalData", {}) or {}
        entities = Entities()
        seen: set[str] = set()
        extra_text: list[str] = []

        def add_ind(t: IndicatorType, value: Optional[str], context: Optional[str] = None) -> None:
            if not value:
                return
            ind = Indicator(type=t, value=str(value).strip(), context=context)
            if ind.key not in seen:
                seen.add(ind.key)
                entities.indicators.append(ind)

        for e in ents.get("entities", []):
            kind = (e.get("kind") or "").lower()
            p = e.get("properties", {}) or {}
            if kind == "host":
                hostname = p.get("hostName") or p.get("netBiosName") or p.get("friendlyName")
                if hostname and not any(h.hostname.lower() == hostname.lower() for h in entities.hosts):
                    dns = p.get("dnsDomain")
                    ad = p.get("additionalData", {}) or {}
                    entities.hosts.append(Host(
                        hostname=hostname, fqdn=f"{hostname}.{dns}" if dns else None,
                        device_id=ad.get("MdatpDeviceId") or ad.get("MDATP DeviceId"),
                        os=p.get("osFamily") or p.get("osVersion")))
            elif kind == "account":
                name, suffix = p.get("accountName"), p.get("upnSuffix")
                upn = (p.get("additionalData", {}) or {}).get("UserPrincipalName") \
                    or (f"{name}@{suffix}" if name and suffix else None)
                if not upn and name and "@" in name:
                    upn = name
                if upn and not any(a.upn.lower() == upn.lower() for a in entities.accounts):
                    entities.accounts.append(Account(
                        upn=upn, display_name=p.get("displayName") or p.get("friendlyName"),
                        object_id=p.get("aadUserId"),
                        sam_account_name=name if name and "@" not in name else None,
                        on_prem_sid=p.get("sid")))
            elif kind == "mailbox":
                upn = p.get("upn") or p.get("mailboxPrimaryAddress")
                if upn and not any(a.upn.lower() == upn.lower() for a in entities.accounts):
                    entities.accounts.append(Account(upn=upn, display_name=p.get("displayName")))
            elif kind == "ip":
                add_ind(IndicatorType.IP, p.get("address"))
            elif kind == "filehash":
                if is_hash(p.get("hashValue", "")):
                    add_ind(IndicatorType.FILE_HASH, p.get("hashValue"))
            elif kind == "file":
                if p.get("fileName"):
                    extra_text.append(p["fileName"])
            elif kind == "url":
                add_ind(IndicatorType.URL, p.get("url"))
            elif kind == "dnsresolution":
                add_ind(IndicatorType.DOMAIN, p.get("domainName"))
            elif kind == "malware":
                if p.get("malwareName") or p.get("name"):
                    extra_text.append(f"malware {p.get('malwareName') or p.get('name')}")

        # attach the file name as context when there is exactly one hash and one file
        hashes = entities.of_type(IndicatorType.FILE_HASH)
        files = [t for t in extra_text if not t.startswith("malware ")]
        if len(hashes) == 1 and len(files) == 1:
            hashes[0].context = files[0]

        products = add.get("alertProductNames") or []
        for a in (alerts.get("value") or []):
            ap = a.get("properties", {}) or {}
            if ap.get("productName") and ap["productName"] not in products:
                products.append(ap["productName"])

        created_raw = props.get("createdTimeUtc")
        try:
            created = datetime.fromisoformat(created_raw.replace("Z", "+00:00")) if created_raw else datetime.now(timezone.utc)
        except ValueError:
            created = datetime.now(timezone.utc)

        description = props.get("description") or ""
        if extra_text:
            description = (description + "\nEntities: " + ", ".join(extra_text)).strip()

        return Incident(
            source="sentinel",
            external_id=inc.get("name"),
            arm_id=inc.get("id"),
            title=props.get("title") or "Untitled Sentinel incident",
            description=description,
            provider_severity=_SEVERITY_IN.get(str(props.get("severity", "")).lower(), Severity.MEDIUM),
            product=", ".join(products) or props.get("providerName"),
            tactics=list(add.get("tactics") or []),
            techniques=list(add.get("techniques") or []),
            created=created,
            entities=entities,
            raw={"incidentNumber": props.get("incidentNumber"), "incidentUrl": props.get("incidentUrl")},
        )
