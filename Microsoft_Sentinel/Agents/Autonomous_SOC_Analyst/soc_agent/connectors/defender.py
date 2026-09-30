"""Microsoft Defender for Endpoint: device isolation, AV scans and custom indicators (blocks)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote

import httpx

from ..models import Host, Indicator, IndicatorType
from .base import Blocklist, ConnectorError, EDR
from .http import AzureTokenProvider, request_json

MDE = "https://api.security.microsoft.com"
MDE_SCOPE = "https://api.securitycenter.microsoft.com/.default"


def _odata(value: str) -> str:
    return value.replace("'", "''")


class DefenderEDR(EDR):
    def __init__(self, tokens: AzureTokenProvider, client: httpx.AsyncClient):
        self.tokens = tokens
        self.client = client

    async def _h(self) -> dict[str, str]:
        return await self.tokens.headers(MDE_SCOPE)

    async def resolve_device(self, host: Host) -> Optional[str]:
        if host.device_id:
            return host.device_id
        short = host.hostname.split(".")[0].lower()
        flt = quote(f"startswith(computerDnsName,'{_odata(short)}')", safe="(),'")
        data = await request_json(self.client, "GET", f"{MDE}/api/machines?$filter={flt}",
                                  headers=await self._h()) or {}
        candidates = []
        for m in data.get("value", []):
            dns = (m.get("computerDnsName") or "").lower()
            if dns == short or dns.startswith(short + ".") or (host.fqdn and dns == host.fqdn.lower()):
                candidates.append(m)
        if not candidates:
            return None
        candidates.sort(key=lambda m: m.get("lastSeen") or "", reverse=True)
        return candidates[0].get("id")

    async def _machine_action(self, device_id: str, verb: str, body: dict) -> str:
        data = await request_json(self.client, "POST", f"{MDE}/api/machines/{quote(device_id)}/{verb}",
                                  headers=await self._h(), json=body, retries=1)
        if not data or not data.get("id"):
            raise ConnectorError(f"Defender '{verb}' returned no machine action id")
        return data["id"]

    async def isolate(self, device_id: str, comment: str) -> str:
        return await self._machine_action(device_id, "isolate", {"Comment": comment[:1000], "IsolationType": "Full"})

    async def release(self, device_id: str, comment: str) -> str:
        return await self._machine_action(device_id, "unisolate", {"Comment": comment[:1000]})

    async def av_scan(self, device_id: str, comment: str) -> str:
        return await self._machine_action(device_id, "runAntiVirusScan", {"Comment": comment[:1000], "ScanType": "Quick"})

    async def action_status(self, action_id: str) -> str:
        data = await request_json(self.client, "GET", f"{MDE}/api/machineactions/{quote(action_id)}",
                                  headers=await self._h()) or {}
        return str(data.get("status", "Unknown"))


class DefenderIndicatorBlocklist(Blocklist):
    """Custom indicators in Defender for Endpoint: blocks on every onboarded device."""
    name = "Defender for Endpoint indicators"

    def __init__(self, tokens: AzureTokenProvider, client: httpx.AsyncClient):
        self.tokens = tokens
        self.client = client

    @staticmethod
    def indicator_fields(ind: Indicator) -> tuple[str, str]:
        if ind.type == IndicatorType.FILE_HASH:
            kind = {32: "FileMd5", 40: "FileSha1", 64: "FileSha256"}.get(len(ind.value))
            if not kind:
                raise ConnectorError(f"Unsupported hash length for {ind.value}")
            return kind, "BlockAndRemediate"
        if ind.type == IndicatorType.IP:
            return "IpAddress", "Block"
        if ind.type == IndicatorType.DOMAIN:
            return "DomainName", "Block"
        if ind.type == IndicatorType.URL:
            return "Url", "Block"
        raise ConnectorError(f"Unsupported indicator type {ind.type}")

    async def block(self, indicator: Indicator, title: str, description: str, expires: datetime) -> str:
        itype, action = self.indicator_fields(indicator)
        body = {
            "indicatorValue": indicator.value,
            "indicatorType": itype,
            "action": action,
            "title": title[:250],
            "description": description[:1000],
            "severity": "High",
            "generateAlert": True,
            "expirationTime": expires.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        data = await request_json(self.client, "POST", f"{MDE}/api/indicators",
                                  headers=await self.tokens.headers(MDE_SCOPE), json=body, retries=1)
        if not data or data.get("id") is None:
            raise ConnectorError("Defender indicator API returned no id")
        return f"mde-indicator:{data['id']}"

    async def unblock(self, ref: str) -> None:
        ind_id = ref.split(":", 1)[1] if ref.startswith("mde-indicator:") else ref
        await request_json(self.client, "DELETE", f"{MDE}/api/indicators/{quote(str(ind_id))}",
                           headers=await self.tokens.headers(MDE_SCOPE), ok_404=True)
