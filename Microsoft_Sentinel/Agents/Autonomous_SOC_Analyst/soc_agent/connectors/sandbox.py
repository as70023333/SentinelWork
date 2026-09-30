"""Malware behavioral analysis (sandbox) connector."""
from __future__ import annotations

from typing import Any, Optional
from urllib.parse import quote

import httpx

from ..models import Indicator, IndicatorType
from .base import Sandbox
from .http import request_json


class VirusTotalSandbox(Sandbox):
    """Uses the aggregated behaviour reports of the VirusTotal sandboxes (no file upload required)."""

    def __init__(self, api_key: str, client: httpx.AsyncClient):
        self.key, self.client = api_key, client

    async def analyze(self, indicator: Indicator) -> Optional[dict[str, Any]]:
        if indicator.type != IndicatorType.FILE_HASH:
            return None
        data = await request_json(
            self.client, "GET",
            f"https://www.virustotal.com/api/v3/files/{quote(indicator.value)}/behaviour_summary",
            headers={"x-apikey": self.key}, ok_404=True, retries=1)
        return self.parse(indicator, data) if data else None

    @staticmethod
    def parse(indicator: Indicator, data: dict[str, Any]) -> Optional[dict[str, Any]]:
        d = data.get("data") or {}
        if not d:
            return None
        mitre = sorted({f"{t.get('id')}: {t.get('signature_description') or ''}".strip(": ")
                        for t in (d.get("mitre_attack_techniques") or []) if t.get("id")})[:15]
        behaviors = list(dict.fromkeys((d.get("tags") or []) + (d.get("command_executions") or [])[:8]))[:15]
        contacted_ips = list(dict.fromkeys(
            t.get("destination_ip") for t in (d.get("ip_traffic") or []) if t.get("destination_ip")))[:15]
        contacted_domains = list(dict.fromkeys(
            x.get("hostname") for x in (d.get("dns_lookups") or []) if x.get("hostname")))[:15]
        return {
            "source": "VirusTotal sandbox behaviour summary",
            "hash": indicator.value,
            "behaviors": behaviors,
            "mitre": mitre,
            "contacted_ips": contacted_ips,
            "contacted_domains": contacted_domains,
            "files_dropped": len(d.get("files_dropped") or []),
            "simulated": False,
        }
