"""Live threat-intelligence providers. Configure any subset via API keys in .env."""
from __future__ import annotations

import base64
from typing import Any, Optional
from urllib.parse import quote, urlparse

import httpx

from ..models import Indicator, IndicatorType, TISourceResult, TIVerdict
from .base import ThreatIntelProvider
from .hunting import TIFromSentinel
from .http import request_json

_ALL = frozenset(IndicatorType)


def _vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


class VirusTotal(ThreatIntelProvider):
    name = "VirusTotal"
    supports = _ALL

    def __init__(self, api_key: str, client: httpx.AsyncClient):
        self.key, self.client = api_key, client

    async def lookup(self, ind: Indicator) -> Optional[TISourceResult]:
        path = {
            IndicatorType.FILE_HASH: f"files/{quote(ind.value)}",
            IndicatorType.IP: f"ip_addresses/{quote(ind.value)}",
            IndicatorType.DOMAIN: f"domains/{quote(ind.value)}",
            IndicatorType.URL: f"urls/{_vt_url_id(ind.value)}",
        }[ind.type]
        data = await request_json(self.client, "GET", f"https://www.virustotal.com/api/v3/{path}",
                                  headers={"x-apikey": self.key}, ok_404=True, retries=1)
        if not data:
            return None
        return self.parse(ind, data)

    @staticmethod
    def parse(ind: Indicator, data: dict[str, Any]) -> TISourceResult:
        attrs = (data.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        total = mal + sus + int(stats.get("undetected", 0)) + int(stats.get("harmless", 0))
        family = ((attrs.get("popular_threat_classification") or {}).get("suggested_threat_label"))
        if total == 0:
            return TISourceResult(source="VirusTotal", verdict=TIVerdict.UNKNOWN, summary="No analysis results")
        ratio_score = round(100 * (mal + 0.5 * sus) / total * 2.5)
        if mal >= 5:
            verdict, score = TIVerdict.MALICIOUS, max(75, min(100, ratio_score))
        elif mal >= 1 or sus >= 2:
            verdict, score = TIVerdict.SUSPICIOUS, max(35, min(69, ratio_score))
        else:
            verdict, score = TIVerdict.CLEAN, 0
        ref = {IndicatorType.FILE_HASH: "file", IndicatorType.IP: "ip-address",
               IndicatorType.DOMAIN: "domain", IndicatorType.URL: "url"}[ind.type]
        ref_id = _vt_url_id(ind.value) if ind.type == IndicatorType.URL else ind.value
        return TISourceResult(source="VirusTotal", verdict=verdict, score=score,
                              summary=f"{mal}/{total} engines flag as malicious",
                              malware_family=family, reference=f"https://www.virustotal.com/gui/{ref}/{ref_id}")


class AbuseIPDB(ThreatIntelProvider):
    name = "AbuseIPDB"
    supports = frozenset({IndicatorType.IP})

    def __init__(self, api_key: str, client: httpx.AsyncClient):
        self.key, self.client = api_key, client

    async def lookup(self, ind: Indicator) -> Optional[TISourceResult]:
        data = await request_json(self.client, "GET", "https://api.abuseipdb.com/api/v2/check",
                                  params={"ipAddress": ind.value, "maxAgeInDays": 90},
                                  headers={"Key": self.key, "Accept": "application/json"}, retries=1)
        return self.parse(ind, data or {})

    @staticmethod
    def parse(ind: Indicator, data: dict[str, Any]) -> Optional[TISourceResult]:
        d = data.get("data") or {}
        if not d:
            return None
        score = int(d.get("abuseConfidenceScore") or 0)
        reports = int(d.get("totalReports") or 0)
        if d.get("isWhitelisted"):
            verdict, score = TIVerdict.CLEAN, 0
        elif score >= 75:
            verdict = TIVerdict.MALICIOUS
        elif score >= 25:
            verdict = TIVerdict.SUSPICIOUS
        elif reports == 0:
            verdict = TIVerdict.UNKNOWN
        else:
            verdict = TIVerdict.CLEAN
        return TISourceResult(source="AbuseIPDB", verdict=verdict, score=score,
                              summary=f"Abuse confidence {score}%, {reports} reports, "
                                      f"{d.get('countryCode') or '?'} / {d.get('isp') or 'unknown ISP'}",
                              reference=f"https://www.abuseipdb.com/check/{ind.value}")


class AlienVaultOTX(ThreatIntelProvider):
    name = "AlienVault OTX"
    supports = _ALL

    def __init__(self, api_key: str, client: httpx.AsyncClient):
        self.key, self.client = api_key, client

    async def lookup(self, ind: Indicator) -> Optional[TISourceResult]:
        if ind.type == IndicatorType.IP:
            section = "IPv6" if ":" in ind.value else "IPv4"
            value = ind.value
        elif ind.type == IndicatorType.DOMAIN:
            section, value = "domain", ind.value
        elif ind.type == IndicatorType.URL:
            section, value = "url", ind.value
        else:
            section, value = "file", ind.value
        url = f"https://otx.alienvault.com/api/v1/indicators/{section}/{quote(value, safe='')}/general"
        data = await request_json(self.client, "GET", url, headers={"X-OTX-API-KEY": self.key},
                                  ok_404=True, retries=1)
        return self.parse(data) if data else None

    @staticmethod
    def parse(data: dict[str, Any]) -> Optional[TISourceResult]:
        pulses = data.get("pulse_info") or {}
        count = int(pulses.get("count") or 0)
        if count == 0:
            return None  # absence from OTX is not evidence of being clean
        families: list[str] = []
        for p in (pulses.get("pulses") or [])[:20]:
            for fam in p.get("malware_families") or []:
                name = fam.get("display_name") if isinstance(fam, dict) else str(fam)
                if name:
                    families.append(name)
        verdict, score = (TIVerdict.MALICIOUS, 80) if count >= 3 else (TIVerdict.SUSPICIOUS, 50)
        return TISourceResult(source="AlienVault OTX", verdict=verdict, score=score,
                              summary=f"Referenced in {count} OTX pulses",
                              malware_family=max(set(families), key=families.count) if families else None)


class GreyNoise(ThreatIntelProvider):
    name = "GreyNoise"
    supports = frozenset({IndicatorType.IP})

    def __init__(self, api_key: str, client: httpx.AsyncClient):
        self.key, self.client = api_key, client

    async def lookup(self, ind: Indicator) -> Optional[TISourceResult]:
        data = await request_json(self.client, "GET", f"https://api.greynoise.io/v3/community/{quote(ind.value)}",
                                  headers={"key": self.key, "Accept": "application/json"}, ok_404=True, retries=1)
        return self.parse(data) if data else None

    @staticmethod
    def parse(data: dict[str, Any]) -> Optional[TISourceResult]:
        cls = str(data.get("classification") or "").lower()
        name = data.get("name") or ""
        if data.get("riot") or cls == "benign":
            return TISourceResult(source="GreyNoise", verdict=TIVerdict.CLEAN, score=0,
                                  summary=f"Known benign service {name}".strip(), reference=data.get("link"))
        if cls == "malicious":
            return TISourceResult(source="GreyNoise", verdict=TIVerdict.MALICIOUS, score=85,
                                  summary="Actively scanning/attacking the internet (malicious)",
                                  reference=data.get("link"))
        if data.get("noise"):
            return TISourceResult(source="GreyNoise", verdict=TIVerdict.SUSPICIOUS, score=40,
                                  summary="Internet background scanner (unclassified)", reference=data.get("link"))
        return None


class MalwareBazaar(ThreatIntelProvider):
    name = "MalwareBazaar"
    supports = frozenset({IndicatorType.FILE_HASH})

    def __init__(self, auth_key: str, client: httpx.AsyncClient):
        self.key, self.client = auth_key, client

    async def lookup(self, ind: Indicator) -> Optional[TISourceResult]:
        data = await request_json(self.client, "POST", "https://mb-api.abuse.ch/api/v1/",
                                  data={"query": "get_info", "hash": ind.value},
                                  headers={"Auth-Key": self.key}, retries=1)
        return self.parse(ind, data or {})

    @staticmethod
    def parse(ind: Indicator, data: dict[str, Any]) -> Optional[TISourceResult]:
        if data.get("query_status") != "ok" or not data.get("data"):
            return None
        entry = data["data"][0]
        family = entry.get("signature")
        return TISourceResult(source="MalwareBazaar", verdict=TIVerdict.MALICIOUS, score=95,
                              summary=f"Known malware sample (first seen {entry.get('first_seen', '?')})",
                              malware_family=family,
                              reference=f"https://bazaar.abuse.ch/sample/{entry.get('sha256_hash', ind.value)}/")


class URLhaus(ThreatIntelProvider):
    name = "URLhaus"
    supports = frozenset({IndicatorType.URL, IndicatorType.DOMAIN})

    def __init__(self, auth_key: str, client: httpx.AsyncClient):
        self.key, self.client = auth_key, client

    async def lookup(self, ind: Indicator) -> Optional[TISourceResult]:
        if ind.type == IndicatorType.URL:
            endpoint, form = "url", {"url": ind.value}
        else:
            endpoint, form = "host", {"host": ind.value}
        data = await request_json(self.client, "POST", f"https://urlhaus-api.abuse.ch/v1/{endpoint}/",
                                  data=form, headers={"Auth-Key": self.key}, retries=1)
        return self.parse(data or {})

    @staticmethod
    def parse(data: dict[str, Any]) -> Optional[TISourceResult]:
        if data.get("query_status") != "ok":
            return None
        count = len(data.get("urls") or []) or 1
        status = data.get("url_status") or ("online" if data.get("urls") else "listed")
        return TISourceResult(source="URLhaus", verdict=TIVerdict.MALICIOUS, score=90,
                              summary=f"Listed as malware distribution ({status}, {count} URL(s))",
                              reference=data.get("urlhaus_reference"))


class SentinelThreatIntel(ThreatIntelProvider):
    """Microsoft Defender Threat Intelligence and every other TI feed connected to Sentinel."""
    name = "Microsoft Sentinel TI"
    supports = _ALL

    def __init__(self, ti: TIFromSentinel):
        self.ti = ti

    async def lookup(self, ind: Indicator) -> Optional[TISourceResult]:
        rows = await self.ti.lookup(ind.value)
        if not rows:
            return None
        best = max(rows, key=lambda r: int(r.get("Confidence") or 0))
        conf = int(best.get("Confidence") or 0)
        verdict = TIVerdict.MALICIOUS if conf >= 70 else TIVerdict.SUSPICIOUS if conf >= 30 else TIVerdict.UNKNOWN
        return TISourceResult(source=self.name, verdict=verdict, score=max(conf, 80) if conf >= 70 else conf,
                              summary=f"{len(rows)} active TI indicator(s); {best.get('Name') or best.get('Description') or 'no name'} "
                                      f"(confidence {conf})")


def domain_of(url: str) -> Optional[str]:
    host = urlparse(url if "://" in url else f"http://{url}").hostname
    return host.lower() if host else None
