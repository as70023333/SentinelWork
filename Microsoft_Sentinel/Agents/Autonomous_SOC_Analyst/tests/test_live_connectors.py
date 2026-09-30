"""Live-mode wiring tested against a fake Microsoft cloud (httpx.MockTransport).

These tests exercise the real Sentinel, Defender, Graph, Log Analytics, VirusTotal and Claude
connectors end to end: request shapes, auth, normalization, write-back and output escaping.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from urllib.parse import parse_qs, unquote

import httpx

from soc_agent.agents.context import Connectors
from soc_agent.config import Settings
from soc_agent.connectors.base import ConnectorError
from soc_agent.connectors.http import AzureTokenProvider, kql_string, require_hostname, require_upn
from soc_agent.connectors.identity import EntraIdentity
from soc_agent.connectors.llm import ClaudeLLM
from soc_agent.connectors.sentinel import SentinelIncidentSource
from soc_agent.connectors.threat_intel import AbuseIPDB, AlienVaultOTX, GreyNoise, MalwareBazaar, URLhaus, VirusTotal
from soc_agent.models import (
    Account,
    ActionStatus,
    ActionType,
    Indicator,
    IndicatorType,
    Status,
    TIVerdict,
    Verdict,
)
from soc_agent.orchestrator import Orchestrator
from soc_agent.policy import Policy
from soc_agent.runtime import build_live
from soc_agent.store import Store

from .helpers import POLICY_PATH

HASH = "a" * 63 + "b"
C2_FROM_SANDBOX = "198.51.100.99"
ARM = ("/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.OperationalInsights/workspaces/ws1"
       "/providers/Microsoft.SecurityInsights/incidents/inc-guid-1")


def live_settings(**kw) -> Settings:
    s = Settings(mode="live", policy_path=POLICY_PATH, db_path=Path(":memory:"), azure_tenant_id="tenant1",
                 azure_client_id="client1", azure_client_secret="secret1", sentinel_subscription_id="sub1",
                 sentinel_resource_group="rg1", sentinel_workspace_name="ws1", sentinel_workspace_id="wsid-1",
                 virustotal_api_key="vt-key", webhook_key="k", anthropic_api_key="", demo_latency=False)
    for k, v in kw.items():
        setattr(s, k, v)
    return s


def table(columns: list[str], rows: list[list]) -> dict:
    return {"tables": [{"name": "PrimaryResult", "columns": [{"name": c, "type": "string"} for c in columns],
                        "rows": rows}]}


class FakeCloud:
    def __init__(self):
        self.requests: list[httpx.Request] = []
        self.token_scopes: list[str] = []

    def body(self, request: httpx.Request) -> dict:
        try:
            return json.loads(request.content or b"{}")
        except ValueError:
            return {}

    def calls(self, method: str, contains: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.method == method and contains in unquote(str(r.url))]

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        host, path, m = request.url.host, unquote(request.url.path), request.method
        J = lambda data, status=200: httpx.Response(status, json=data)  # noqa: E731

        if host == "login.microsoftonline.com":
            form = parse_qs(request.content.decode())
            assert form["grant_type"] == ["client_credentials"] and form["client_secret"] == ["secret1"]
            self.token_scopes.append(form["scope"][0])
            return J({"access_token": f"tok-{form['scope'][0]}", "expires_in": 3600})
        assert request.headers.get("authorization", "").startswith("Bearer ") or host not in {
            "management.azure.com", "graph.microsoft.com", "api.security.microsoft.com", "api.loganalytics.io"}

        if host == "management.azure.com":
            assert request.url.params["api-version"] == "2025-09-01"
            if path.endswith("/incidents/inc-guid-1") and m == "GET":
                return J({"id": ARM, "name": "inc-guid-1", "etag": '"e1"', "properties": {
                    "title": "Ransomware activity detected on one endpoint", "description": "Defender detected it",
                    "severity": "High", "status": "New", "incidentNumber": 42,
                    "createdTimeUtc": "2026-09-30T10:00:00Z",
                    "labels": [{"labelName": "existing", "labelType": "User"}],
                    "additionalData": {"tactics": ["Impact"], "alertProductNames": ["Microsoft Defender for Endpoint"]}}})
            if path.endswith("/entities") and m == "POST":
                return J({"entities": [
                    {"kind": "Host", "properties": {"hostName": "WKS-1", "dnsDomain": "contoso.com", "osFamily": "Windows"}},
                    {"kind": "Account", "properties": {"accountName": "user", "upnSuffix": "contoso.com",
                                                       "aadUserId": "oid-1", "displayName": "User One"}},
                    {"kind": "FileHash", "properties": {"hashValue": HASH, "algorithm": "SHA256"}},
                    {"kind": "File", "properties": {"fileName": "payload.exe"}},
                    {"kind": "Ip", "properties": {"address": "10.0.0.8"}},
                    {"kind": "FileHash", "properties": {"hashValue": "not-a-hash"}}]})
            if path.endswith("/alerts"):
                return J({"value": [{"properties": {"productName": "Microsoft Defender for Endpoint"}}]})
            if path.endswith("/incidents/inc-guid-1") and m == "PUT":
                return J({"id": ARM, "name": "inc-guid-1"})
            if "/incidents/inc-guid-1/comments/" in path and m == "PUT":
                return J({"name": "c"})
            if path.endswith("/incidents") and m == "GET":
                return J({"value": [{"name": "inc-guid-1"}]})

        if host == "api.loganalytics.io":
            q = self.body(request)["query"]
            if q.startswith("SigninLogs"):
                assert '=~ "user@contoso.com"' in q
                return J(table(["TimeGenerated", "IPAddress", "Country", "City", "AppDisplayName", "ResultType",
                                "ResultDescription", "RiskLevelDuringSignIn"],
                               [["2026-09-30T09:00:00Z", "20.1.1.1", "US", "KC", "Outlook", "0", "", "none"]]))
            if q.startswith("ThreatIntelIndicators"):
                if HASH in q:
                    return J(table(["Key", "Confidence", "Name", "Description"],
                                   [["file:hashes.'SHA-256'", 90, "LockBit payload", ""]]))
                return J(table(["Key", "Confidence", "Name", "Description"], []))
            return J(table(["TimeGenerated", "Operation", "Target", "Detail"], []))

        if host == "graph.microsoft.com":
            if path == "/v1.0/security/runHuntingQuery":
                q = self.body(request)["Query"]
                if q.startswith("DeviceProcessEvents"):
                    return J({"results": [
                        {"Timestamp": "2026-09-30T09:58:00Z", "FileName": "vssadmin.exe",
                         "ProcessCommandLine": "vssadmin.exe delete shadows /all /quiet <script>alert(1)</script>",
                         "InitiatingProcessFileName": "payload.exe", "SHA256": "", "AccountName": "user", "Signer": ""},
                        {"Timestamp": "2026-09-30T09:57:00Z", "FileName": "payload.exe",
                         "ProcessCommandLine": "payload.exe", "InitiatingProcessFileName": "explorer.exe",
                         "SHA256": HASH.upper(), "AccountName": "user", "Signer": ""}]})
                if q.startswith("DeviceNetworkEvents"):
                    return J({"results": []})
                if q.startswith("let hashes"):
                    return J({"results": [{"Indicator": HASH, "Devices": '["wks-1.contoso.com"]', "DeviceCount": 1}]})
                return J({"results": []})
            if path.startswith("/v1.0/users/") and path.endswith("microsoft.graph.directoryRole"):
                return J({"value": []})
            if path.startswith("/v1.0/users/") and m == "GET":
                return J({"id": "oid-1", "userPrincipalName": "user@contoso.com", "displayName": "User One",
                          "accountEnabled": True, "onPremisesSyncEnabled": False})
            if path.startswith("/v1.0/identityProtection/riskyUsers/"):
                return httpx.Response(404, json={"error": {"code": "NotFound"}})

        if host == "api.security.microsoft.com":
            if path == "/api/machines" and m == "GET":
                return J({"value": [{"id": "old", "computerDnsName": "wks-1.contoso.com", "lastSeen": "2025-01-01"},
                                    {"id": "dev-1", "computerDnsName": "wks-1.contoso.com", "lastSeen": "2026-09-30"},
                                    {"id": "other", "computerDnsName": "wks-10.contoso.com", "lastSeen": "2026-09-30"}]})
            if path == "/api/machines/dev-1/isolate":
                return J({"id": "ma-1", "status": "Pending"})
            if path == "/api/machines/dev-1/runAntiVirusScan":
                return J({"id": "ma-2", "status": "Pending"})
            if path == "/api/machineactions/ma-1":
                return J({"id": "ma-1", "status": "Succeeded"})
            if path == "/api/indicators" and m == "POST":
                return J({"id": 1000 + len(self.calls("POST", "/api/indicators"))})

        if host == "www.virustotal.com":
            assert request.headers["x-apikey"] == "vt-key"
            if path == f"/api/v3/files/{HASH}":
                return J({"data": {"attributes": {
                    "last_analysis_stats": {"malicious": 50, "suspicious": 0, "undetected": 20, "harmless": 0},
                    "popular_threat_classification": {"suggested_threat_label": "ransomware.lockbit/lockbit"}}}})
            if path == f"/api/v3/files/{HASH}/behaviour_summary":
                return J({"data": {"tags": ["DETECT_DEBUG_ENVIRONMENT"], "command_executions": ["vssadmin delete shadows"],
                                   "mitre_attack_techniques": [{"id": "T1486", "signature_description": "Encrypt"}],
                                   "ip_traffic": [{"destination_ip": C2_FROM_SANDBOX, "destination_port": 443}],
                                   "dns_lookups": []}})
            if path == f"/api/v3/ip_addresses/{C2_FROM_SANDBOX}":
                return J({"data": {"attributes": {"last_analysis_stats": {"malicious": 12, "suspicious": 1,
                                                                          "undetected": 70, "harmless": 10}}}})
            return httpx.Response(404, json={"error": {"code": "NotFoundError"}})

        if host == "api.anthropic.com":
            assert request.headers["anthropic-version"] == "2023-06-01"
            return J({"content": [{"type": "text", "text": "EXECUTIVE SUMMARY:\nContained.\nNARRATIVE:\nx\n"
                                                           "NEXT STEPS:\n- y"}]})
        return httpx.Response(599, json={"error": f"unexpected call {m} {request.url}"})


class LiveWiringTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.cloud = FakeCloud()
        self.client = httpx.AsyncClient(transport=httpx.MockTransport(self.cloud))
        self.settings = live_settings()
        self.assertEqual(self.settings.validate(), [])
        connectors: Connectors = build_live(self.settings, self.client)
        self.store = Store(":memory:")
        self.orch = Orchestrator(self.settings, Policy.load(POLICY_PATH), self.store, connectors)

    async def asyncTearDown(self):
        await self.orch.drain(10)
        await self.client.aclose()
        self.store.close()

    async def test_full_live_pipeline(self):
        inc = await self.orch.handle(ARM)
        # normalization
        self.assertEqual(inc.external_id, "inc-guid-1")
        self.assertEqual(inc.entities.hosts[0].fqdn, "WKS-1.contoso.com")
        self.assertEqual(inc.entities.accounts[0].upn, "user@contoso.com")
        self.assertEqual([i.value for i in inc.entities.indicators if i.type == IndicatorType.FILE_HASH], [HASH])
        self.assertEqual(inc.entities.of_type(IndicatorType.FILE_HASH)[0].context, "payload.exe")
        # verdict
        self.assertEqual((inc.verdict, inc.alert_class.value, inc.severity.value),
                         (Verdict.TRUE_POSITIVE, "ransomware", "critical"))
        self.assertTrue(all(r.ok for r in inc.agent_runs), [(r.agent, r.error) for r in inc.agent_runs])
        rep = next(r for r in inc.reputations if r.indicator.value == HASH)
        self.assertEqual({s.source for s in rep.sources}, {"Microsoft Sentinel TI", "VirusTotal"})
        # the internal IP must never be blocked
        self.assertFalse(any(a.target == "10.0.0.8" for a in inc.actions))

        acts = {(a.type, a.target): a for a in inc.actions}
        iso = acts[(ActionType.ISOLATE_HOST, "WKS-1")]
        self.assertEqual(iso.status, ActionStatus.EXECUTED, iso.result)
        self.assertIn("Succeeded", iso.result)
        body = self.cloud.body(self.cloud.calls("POST", "/api/machines/dev-1/isolate")[0])
        self.assertEqual(body["IsolationType"], "Full")
        self.assertIn("inc-guid-1", body["Comment"])
        blk = acts[(ActionType.BLOCK_HASH, HASH)]
        self.assertEqual(blk.status, ActionStatus.EXECUTED, blk.result)
        ind_body = self.cloud.body(self.cloud.calls("POST", "/api/indicators")[0])
        self.assertEqual((ind_body["indicatorType"], ind_body["action"], ind_body["indicatorValue"]),
                         ("FileSha256", "BlockAndRemediate", HASH))
        self.assertRegex(ind_body["expirationTime"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual(inc.status, Status.CONTAINED)

        # Sentinel write-back and comment
        put = self.cloud.body(self.cloud.calls("PUT", "/incidents/inc-guid-1?")[0])
        self.assertEqual(put["etag"], '"e1"')
        self.assertEqual((put["properties"]["severity"], put["properties"]["status"]), ("High", "Active"))
        labels = {lbl["labelName"] for lbl in put["properties"]["labels"]}
        self.assertTrue({"existing", "soc-agent", "soc-agent:page", "soc-agent:class:ransomware"} <= labels)
        comment = self.cloud.body(self.cloud.calls("PUT", "/comments/")[0])["properties"]["message"]
        self.assertIn("<h1>", comment)
        self.assertNotIn("<script>", comment)
        self.assertIn("&lt;script&gt;", comment)

        # auth: one token per scope, cached across all calls
        self.assertEqual(sorted(self.cloud.token_scopes), sorted(set(self.cloud.token_scopes)))

        # slow path: the sandbox reveals a C2 IP, which gets enriched and blocked
        await self.orch.drain(10)
        inc = self.orch.get(inc.id)
        self.assertIsNotNone(inc.sandbox)
        c2 = next(a for a in inc.actions if a.target == C2_FROM_SANDBOX)
        self.assertEqual((c2.type, c2.status), (ActionType.BLOCK_IP, ActionStatus.EXECUTED))
        ip_body = self.cloud.body(self.cloud.calls("POST", "/api/indicators")[-1])
        self.assertEqual((ip_body["indicatorType"], ip_body["action"]), ("IpAddress", "Block"))

    async def test_webhook_redelivery_is_deduplicated(self):
        first = await self.orch.handle(ARM)
        again = await self.orch.handle("inc-guid-1")
        self.assertEqual(first.id, again.id)
        self.assertEqual(len(self.cloud.calls("POST", "/isolate")), 1)

    async def test_false_positive_closes_in_sentinel(self):
        inc = await self.orch.handle(ARM)
        await self.orch.set_status(inc.id, Status.CLOSED, "alex", verdict=Verdict.FALSE_POSITIVE)
        put = self.cloud.body(self.cloud.calls("PUT", "/incidents/inc-guid-1?")[-1])
        self.assertEqual(put["properties"]["status"], "Closed")
        self.assertEqual(put["properties"]["classification"], "FalsePositive")
        self.assertEqual(put["properties"]["classificationReason"], "IncorrectAlertLogic")

    async def test_list_new(self):
        self.assertEqual(await self.orch.connectors.siem.list_new(), ["inc-guid-1"])

    async def test_claude_llm(self):
        llm = ClaudeLLM("sk-test", "claude-sonnet-5-5", self.client)
        self.assertIn("Contained.", await llm.complete("sys", "prompt", 50))
        req = self.cloud.calls("POST", "api.anthropic.com")[0]
        body = self.cloud.body(req)
        self.assertEqual((body["model"], body["system"], req.headers["x-api-key"]), ("claude-sonnet-5-5", "sys", "sk-test"))


class ConnectorUnitTests(unittest.IsolatedAsyncioTestCase):
    def test_kql_guards(self):
        self.assertEqual(kql_string('a"b\\c'), '"a\\"b\\\\c"')
        with self.assertRaises(ConnectorError):
            require_upn('x@y.com" or 1==1 //')
        with self.assertRaises(ConnectorError):
            require_hostname("wks-1; drop")
        self.assertEqual(require_upn("o'brien@contoso.com"), "o'brien@contoso.com")

    def test_incident_ref_validation(self):
        self.assertEqual(SentinelIncidentSource.incident_name(ARM), "inc-guid-1")
        self.assertEqual(SentinelIncidentSource.incident_name("abc-123"), "abc-123")
        with self.assertRaises(ConnectorError):
            SentinelIncidentSource.incident_name("../../etc")

    def test_ti_parsers(self):
        ip = Indicator(type=IndicatorType.IP, value="192.0.2.1")
        vt = VirusTotal.parse(ip, {"data": {"attributes": {"last_analysis_stats": {
            "malicious": 0, "suspicious": 0, "undetected": 60, "harmless": 30}}}})
        self.assertEqual((vt.verdict, vt.score), (TIVerdict.CLEAN, 0))
        self.assertEqual(AbuseIPDB.parse(ip, {"data": {"abuseConfidenceScore": 100, "totalReports": 5}}).verdict,
                         TIVerdict.MALICIOUS)
        self.assertEqual(AbuseIPDB.parse(ip, {"data": {"abuseConfidenceScore": 0, "totalReports": 0}}).verdict,
                         TIVerdict.UNKNOWN)
        self.assertEqual(GreyNoise.parse({"riot": True, "name": "Google"}).verdict, TIVerdict.CLEAN)
        self.assertEqual(GreyNoise.parse({"classification": "malicious", "noise": True}).verdict, TIVerdict.MALICIOUS)
        self.assertIsNone(GreyNoise.parse({"classification": "unknown", "noise": False}))
        self.assertIsNone(AlienVaultOTX.parse({"pulse_info": {"count": 0}}))
        otx = AlienVaultOTX.parse({"pulse_info": {"count": 5, "pulses": [{"malware_families": [{"display_name": "Emotet"}]}]}})
        self.assertEqual((otx.verdict, otx.malware_family), (TIVerdict.MALICIOUS, "Emotet"))
        h = Indicator(type=IndicatorType.FILE_HASH, value=HASH)
        self.assertIsNone(MalwareBazaar.parse(h, {"query_status": "hash_not_found"}))
        self.assertEqual(MalwareBazaar.parse(h, {"query_status": "ok", "data": [{"signature": "AgentTesla"}]}).malware_family,
                         "AgentTesla")
        self.assertIsNone(URLhaus.parse({"query_status": "no_results"}))
        self.assertEqual(URLhaus.parse({"query_status": "ok", "urls": [{}, {}]}).verdict, TIVerdict.MALICIOUS)

    async def test_synced_user_cannot_be_disabled_in_entra(self):
        tokens = AzureTokenProvider("t", "c", "s", client=httpx.AsyncClient(transport=httpx.MockTransport(FakeCloud())))
        ident = EntraIdentity(tokens, httpx.AsyncClient(transport=httpx.MockTransport(FakeCloud())))
        from soc_agent.connectors.base import UserInfo
        with self.assertRaises(ConnectorError) as ctx:
            await ident.disable(Account(upn="u@contoso.com"), UserInfo(upn="u@contoso.com", on_prem_synced=True), "r")
        self.assertIn("IDENTITY_BACKEND=both", str(ctx.exception))

    async def test_retry_then_error(self):
        calls = {"n": 0}

        def handler(request):
            calls["n"] += 1
            return httpx.Response(503, headers={"Retry-After": "0"}, text="busy")
        from soc_agent.connectors.http import request_json
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            with self.assertRaises(ConnectorError) as ctx:
                await request_json(c, "GET", "https://example.test/x", retries=2)
        self.assertEqual(calls["n"], 3)
        self.assertEqual(ctx.exception.status, 503)

    def test_live_settings_validation(self):
        s = live_settings(webhook_key="", sentinel_workspace_id="")
        problems = " ".join(s.validate())
        self.assertIn("SOC_WEBHOOK_KEY", problems)
        self.assertIn("SENTINEL_WORKSPACE_ID", problems)
        self.assertIn("AD_AUTOMATION_WEBHOOK_URL", " ".join(live_settings(identity_backend="both").validate()))


if __name__ == "__main__":
    unittest.main()
