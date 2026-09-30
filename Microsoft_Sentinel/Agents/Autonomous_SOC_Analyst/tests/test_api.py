"""HTTP API and dashboard."""
from __future__ import annotations

import time
import unittest

from starlette.testclient import TestClient

from soc_agent.api import create_app
from soc_agent.runtime import build_runtime
from soc_agent.store import Store

from .helpers import demo_settings


def wait_done(client: TestClient, incident_id: str, headers=None, timeout: float = 10) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        d = client.get(f"/api/incidents/{incident_id}", headers=headers or {}).json()
        if d.get("fast_path_seconds") is not None:
            return d
        time.sleep(0.05)
    raise AssertionError("incident did not finish")


class ApiTests(unittest.TestCase):
    def make(self, **overrides) -> TestClient:
        settings = demo_settings(**overrides)
        return TestClient(create_app(settings, runtime=build_runtime(settings, store=Store(":memory:"))))

    def test_demo_flow(self):
        with self.make() as c:
            self.assertEqual(c.get("/healthz").json()["mode"], "demo")
            page = c.get("/")
            self.assertEqual(page.status_code, 200)
            self.assertIn("Autonomous SOC Analyst", page.text)
            self.assertIn("frame-ancestors 'none'", page.headers["content-security-policy"])
            info = c.get("/api/info").json()
            self.assertEqual(len(info["scenarios"]), 5)
            self.assertFalse(info["write_key_required"])

            r = c.post("/api/demo/run/ransomware_workstation")
            self.assertEqual(r.status_code, 202)
            d = wait_done(c, r.json()["incident_id"])
            self.assertEqual(d["disposition"], "page")
            self.assertIn("<table>", d["report_html"])
            self.assertNotIn("raw", d)

            pending = next(a for a in d["actions"] if a["status"] == "pending_approval")
            r = c.post(f"/api/incidents/{d['id']}/actions/{pending['id']}/approve", json={"actor": "alex"})
            self.assertEqual(r.status_code, 200)
            r = c.post(f"/api/incidents/{d['id']}/actions/{pending['id']}/approve", json={})
            self.assertEqual(r.status_code, 409)
            r = c.post(f"/api/incidents/{d['id']}/actions/nope/approve", json={})
            self.assertEqual(r.status_code, 404)
            r = c.post(f"/api/incidents/{d['id']}/actions/{pending['id']}/explode", json={})
            self.assertEqual(r.status_code, 400)

            env = c.get("/api/environment").json()
            self.assertEqual({h["host"] for h in env["world"]["isolated_hosts"]}, {"WKS-FIN-042", "WKS-FIN-017"})
            self.assertEqual(env["feed"][0]["incident_id"], d["id"])

            self.assertEqual(c.post(f"/api/incidents/{d['id']}/status", json={"status": "remediated"}).status_code, 200)
            self.assertEqual(c.post(f"/api/incidents/{d['id']}/status", json={"status": "bad"}).status_code, 400)
            self.assertTrue(c.get("/api/audit").json())
            self.assertEqual(c.get("/api/incidents/unknown").status_code, 404)
            self.assertEqual(c.post("/api/demo/run/unknown").status_code, 404)

            r = c.post("/api/webhook/sentinel", json={"object": {"id": "rdp_brute_force"}})
            self.assertEqual(r.status_code, 202)
            wait_done(c, r.json()["incident_id"])
            self.assertEqual(c.post("/api/webhook/sentinel", json={"foo": 1}).status_code, 400)
            self.assertEqual(c.post("/api/webhook/sentinel", content=b"not json").status_code, 400)

            self.assertEqual(c.post("/api/demo/reset").json(), {"ok": True})
            self.assertEqual(c.get("/api/incidents").json(), [])
            self.assertEqual(c.get("/api/environment").json()["world"]["isolated_hosts"], [])

    def test_api_key_protects_writes(self):
        with self.make(webhook_key="s3cret") as c:
            self.assertTrue(c.get("/api/info").json()["write_key_required"])
            self.assertEqual(c.get("/api/incidents").status_code, 200)          # dashboard is public (read-only)
            self.assertEqual(c.post("/api/demo/run/rdp_brute_force").status_code, 401)
            self.assertEqual(c.post("/api/demo/run/rdp_brute_force",
                                    headers={"X-SOC-Key": "wrong"}).status_code, 401)
            r = c.post("/api/demo/run/rdp_brute_force", headers={"X-SOC-Key": "s3cret"})
            self.assertEqual(r.status_code, 202)
            r = c.post("/api/webhook/sentinel?key=s3cret", json={"incidentArmId": "rdp_brute_force"})
            self.assertEqual(r.status_code, 202)
            r = c.post("/api/webhook/sentinel", json={"incidentArmId": "rdp_brute_force"},
                       headers={"Authorization": "Bearer s3cret"})
            self.assertEqual(r.status_code, 202)
            wait_done(c, r.json()["incident_id"])

    def test_private_dashboard(self):
        with self.make(webhook_key="k", dashboard_public=False) as c:
            self.assertEqual(c.get("/api/incidents").status_code, 401)
            self.assertEqual(c.get("/api/incidents", headers={"X-SOC-Key": "k"}).status_code, 200)
            self.assertEqual(c.get("/healthz").status_code, 200)


if __name__ == "__main__":
    unittest.main()
