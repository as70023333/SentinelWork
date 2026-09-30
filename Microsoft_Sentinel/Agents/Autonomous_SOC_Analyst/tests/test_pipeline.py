"""End-to-end pipeline tests on the demo scenarios (real agent logic, simulated tenant)."""
from __future__ import annotations

import asyncio
import unittest

from soc_agent.connectors.base import LLM, ConnectorError
from soc_agent.models import ActionStatus, ActionType, Disposition, Status, Verdict
from soc_agent.runtime import build_runtime
from soc_agent.store import Store

from .helpers import demo_settings


class FakeLLM(LLM):
    name = "fake-llm"

    def __init__(self, text: str = "", delay: float = 0.0, fail: bool = False):
        self.text, self.delay, self.fail = text, delay, fail
        self.prompts: list[str] = []

    async def complete(self, system: str, prompt: str, max_tokens: int = 1500) -> str:
        self.prompts.append(prompt)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.fail:
            raise ConnectorError("boom")
        return self.text


class ScenarioTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.rt = build_runtime(demo_settings(), store=Store(":memory:"))
        self.world = self.rt.connectors.world

    async def asyncTearDown(self):
        await self.rt.orchestrator.drain(10)
        await self.rt.aclose()

    async def test_every_scenario_matches_expectation(self):
        for name, sc in self.world.scenarios.items():
            with self.subTest(scenario=name):
                inc = await self.rt.orchestrator.handle(name)
                got = {"verdict": inc.verdict.value, "severity": inc.severity.value,
                       "alert_class": inc.alert_class.value, "disposition": inc.disposition.value}
                self.assertEqual(got, sc["expected"])
                self.assertIsNotNone(inc.fast_path_seconds)
                self.assertLess(inc.fast_path_seconds, self.rt.settings.fast_path_budget_seconds)
                self.assertTrue(inc.report_markdown.startswith("# IR Report"))
                self.assertTrue(inc.executive_summary)
                self.assertTrue(all(r.ok for r in inc.agent_runs), [r.error for r in inc.agent_runs])

    async def test_ransomware_contains_and_discovers_c2(self):
        inc = await self.rt.orchestrator.handle("ransomware_workstation")
        acts = {(a.type, a.target): a.status for a in inc.actions}
        self.assertEqual(acts[(ActionType.ISOLATE_HOST, "WKS-FIN-042")], ActionStatus.EXECUTED)
        self.assertEqual(acts[(ActionType.ISOLATE_HOST, "WKS-FIN-017")], ActionStatus.PENDING_APPROVAL)
        self.assertEqual(acts[(ActionType.BLOCK_IP, "203.0.113.66")], ActionStatus.EXECUTED)  # discovered, not in alert
        self.assertEqual(inc.status, Status.CONTAINED)
        self.assertIsNotNone(inc.time_to_contain_seconds)
        self.assertIn("WKS-FIN-042", [h["host"] for h in self.world.state()["isolated_hosts"]])
        feed = list(self.rt.connectors.feed.items)
        self.assertEqual(feed[0]["event"], "page")
        # the slow path adds the sandbox report and bumps the report version
        await self.rt.orchestrator.drain(15)
        inc = self.rt.orchestrator.get(inc.id)
        self.assertIsNotNone(inc.sandbox)
        self.assertGreaterEqual(inc.report_version, 2)
        self.assertIn("Malware analysis (sandbox)", inc.report_markdown)

    async def test_domain_controller_guardrails(self):
        inc = await self.rt.orchestrator.handle("domain_controller_credential_dump")
        acts = {(a.type, a.target): a for a in inc.actions}
        self.assertEqual(acts[(ActionType.ISOLATE_HOST, "DC01")].status, ActionStatus.DENIED_BY_POLICY)
        self.assertEqual(acts[(ActionType.DISABLE_USER, "svc-backup@contoso.com")].status,
                         ActionStatus.PENDING_APPROVAL)
        self.assertEqual(self.world.state()["isolated_hosts"], [])
        self.assertEqual(self.world.state()["disabled_users"], [])

        # human approves the tier-0 disable, then rolls it back
        a = acts[(ActionType.DISABLE_USER, "svc-backup@contoso.com")]
        inc = await self.rt.orchestrator.decide(inc.id, a.id, "approve", "alex")
        self.assertEqual(inc.action(a.id).status, ActionStatus.EXECUTED)
        self.assertEqual(inc.action(a.id).decided_by, "alex")
        self.assertEqual(len(self.world.state()["disabled_users"]), 1)
        self.assertIn("Approved by a human", inc.executive_summary)
        inc = await self.rt.orchestrator.decide(inc.id, a.id, "rollback", "alex")
        self.assertEqual(inc.action(a.id).status, ActionStatus.ROLLED_BACK)
        self.assertEqual(self.world.state()["disabled_users"], [])
        with self.assertRaises(ValueError):
            await self.rt.orchestrator.decide(inc.id, a.id, "rollback", "alex")
        audit_events = [r["event"] for r in self.rt.store.audit_log(inc.id)]
        for ev in ("denied_by_policy", "pending_approval", "approved", "executed", "rolled_back"):
            self.assertIn(ev, audit_events)

    async def test_false_positive_takes_no_action(self):
        inc = await self.rt.orchestrator.handle("false_positive_admin_tool")
        self.assertEqual(inc.verdict, Verdict.FALSE_POSITIVE)
        self.assertEqual(inc.status, Status.CLOSED)
        self.assertEqual(inc.disposition, Disposition.AUTO_CLOSE)
        self.assertEqual(inc.actions, [])
        self.assertIsNone(inc.time_to_contain_seconds)

    async def test_rate_limit_protects_the_fleet(self):
        self.rt.policy.cfg.guardrails.rate_limits_per_hour[ActionType.ISOLATE_HOST] = 2
        statuses = []
        for _ in range(3):
            inc = await self.rt.orchestrator.handle("ransomware_workstation")
            statuses.append(next(a for a in inc.actions if a.type == ActionType.ISOLATE_HOST
                                 and a.target == "WKS-FIN-042").status)
        self.assertEqual(statuses, [ActionStatus.EXECUTED, ActionStatus.EXECUTED, ActionStatus.PENDING_APPROVAL])

    async def test_kill_switch_means_nothing_executes(self):
        self.rt.policy.cfg.autonomy.enabled = False
        inc = await self.rt.orchestrator.handle("credential_phish")
        self.assertTrue(inc.actions)
        self.assertTrue(all(a.status == ActionStatus.RECOMMENDED for a in inc.actions))
        self.assertEqual(inc.status, Status.INVESTIGATING)
        self.assertEqual(inc.disposition, Disposition.PAGE)  # high TP not contained -> page

    async def test_failed_action_is_recorded_and_pages(self):
        async def broken(*a, **k):
            raise ConnectorError("identity API down")
        self.rt.connectors.identity.disable = broken
        inc = await self.rt.orchestrator.handle("credential_phish")
        disable = next(a for a in inc.actions if a.type == ActionType.DISABLE_USER)
        self.assertEqual(disable.status, ActionStatus.FAILED)
        self.assertIn("identity API down", disable.result)
        self.assertEqual(inc.disposition, Disposition.PAGE)
        self.assertIn("FAILED", inc.executive_summary)

    async def test_slow_agent_times_out_without_blocking(self):
        self.rt.settings.agent_timeout_seconds = 0.3

        async def slow(*a, **k):
            await asyncio.sleep(5)
        self.rt.connectors.telemetry.user_activity = slow
        inc = await self.rt.orchestrator.handle("ransomware_workstation")
        user_run = next(r for r in inc.agent_runs if r.agent == "User Activity")
        self.assertFalse(user_run.ok)
        self.assertIn("timed out", user_run.error)
        self.assertEqual(inc.status, Status.CONTAINED)   # containment still happened

    async def test_llm_report_and_injection_resistance(self):
        text = ("EXECUTIVE SUMMARY:\nLockBit contained on WKS-FIN-042.\nNARRATIVE:\nPhishing doc -> PowerShell "
                "(T1059.001) -> LockBit (T1486).\nNEXT STEPS:\n- Approve isolation of WKS-FIN-017")
        llm = FakeLLM(text)
        self.rt.connectors.llm = llm
        inc = await self.rt.orchestrator.handle("ransomware_workstation")
        self.assertEqual(inc.executive_summary, "LockBit contained on WKS-FIN-042.")
        self.assertIn("## What happened", inc.report_markdown)
        self.assertIn("Approve isolation of WKS-FIN-017", inc.report_markdown)
        self.assertEqual(inc.report_generator, "fake-llm")
        self.assertIn("UNTRUSTED", llm.prompts[0].upper())
        # the actions table is rendered from facts, never from LLM text
        self.assertIn("| isolate_host | WKS-FIN-042 | **executed** |", inc.report_markdown)

    async def test_llm_failure_or_timeout_falls_back_to_template(self):
        self.rt.connectors.llm = FakeLLM(fail=True)
        inc = await self.rt.orchestrator.handle("rdp_brute_force")
        self.assertEqual(inc.report_generator, "template")
        self.rt.settings.llm_timeout_seconds = 2.0
        self.rt.connectors.llm = FakeLLM("EXECUTIVE SUMMARY:\nx", delay=3)
        inc = await self.rt.orchestrator.handle("rdp_brute_force")
        self.assertEqual(inc.report_generator, "template")
        self.assertTrue(any("budget" in e.message for e in inc.timeline))

    async def test_set_status(self):
        inc = await self.rt.orchestrator.handle("credential_phish")
        inc = await self.rt.orchestrator.set_status(inc.id, Status.REMEDIATED, "alex", note="password reset")
        self.assertEqual(inc.status, Status.REMEDIATED)
        inc = await self.rt.orchestrator.set_status(inc.id, Status.CLOSED, "alex", verdict=Verdict.TRUE_POSITIVE)
        self.assertEqual(inc.status, Status.CLOSED)
        with self.assertRaises(ValueError):
            await self.rt.orchestrator.set_status(inc.id, Status.CONTAINED, "alex")
        with self.assertRaises(KeyError):
            await self.rt.orchestrator.set_status("nope", Status.CLOSED, "alex")

    async def test_persistence_roundtrip(self):
        inc = await self.rt.orchestrator.handle("credential_phish")
        stored = self.rt.store.get(inc.id)
        self.assertEqual(stored.model_dump(), inc.model_dump())


if __name__ == "__main__":
    unittest.main()
