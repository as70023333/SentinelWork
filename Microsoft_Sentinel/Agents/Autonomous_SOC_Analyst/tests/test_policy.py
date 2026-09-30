"""IR policy engine and guardrails."""
from __future__ import annotations

import unittest

from soc_agent.models import (
    ActionStatus,
    ActionType,
    AlertClass,
    Disposition,
    Incident,
    Indicator,
    IndicatorType,
    ResponseAction,
    Severity,
    Verdict,
)
from soc_agent.policy import Policy

from .helpers import POLICY_PATH


def zero(_):
    return 0


class PolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p = Policy.load(POLICY_PATH)

    def gate(self, action=ActionType.ISOLATE_HOST, cls=AlertClass.RANSOMWARE, verdict=Verdict.TRUE_POSITIVE,
             confidence=0.9, recent=zero, **kw):
        return self.p.gate_action(action, cls, target="X", verdict=verdict, confidence=confidence,
                                  recent_count=recent, **kw)

    def test_classification_order(self):
        cases = {
            "Ransomware activity detected on one endpoint": AlertClass.RANSOMWARE,
            "Credential dump: LSASS memory access": AlertClass.CREDENTIAL_ACCESS,
            "Suspicious sign-in after user clicked a phishing link": AlertClass.PHISHING,
            "Multiple failed RDP sign-ins from an external IP": AlertClass.BRUTE_FORCE,
            "Impossible travel activity": AlertClass.IDENTITY_COMPROMISE,
            "Something odd happened": AlertClass.SUSPICIOUS_ACTIVITY,
        }
        for title, expected in cases.items():
            with self.subTest(title=title):
                inc = Incident(title=title, tactics=["CredentialAccess"])
                self.assertEqual(self.p.classify(inc), expected)

    def test_malware_family_drives_class(self):
        inc = Incident(title="Suspicious file detected")
        self.assertEqual(self.p.classify(inc, ["LockBit"]), AlertClass.RANSOMWARE)

    def test_protected_hosts(self):
        self.assertEqual(self.p.protected_host_pattern("DC01"), "dc*")
        self.assertEqual(self.p.protected_host_pattern("x", "dc02.contoso.com"), "dc*")
        self.assertIsNotNone(self.p.protected_host_pattern("NYC-DC-03"))
        self.assertIsNone(self.p.protected_host_pattern("WKS-FIN-042", "wks-fin-042.contoso.com"))

    def test_tier0_accounts(self):
        self.assertIsNotNone(self.p.tier0_pattern("svc-backup@contoso.com"))
        self.assertIsNotNone(self.p.tier0_pattern("Administrator@contoso.com"))
        self.assertIsNone(self.p.tier0_pattern("jdoe@contoso.com"))

    def test_internal_and_allowlist(self):
        self.assertTrue(self.p.is_internal_ip("10.2.3.4"))
        self.assertTrue(self.p.is_internal_ip("192.168.1.1"))
        self.assertFalse(self.p.is_internal_ip("203.0.113.66"))
        self.assertFalse(self.p.is_internal_ip("not-an-ip"))
        self.assertTrue(self.p.is_allowlisted(Indicator(type=IndicatorType.DOMAIN, value="login.microsoft.com")))
        self.assertTrue(self.p.is_allowlisted(Indicator(type=IndicatorType.URL, value="https://www.office.com/x")))
        self.assertFalse(self.p.is_allowlisted(Indicator(type=IndicatorType.DOMAIN, value="m1crosoft.com")))
        self.assertFalse(self.p.is_allowlisted(Indicator(type=IndicatorType.DOMAIN, value="evilmicrosoft.com")))

    def test_gate_autonomous(self):
        d = self.gate()
        self.assertEqual(d.status, ActionStatus.PLANNED)
        self.assertFalse(d.protected)

    def test_gate_false_positive_proposes_nothing(self):
        self.assertIsNone(self.gate(verdict=Verdict.FALSE_POSITIVE))

    def test_gate_undetermined_recommends(self):
        self.assertEqual(self.gate(verdict=Verdict.UNDETERMINED).status, ActionStatus.RECOMMENDED)

    def test_gate_class_not_allowed(self):
        self.assertIsNone(self.gate(action=ActionType.DISABLE_USER, cls=AlertClass.RANSOMWARE))
        self.assertIsNone(self.gate(action=ActionType.ISOLATE_HOST, cls=AlertClass.PHISHING))

    def test_gate_protected_host_denied(self):
        d = self.gate(protected_pattern="dc*", protected_mode="deny")
        self.assertEqual(d.status, ActionStatus.DENIED_BY_POLICY)
        self.assertTrue(d.protected)

    def test_gate_tier0_needs_approval(self):
        d = self.gate(action=ActionType.DISABLE_USER, cls=AlertClass.PHISHING,
                      protected_pattern="svc-backup@*", protected_mode="approval")
        self.assertEqual(d.status, ActionStatus.PENDING_APPROVAL)

    def test_gate_low_confidence_needs_approval(self):
        self.assertEqual(self.gate(confidence=0.5).status, ActionStatus.PENDING_APPROVAL)

    def test_gate_rate_limit(self):
        d = self.gate(recent=lambda _: 5)
        self.assertEqual(d.status, ActionStatus.PENDING_APPROVAL)
        self.assertIn("Rate limit", d.note)
        self.assertTrue(d.protected)

    def test_gate_related_host_needs_approval(self):
        self.assertEqual(self.gate(is_related_host=True).status, ActionStatus.PENDING_APPROVAL)

    def test_global_kill_switch_and_modes(self):
        p = Policy(self.p.cfg.model_copy(deep=True))
        p.cfg.autonomy.enabled = False
        self.assertEqual(p.gate_action(ActionType.BLOCK_IP, AlertClass.MALWARE, target="1.2.3.4",
                                       verdict=Verdict.TRUE_POSITIVE, confidence=0.9, recent_count=zero).status,
                         ActionStatus.RECOMMENDED)
        p.cfg.autonomy.enabled = True
        p.cfg.autonomy.actions[ActionType.BLOCK_IP] = "recommend"
        self.assertEqual(p.gate_action(ActionType.BLOCK_IP, AlertClass.MALWARE, target="1.2.3.4",
                                       verdict=Verdict.TRUE_POSITIVE, confidence=0.9, recent_count=zero).status,
                         ActionStatus.RECOMMENDED)
        p.cfg.autonomy.actions[ActionType.BLOCK_IP] = "disabled"
        self.assertIsNone(p.gate_action(ActionType.BLOCK_IP, AlertClass.MALWARE, target="1.2.3.4",
                                        verdict=Verdict.TRUE_POSITIVE, confidence=0.9, recent_count=zero))

    def test_escalation(self):
        inc = Incident(title="t", severity=Severity.CRITICAL, verdict=Verdict.TRUE_POSITIVE)
        self.assertEqual(self.p.escalate(inc)[0], Disposition.PAGE)
        inc = Incident(title="t", severity=Severity.HIGH, verdict=Verdict.TRUE_POSITIVE,
                       actions=[ResponseAction(type=ActionType.DISABLE_USER, target="u", status=ActionStatus.EXECUTED)])
        self.assertEqual(self.p.escalate(inc)[0], Disposition.QUEUE)
        inc.actions[0].status = ActionStatus.FAILED
        self.assertEqual(self.p.escalate(inc)[0], Disposition.PAGE)
        inc = Incident(title="t", severity=Severity.MEDIUM, verdict=Verdict.TRUE_POSITIVE,
                       actions=[ResponseAction(type=ActionType.DISABLE_USER, target="u",
                                               status=ActionStatus.PENDING_APPROVAL, guardrail_hit=True)])
        self.assertEqual(self.p.escalate(inc)[0], Disposition.PAGE)
        inc = Incident(title="t", severity=Severity.LOW, verdict=Verdict.FALSE_POSITIVE)
        self.assertEqual(self.p.escalate(inc)[0], Disposition.AUTO_CLOSE)

    def test_invalid_policy_rejected(self):
        from pydantic import ValidationError

        from soc_agent.policy import PolicyCfg
        with self.assertRaises(ValidationError):
            PolicyCfg.model_validate({"escalation": [{"name": "x", "when": {"sevrity": ["high"]},
                                                      "disposition": "page"}]})
        with self.assertRaises(ValidationError):
            PolicyCfg.model_validate({"escalation": [{"name": "x", "disposition": "wake-everyone"}]})
        with self.assertRaises(ValidationError):
            PolicyCfg.model_validate({"escalation": [{"name": "x", "disposition": "page"}],
                                      "guardrails": {"internal_networks": ["10.0.0.0/33"]}})


if __name__ == "__main__":
    unittest.main()
