"""Pure detection heuristics used by the investigation agents (easy to unit test and extend)."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Callable, Optional

from ..connectors.base import AuditEvent, NetworkConnection, ProcessEvent, SignIn
from ..models import Signal

# ------------------------------------------------------------------ endpoint behaviors
@dataclass(frozen=True)
class BehaviorRule:
    name: str
    pattern: re.Pattern
    weight: int
    mitre: str


BEHAVIOR_RULES: list[BehaviorRule] = [
    BehaviorRule("Shadow copy deletion", re.compile(
        r"vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete|win32_shadowcopy.*delete", re.I),
        20, "T1490"),
    BehaviorRule("Credential dumping tool / LSASS dump", re.compile(
        r"sekurlsa::|lsadump::|mimikatz|comsvcs(\.dll)?\s*,?\s*minidump|procdump(64)?(\.exe)?\s.*lsass|\blsass\.dmp\b",
        re.I), 20, "T1003.001"),
    BehaviorRule("System recovery disabled", re.compile(
        r"bcdedit(\.exe)?.*recoveryenabled\s+no|bcdedit(\.exe)?.*bootstatuspolicy\s+ignoreallfailures", re.I),
        10, "T1490"),
    BehaviorRule("Encoded PowerShell command", re.compile(
        r"\s-(?:e|ec|en|enc\w*)\s+[A-Za-z0-9+/=]{12,}", re.I), 10, "T1059.001"),
    BehaviorRule("Remote execution tool", re.compile(r"\bpsexec(64)?(\.exe)?\b|\bpaexec\b|wmic(\.exe)?\s+/node:", re.I),
                 10, "T1569.002"),
    BehaviorRule("Download cradle", re.compile(
        r"downloadstring|downloadfile|invoke-webrequest|\biwr\b|certutil(\.exe)?.*-urlcache|bitsadmin(\.exe)?.*/transfer",
        re.I), 8, "T1105"),
]

OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe"}
SCRIPT_CHILDREN = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe"}
BEACON_MIN_CONNECTIONS = 20


def analyze_processes(host: str, processes: list[ProcessEvent]) -> list[Signal]:
    signals: dict[str, Signal] = {}
    for p in processes:
        for rule in BEHAVIOR_RULES:
            if rule.name not in signals and rule.pattern.search(" " + p.command_line + " "):
                cmd = p.command_line if len(p.command_line) <= 140 else p.command_line[:137] + "..."
                signals[rule.name] = Signal(category="behavior", name=rule.name, weight=rule.weight,
                                            detail=f"{host}: {cmd} (parent {p.parent or '?'}, {rule.mitre})")
        name = "Office application spawned a script host"
        if name not in signals and p.parent.lower() in OFFICE_PARENTS and p.process.lower() in SCRIPT_CHILDREN:
            signals[name] = Signal(category="behavior", name=name, weight=10,
                                   detail=f"{host}: {p.parent} -> {p.process} (T1204.002)")
    return list(signals.values())


def analyze_connections(host: str, connections: list[NetworkConnection],
                        is_internal: Callable[[str], bool]) -> tuple[list[Signal], list[str]]:
    """Return beaconing signals and the public IPs that look like C2."""
    signals, beacons = [], []
    for c in sorted(connections, key=lambda c: c.count, reverse=True):
        try:
            ipaddress.ip_address(c.remote_ip)
        except ValueError:
            continue
        if is_internal(c.remote_ip) or c.count < BEACON_MIN_CONNECTIONS:
            continue
        beacons.append(c.remote_ip)
        if len(signals) < 3:
            signals.append(Signal(category="behavior", name="Beaconing to external host", weight=12,
                                  detail=f"{host}: {c.count} connections to {c.remote_ip}:{c.remote_port} "
                                         f"from {c.process or '?'} (T1071)"))
    if len(signals) > 1:  # one beaconing signal carries the weight, the rest are detail only
        for s in signals[1:]:
            s.weight = 0
    return signals, beacons


def trusted_signer_signal(host: str, processes: list[ProcessEvent], hashes: set[str],
                          trusted: list[str]) -> Optional[Signal]:
    trusted_l = {t.lower() for t in trusted}
    for p in processes:
        if p.sha256 and p.sha256.lower() in hashes and p.signer and p.signer.lower() in trusted_l:
            return Signal(category="benign", name="Alerted file is signed by a trusted internal publisher",
                          weight=-15, detail=f"{host}: {p.process} signed by '{p.signer}'")
    return None


# ------------------------------------------------------------------ identity
IMPOSSIBLE_TRAVEL_MINUTES = 120
MFA_FATIGUE_MIN_DENIALS = 3
FAILURE_BURST = 10


def analyze_signins(upn: str, signins: list[SignIn]) -> list[Signal]:
    s_sorted = sorted(signins, key=lambda s: s.time)
    signals: list[Signal] = []
    successes = [s for s in s_sorted if s.success]

    # impossible travel: consecutive successful sign-ins from different countries too close together
    for a, b in zip(successes, successes[1:]):
        if a.country and b.country and a.country != b.country:
            minutes = (b.time - a.time).total_seconds() / 60
            if minutes <= IMPOSSIBLE_TRAVEL_MINUTES:
                signals.append(Signal(
                    category="identity", name="Impossible travel", weight=12,
                    detail=f"{upn}: {a.country} ({a.city or '?'}, {a.ip}) -> {b.country} ({b.city or '?'}, {b.ip}) "
                           f"in {minutes:.0f} min"))
                break

    # MFA fatigue: several MFA denials followed by a success from the same IP
    for succ in successes:
        denials = [s for s in s_sorted if s.mfa_denied and s.ip == succ.ip and s.time <= succ.time
                   and (succ.time - s.time).total_seconds() <= 3600]
        if len(denials) >= MFA_FATIGUE_MIN_DENIALS:
            signals.append(Signal(category="identity", name="MFA fatigue", weight=12,
                                  detail=f"{upn}: {len(denials)} MFA prompts denied/timed out, then approved "
                                         f"from {succ.ip}"))
            break

    # password attacks
    failures = [s for s in s_sorted if not s.success and not s.mfa_denied]
    if len(failures) >= FAILURE_BURST:
        ips = {f.ip for f in failures}
        succ_after = [s for s in successes if s.ip in ips and s.time >= failures[0].time]
        if succ_after:
            signals.append(Signal(category="identity", name="Successful sign-in after password attack", weight=10,
                                  detail=f"{upn}: {len(failures)} failures then success from {succ_after[0].ip}"))
        else:
            signals.append(Signal(category="identity", name="Password attack against account", weight=8,
                                  detail=f"{upn}: {len(failures)} failed sign-ins from {', '.join(sorted(ips))}, "
                                         "no successful sign-in"))

    risky = [s for s in successes if s.risk in {"high", "medium"}]
    if risky:
        worst = "high" if any(s.risk == "high" for s in risky) else "medium"
        signals.append(Signal(category="identity", name=f"Risky sign-in ({worst})", weight=8 if worst == "high" else 4,
                              detail=f"{upn}: successful sign-in flagged {worst} risk from {risky[-1].ip}"))
    return signals


_AUDIT_RULES = [
    ("Suspicious mailbox rule", re.compile(r"inboxrule|updateinboxrules", re.I), 10),
    ("Mailbox forwarding / permission change", re.compile(r"set-mailbox|add-mailboxpermission", re.I), 8),
    ("Privileged role change", re.compile(r"add member to role|add eligible member to role", re.I), 10),
    ("Application consent granted", re.compile(r"consent to application", re.I), 8),
    ("Authentication method changed", re.compile(r"(register|update|add).*security info|user registered", re.I), 6),
]


def analyze_audit(upn: str, events: list[AuditEvent]) -> list[Signal]:
    out: dict[str, Signal] = {}
    for e in events:
        for name, rx, weight in _AUDIT_RULES:
            if name not in out and rx.search(e.operation):
                detail = f"{upn}: {e.operation}" + (f" ({e.detail[:120]})" if e.detail else "")
                out[name] = Signal(category="identity", name=name, weight=weight, detail=detail)
    return list(out.values())


def user_risk_signal(upn: str, risk_level: str) -> Optional[Signal]:
    if risk_level == "high":
        return Signal(category="identity", name="Entra ID user risk: high", weight=8, detail=upn)
    if risk_level == "medium":
        return Signal(category="identity", name="Entra ID user risk: medium", weight=4, detail=upn)
    return None
