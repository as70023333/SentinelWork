"""Investigation agents: threat intel enrichment, user activity, endpoint & network, prevalence.

Each agent is an async function ``agent(ctx) -> AgentOutput``. The orchestrator runs them
in parallel under a timeout, so one slow or failing data source never blocks containment.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from ..connectors.base import ConnectorError, UserInfo
from ..models import (
    Account,
    Host,
    Indicator,
    IndicatorReputation,
    IndicatorType,
    Signal,
    TISourceResult,
    TIVerdict,
)
from ..scoring import aggregate_reputation
from . import analysis
from .context import AgentContext

USER_LOOKBACK_HOURS = 72
HOST_LOOKBACK_HOURS = 24
PREVALENCE_DAYS = 7
MAX_HOSTS = 5
MAX_ACCOUNTS = 5
MAX_INDICATORS = 25
PROVIDER_TIMEOUT = 8.0


@dataclass
class AgentOutput:
    summary: str
    queries: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ======================================================================== threat intel
async def enrich_indicators(ctx: AgentContext, indicators: list[Indicator]) -> AgentOutput:
    """Threat Intel Enrichment Agent: every indicator against every configured feed, in parallel."""
    inc, policy = ctx.incident, ctx.policy
    known = {r.indicator.key for r in inc.reputations}
    todo = [i for i in indicators if i.key not in known][:MAX_INDICATORS]
    errors: list[str] = []

    async def one_provider(p, ind: Indicator) -> TISourceResult | None:
        try:
            return await asyncio.wait_for(p.lookup(ind), timeout=PROVIDER_TIMEOUT)
        except asyncio.TimeoutError:
            errors.append(f"{p.name}: timeout for {ind.value}")
        except ConnectorError as exc:
            errors.append(f"{p.name}: {exc}")
        except Exception as exc:  # a broken feed must never break the pipeline
            errors.append(f"{p.name}: {exc.__class__.__name__}: {exc}")
        return None

    async def one_indicator(ind: Indicator) -> IndicatorReputation:
        rep = IndicatorReputation(indicator=ind, allowlisted=policy.is_allowlisted(ind))
        if not rep.allowlisted:
            providers = [p for p in ctx.connectors.threat_intel if ind.type in p.supports]
            results = await asyncio.gather(*(one_provider(p, ind) for p in providers))
            rep.sources = [r for r in results if r is not None]
        return aggregate_reputation(rep, policy)

    reps = await asyncio.gather(*(one_indicator(i) for i in todo))
    inc.reputations.extend(reps)
    mal = [r for r in reps if r.verdict == TIVerdict.MALICIOUS]
    feeds = len(ctx.connectors.threat_intel)
    summary = (f"Checked {len(reps)} indicator(s) against {feeds} feed(s): {len(mal)} malicious"
               + (f" ({', '.join(r.indicator.value for r in mal[:4])})" if mal else ""))
    return AgentOutput(summary=summary, errors=errors)


# ======================================================================== user activity
async def investigate_users(ctx: AgentContext) -> AgentOutput:
    """User Activity Agent: directory context + 72h of sign-ins and audit activity per account."""
    inc, policy = ctx.incident, ctx.policy
    accounts = inc.entities.accounts[:MAX_ACCOUNTS]
    if not accounts:
        return AgentOutput(summary="No user accounts in this incident")
    queries: list[str] = []
    errors: list[str] = []
    users_ctx: dict[str, dict] = {}
    any_privileged = False

    async def one(account: Account) -> None:
        nonlocal any_privileged
        info_task = ctx.connectors.identity.lookup(account)
        act_task = ctx.connectors.telemetry.user_activity(account, USER_LOOKBACK_HOURS)
        info_res, act_res = await asyncio.gather(info_task, act_task, return_exceptions=True)
        info = info_res if isinstance(info_res, UserInfo) else UserInfo(upn=account.upn)
        if isinstance(info_res, Exception):
            errors.append(f"directory lookup {account.upn}: {info_res}")
        ctx.user_infos[account.upn.lower()] = info
        if info.object_id and not account.object_id:
            account.object_id = info.object_id

        tier0 = policy.tier0_pattern(account.upn)
        privileged = bool(tier0 or info.privileged_roles)
        any_privileged = any_privileged or privileged
        signals: list[Signal] = []
        if isinstance(act_res, Exception):
            errors.append(f"activity {account.upn}: {act_res}")
            signins, audit = [], []
        else:
            queries.extend(act_res.queries)
            signins, audit = act_res.signins, act_res.audit
            signals += analysis.analyze_signins(account.upn, signins)
            signals += analysis.analyze_audit(account.upn, audit)
        risk_sig = analysis.user_risk_signal(account.upn, info.risk_level)
        if risk_sig:
            signals.append(risk_sig)
        inc.signals.extend(signals)
        countries = sorted({s.country for s in signins if s.country})
        users_ctx[account.upn] = {
            "display_name": info.display_name or account.display_name or "",
            "enabled": info.enabled,
            "privileged": privileged,
            "privileged_reason": (f"tier-0 pattern '{tier0}'" if tier0 else
                                  f"roles: {', '.join(info.privileged_roles)}" if info.privileged_roles else ""),
            "risk_level": info.risk_level,
            "on_prem_synced": info.on_prem_synced,
            "signins_72h": len(signins),
            "failed_signins_72h": sum(1 for s in signins if not s.success),
            "countries": countries,
            "recent_audit": [f"{a.operation} {a.target}".strip() for a in audit[-5:]],
            "findings": [s.name for s in signals],
        }

    await asyncio.gather(*(one(a) for a in accounts))
    inc.user_context = {"users": users_ctx, "privileged": any_privileged}
    flagged = {u: d["findings"] for u, d in users_ctx.items() if d["findings"]}
    summary = (f"Reviewed {len(accounts)} account(s): "
               + ("; ".join(f"{u} -> {', '.join(f)}" for u, f in flagged.items()) if flagged
                  else "no suspicious sign-in or audit activity"))
    if any_privileged:
        summary += " [privileged identity involved]"
    return AgentOutput(summary=summary, queries=queries, errors=errors)


# ======================================================================== endpoint & network
async def investigate_hosts(ctx: AgentContext) -> AgentOutput:
    """Endpoint & Network Traffic Agent: 24h process tree and outbound connections per host."""
    inc, policy = ctx.incident, ctx.policy
    hosts = inc.entities.hosts[:MAX_HOSTS]
    if not hosts:
        return AgentOutput(summary="No hosts in this incident")
    queries: list[str] = []
    errors: list[str] = []
    discovered: list[Indicator] = []
    alert_hashes = {i.value.lower() for i in inc.entities.of_type(IndicatorType.FILE_HASH)}
    known_ips = {i.value for i in inc.entities.of_type(IndicatorType.IP)}
    notes: list[str] = []

    async def one(host: Host) -> None:
        try:
            act = await ctx.connectors.telemetry.host_activity(host, HOST_LOOKBACK_HOURS)
        except Exception as exc:
            errors.append(f"{host.hostname}: {exc}")
            return
        queries.extend(act.queries)
        sigs = analysis.analyze_processes(host.hostname, act.processes)
        beacon_sigs, beacons = analysis.analyze_connections(host.hostname, act.connections, policy.is_internal_ip)
        sigs += beacon_sigs
        benign = analysis.trusted_signer_signal(host.hostname, act.processes, alert_hashes,
                                                policy.cfg.benign_evidence.trusted_signers)
        if benign:
            sigs.append(benign)
        inc.signals.extend(sigs)
        for ip in beacons:
            if ip not in known_ips:
                known_ips.add(ip)
                discovered.append(Indicator(type=IndicatorType.IP, value=ip,
                                            context=f"discovered: beaconing from {host.hostname}"))
        notes.append(f"{host.hostname}: {len(act.processes)} process events, {len(act.connections)} remote "
                     f"endpoints, {len([s for s in sigs if s.category == 'behavior'])} suspicious behaviors")

    await asyncio.gather(*(one(h) for h in hosts))
    for d in discovered:
        inc.entities.indicators.append(d)
    summary = "; ".join(notes) or "No endpoint telemetry returned"
    if discovered:
        summary += f". Discovered {len(discovered)} new indicator(s) not in the alert: " + \
                   ", ".join(d.value for d in discovered)
    return AgentOutput(summary=summary, queries=queries, errors=errors)


async def investigate_prevalence(ctx: AgentContext) -> AgentOutput:
    """Is this one machine or many? Also recognizes widely deployed (benign) software."""
    inc, policy = ctx.incident, ctx.policy
    inds = [i for i in inc.entities.indicators if i.type in (IndicatorType.FILE_HASH, IndicatorType.IP)]
    if not inds:
        return AgentOutput(summary="No hashes or IPs to hunt for")
    prev = await ctx.connectors.telemetry.prevalence(inds, PREVALENCE_DAYS)
    incident_hosts = {h.hostname.split(".")[0].lower() for h in inc.entities.hosts}
    threshold = policy.cfg.benign_evidence.common_software_min_devices
    related: list[str] = []
    notes: list[str] = []
    for ind in inds:
        key = ind.value.lower()
        count = prev.device_count_by_indicator.get(key, 0)
        hosts = prev.hosts_by_indicator.get(key, [])
        if ind.type == IndicatorType.FILE_HASH and count >= threshold:
            inc.signals.append(Signal(category="benign", name="Common software in the environment", weight=-10,
                                      detail=f"hash {ind.value[:12]}... present on {count} devices "
                                             f"(threshold {threshold})"))
            notes.append(f"{ind.value[:12]}... on {count} devices (deployed software)")
            continue
        others = sorted({h.split(".")[0].lower() for h in hosts} - incident_hosts)
        if others:
            notes.append(f"{ind.value[:16]} also seen on {', '.join(o.upper() for o in others)}")
            related.extend(o.upper() for o in others if o.upper() not in related)
    inc.related_hosts = related
    summary = "; ".join(notes) if notes else "Indicators not seen on any other device in the last 7 days"
    return AgentOutput(summary=summary, queries=prev.queries)


# ======================================================================== sandbox
async def analyze_malware(ctx: AgentContext) -> AgentOutput:
    """Malware Analysis Agent (slow path): behavioral sandbox report for the file hashes."""
    if not ctx.connectors.sandbox:
        return AgentOutput(summary="No sandbox configured")
    for ind in ctx.incident.entities.of_type(IndicatorType.FILE_HASH):
        report = await ctx.connectors.sandbox.analyze(ind)
        if report:
            ctx.incident.sandbox = report
            return AgentOutput(summary=f"Sandbox: {report.get('family') or 'behavior report'} - "
                                       f"{len(report.get('behaviors', []))} behaviors, "
                                       f"{len(report.get('mitre', []))} ATT&CK techniques")
    return AgentOutput(summary="No sandbox report available for the file hashes")
