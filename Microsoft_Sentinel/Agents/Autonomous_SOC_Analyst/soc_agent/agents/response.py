"""Response agents: the Policy & Guardrail planner plus the containment executors
(Endpoint Containment, Network Block, Identity Containment) and their rollbacks."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from ..connectors.base import ConnectorError, UserInfo
from ..models import (
    Account,
    ActionStatus,
    ActionType,
    Host,
    Incident,
    Indicator,
    IndicatorType,
    ResponseAction,
    TIVerdict,
    utcnow,
)
from .context import AgentContext

log = logging.getLogger("soc_agent.response")

BLOCK_ACTION = {
    IndicatorType.IP: ActionType.BLOCK_IP,
    IndicatorType.FILE_HASH: ActionType.BLOCK_HASH,
    IndicatorType.DOMAIN: ActionType.BLOCK_DOMAIN,
    IndicatorType.URL: ActionType.BLOCK_URL,
}
CONTAINMENT_TYPES = {ActionType.ISOLATE_HOST, ActionType.BLOCK_IP, ActionType.BLOCK_HASH, ActionType.BLOCK_DOMAIN,
                     ActionType.BLOCK_URL, ActionType.DISABLE_USER, ActionType.REVOKE_SESSIONS}
ISOLATION_CONFIRM_SECONDS = 5.0


# ============================================================================ planning
def plan_actions(ctx: AgentContext, indicators: Optional[list[Indicator]] = None,
                 include_hosts: bool = True, include_accounts: bool = True) -> list[ResponseAction]:
    """Policy & Guardrail Agent: propose containment and gate every proposal through the IR policy."""
    inc, policy = ctx.incident, ctx.policy
    planned_counts: dict[ActionType, int] = {}
    existing = {(a.type, a.target.lower()) for a in inc.actions}
    proposals: list[ResponseAction] = []

    def recent(action_type: ActionType) -> int:
        return ctx.store.executed_in_last_hour(action_type) + planned_counts.get(action_type, 0)

    def propose(action_type: ActionType, target: str, params: dict, reason: str, *,
                protected_pattern: Optional[str] = None, protected_mode=None, related: bool = False) -> None:
        if (action_type, target.lower()) in existing:
            return
        decision = policy.gate_action(action_type, inc.alert_class, target=target, verdict=inc.verdict,
                                      confidence=inc.assessment.confidence, recent_count=recent,
                                      protected_pattern=protected_pattern, protected_mode=protected_mode,
                                      is_related_host=related)
        if decision is None:
            return
        if decision.status == ActionStatus.PLANNED:
            planned_counts[action_type] = planned_counts.get(action_type, 0) + 1
        existing.add((action_type, target.lower()))
        proposals.append(ResponseAction(type=action_type, target=target, params=params, status=decision.status,
                                        reason=reason, policy_note=decision.note, guardrail_hit=decision.protected))

    g = policy.cfg.guardrails
    if include_hosts:
        host_list = [(h, False) for h in inc.entities.hosts] + \
                    [(Host(hostname=name), True) for name in inc.related_hosts]
        for host, related in host_list:
            pattern = policy.protected_host_pattern(host.hostname, host.fqdn)
            why = ("same malicious indicator found on this host" if related
                   else f"host named in a confirmed {inc.alert_class.value} incident")
            propose(ActionType.ISOLATE_HOST, host.hostname, host.model_dump(), f"Contain: {why}",
                    protected_pattern=pattern, protected_mode=g.protected_host_action if pattern else None,
                    related=related)
            if not related:
                propose(ActionType.AV_SCAN, host.hostname, host.model_dump(), "Sweep the host for other artifacts")

    for rep in inc.reputations:
        ind = rep.indicator
        if indicators is not None and ind.key not in {i.key for i in indicators}:
            continue
        if rep.verdict != TIVerdict.MALICIOUS or rep.allowlisted:
            continue
        if ind.type == IndicatorType.IP and policy.is_internal_ip(ind.value):
            inc.log("guardrail", f"Not blocking {ind.value}: internal network address")
            continue
        sources = ", ".join(s.source for s in rep.sources if s.verdict == TIVerdict.MALICIOUS)
        propose(BLOCK_ACTION[ind.type], ind.value, ind.model_dump(mode="json"),
                f"Malicious per {sources or 'threat intel'} (score {rep.score})")

    if include_accounts:
        for account in inc.entities.accounts:
            info = ctx.user_infos.get(account.upn.lower())
            tier0 = policy.tier0_pattern(account.upn)
            pattern, mode = None, None
            if tier0:
                pattern, mode = tier0, g.tier0_account_action
            elif info and info.privileged_roles:
                pattern, mode = f"privileged roles: {', '.join(info.privileged_roles)}", g.privileged_role_action
            params = account.model_dump()
            propose(ActionType.DISABLE_USER, account.upn, params,
                    f"Account involved in confirmed {inc.alert_class.value}",
                    protected_pattern=pattern, protected_mode=mode)
            propose(ActionType.REVOKE_SESSIONS, account.upn, params, "Kill stolen tokens / active sessions",
                    protected_pattern=pattern, protected_mode=mode)
    return proposals


# ============================================================================ execution
def _comment(inc: Incident, what: str) -> str:
    ref = inc.external_id or inc.id
    return f"Autonomous SOC Analyst: {what} for incident {ref} ({inc.title[:120]})"


async def _user_info(ctx: AgentContext, account: Account) -> UserInfo:
    info = ctx.user_infos.get(account.upn.lower())
    if info is None:
        info = await ctx.connectors.identity.lookup(account)
        ctx.user_infos[account.upn.lower()] = info
    return info


async def execute_action(ctx: AgentContext, action: ResponseAction, actor: str = "agent") -> ResponseAction:
    """Run one containment action. Never raises: failures are recorded on the action."""
    inc, c = ctx.incident, ctx.connectors
    try:
        if action.type in (ActionType.ISOLATE_HOST, ActionType.AV_SCAN):
            host = Host(**action.params)
            device_id = await c.edr.resolve_device(host)
            if not device_id:
                raise ConnectorError(f"{host.hostname} was not found in Defender for Endpoint")
            action.params["device_id"] = device_id
            if action.type == ActionType.ISOLATE_HOST:
                ma = await c.edr.isolate(device_id, _comment(inc, "full network isolation"))
                action.rollback_ref = device_id
                status = await _await_machine_action(ctx, ma, ISOLATION_CONFIRM_SECONDS)
                if status in {"Failed", "Cancelled", "TimeOut"}:
                    raise ConnectorError(f"Defender reported isolation {status}")
                action.result = (f"Isolated (machine action {ma}: {status})" if status == "Succeeded"
                                 else f"Isolation command accepted (machine action {ma}: {status}); "
                                      "device confirmation pending")
            else:
                ma = await c.edr.av_scan(device_id, _comment(inc, "quick antivirus scan"))
                action.result = f"Quick scan started (machine action {ma})"
        elif action.type in BLOCK_ACTION.values():
            ind = Indicator(**action.params)
            hours = ctx.policy.cfg.guardrails.block_expiry_hours
            expires = datetime.now(timezone.utc) + timedelta(hours=hours)
            action.rollback_ref = await c.blocklist.block(
                ind, title=f"SOC agent block: {ind.value}"[:250],
                description=_comment(inc, f"{action.reason}"), expires=expires)
            action.result = f"Blocked in {c.blocklist.name} until {expires:%Y-%m-%d %H:%M} UTC"
        elif action.type == ActionType.DISABLE_USER:
            account = Account(**action.params)
            info = await _user_info(ctx, account)
            action.rollback_ref = await c.identity.disable(account, info, _comment(inc, "account disabled"))
            action.result = "Account disabled" + (" in on-prem AD" if info.on_prem_synced else "")
        elif action.type == ActionType.REVOKE_SESSIONS:
            account = Account(**action.params)
            info = await _user_info(ctx, account)
            await c.identity.revoke_sessions(account, info)
            action.result = "All refresh tokens and sessions revoked"
        else:  # pragma: no cover
            raise ConnectorError(f"No executor for {action.type}")
        action.status = ActionStatus.EXECUTED
        action.executed_at = utcnow()
        action.decided_by = actor
        inc.log(actor, f"{action.type.value} {action.target}: {action.result}")
        ctx.store.audit(inc.id, "executed", actor, action_id=action.id, action_type=action.type,
                        detail={"target": action.target, "result": action.result})
    except Exception as exc:  # record, never crash the pipeline
        action.status = ActionStatus.FAILED
        action.result = f"{exc.__class__.__name__}: {exc}"[:500]
        action.decided_by = actor
        inc.log(actor, f"FAILED {action.type.value} {action.target}: {action.result}")
        ctx.store.audit(inc.id, "failed", actor, action_id=action.id, action_type=action.type,
                        detail={"target": action.target, "error": action.result})
        log.warning("Action %s %s failed: %s", action.type.value, action.target, action.result)
    return action


async def _await_machine_action(ctx: AgentContext, action_id: str, seconds: float) -> str:
    deadline = asyncio.get_running_loop().time() + seconds
    status = "Pending"
    while True:
        try:
            status = await ctx.connectors.edr.action_status(action_id)
        except ConnectorError:
            return status
        if status in {"Succeeded", "Failed", "Cancelled", "TimeOut"}:
            return status
        if asyncio.get_running_loop().time() >= deadline:
            return status
        await asyncio.sleep(1.0)


async def rollback_action(ctx: AgentContext, action: ResponseAction, actor: str) -> ResponseAction:
    """Undo an executed action (one-click rollback from the dashboard)."""
    inc, c = ctx.incident, ctx.connectors
    if action.status != ActionStatus.EXECUTED:
        raise ValueError(f"Only executed actions can be rolled back (status is {action.status.value})")
    if action.type == ActionType.AV_SCAN:
        raise ValueError("An antivirus scan cannot be rolled back")
    if action.type == ActionType.REVOKE_SESSIONS:
        raise ValueError("Revoked sessions cannot be restored; the user simply signs in again")
    if action.type == ActionType.ISOLATE_HOST:
        await c.edr.release(action.rollback_ref or action.params.get("device_id", ""),
                            _comment(inc, f"release from isolation by {actor}"))
    elif action.type in BLOCK_ACTION.values():
        if not action.rollback_ref:
            raise ValueError("No rollback reference recorded for this block")
        await c.blocklist.unblock(action.rollback_ref)
    elif action.type == ActionType.DISABLE_USER:
        account = Account(**action.params)
        info = await _user_info(ctx, account)
        await c.identity.enable(account, info, _comment(inc, f"re-enabled by {actor}"))
    action.status = ActionStatus.ROLLED_BACK
    action.decided_by = actor
    action.result += f" | rolled back by {actor} at {utcnow():%H:%M:%S} UTC"
    inc.log(actor, f"Rolled back {action.type.value} {action.target}")
    ctx.store.audit(inc.id, "rolled_back", actor, action_id=action.id, action_type=action.type,
                    detail={"target": action.target})
    return action
