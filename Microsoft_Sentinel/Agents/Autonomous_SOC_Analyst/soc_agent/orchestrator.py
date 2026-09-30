"""Triage Orchestrator ("Flow State" agent).

Owns the incident lifecycle: runs the specialist agents in parallel, applies the IR policy,
executes containment, decides page vs. queue, writes the report and delivers it, all inside
the fast-path time budget (28 s by default). Slow work (sandbox detonation, isolation
confirmation) continues in the background and updates the report when it finishes.
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from typing import Awaitable, Callable, Optional

from .agents import investigate, report, response
from .agents.context import AgentContext, Connectors
from .agents.investigate import AgentOutput
from .config import Settings
from .models import (
    ActionStatus,
    AgentRun,
    Disposition,
    Incident,
    IndicatorType,
    Status,
    Verdict,
    utcnow,
)
from .policy import Policy
from .scoring import assess
from .store import Store

log = logging.getLogger("soc_agent.orchestrator")

DELIVERY_RESERVE = 2.5      # seconds kept for notifications + SIEM write-back
CONTAIN_RESERVE = 6.0       # seconds kept for containment + report when investigating
MAX_CONCURRENT_INCIDENTS = 8
LIVE_CACHE_SIZE = 500


class Orchestrator:
    def __init__(self, settings: Settings, policy: Policy, store: Store, connectors: Connectors):
        self.settings, self.policy, self.store, self.connectors = settings, policy, store, connectors
        self._live: OrderedDict[str, Incident] = OrderedDict()
        self._locks: dict[str, asyncio.Lock] = {}
        self._background: set[asyncio.Task] = set()
        self._sem: Optional[asyncio.Semaphore] = None
        self._inflight_refs: set[str] = set()

    # ------------------------------------------------------------------ access
    def _lock(self, incident_id: str) -> asyncio.Lock:
        return self._locks.setdefault(incident_id, asyncio.Lock())

    def get(self, incident_id: str) -> Optional[Incident]:
        return self._live.get(incident_id) or self.store.get(incident_id)

    def list(self, limit: int = 100) -> list[Incident]:
        stored = self.store.list(limit)
        return [self._live.get(i.id, i) for i in stored]

    def _ctx(self, incident: Incident) -> AgentContext:
        return AgentContext(incident=incident, policy=self.policy, settings=self.settings,
                            connectors=self.connectors, store=self.store)

    def _save(self, incident: Incident) -> None:
        self.store.save(incident)

    def _remember(self, incident: Incident) -> None:
        """Keep a bounded cache of live incident objects so concurrent updates share one object."""
        self._live[incident.id] = incident
        self._live.move_to_end(incident.id)
        while len(self._live) > LIVE_CACHE_SIZE:
            old_id, _ = self._live.popitem(last=False)
            lock = self._locks.get(old_id)
            if lock is not None and not lock.locked():
                self._locks.pop(old_id, None)

    def _spawn(self, coro: Awaitable, name: str) -> None:
        task = asyncio.create_task(coro, name=name)
        self._background.add(task)
        task.add_done_callback(self._background.discard)

    async def drain(self, timeout: float = 60.0) -> None:
        """Wait for background work (sandbox, verification). Used by the CLI and tests."""
        deadline = time.monotonic() + timeout
        while self._background and time.monotonic() < deadline:
            await asyncio.wait(set(self._background), timeout=max(0.1, deadline - time.monotonic()))

    # ------------------------------------------------------------------ ingestion
    async def handle(self, ref: str, *, force: bool = False) -> Incident:
        """Entry point for a SIEM reference (Sentinel incident ARM id / name, or demo scenario id)."""
        if not force and self.settings.is_live:
            existing = self.store.find_by_external(self._external_name(ref))
            if existing:
                log.info("Incident %s already handled (%s); skipping", ref, existing.id)
                return existing
        if ref in self._inflight_refs and not force:
            raise RuntimeError(f"Incident {ref} is already being processed")
        self._inflight_refs.add(ref)
        try:
            incident = await self.connectors.siem.fetch(ref)
            return await self.process(incident)
        finally:
            self._inflight_refs.discard(ref)

    async def start(self, ref: str) -> Incident:
        """Fetch the incident now and run the fast path in the background (used by the API so the
        caller gets an incident id immediately)."""
        if self.settings.is_live:
            existing = self.store.find_by_external(self._external_name(ref))
            if existing:
                return existing
        incident = await self.connectors.siem.fetch(ref)
        self._remember(incident)
        self._save(incident)
        self._spawn(self._safe_process(incident), f"incident-{incident.id}")
        return incident

    async def _safe_process(self, incident: Incident) -> None:
        try:
            await self.process(incident)
        except Exception:
            log.exception("Fast path failed for %s", incident.id)

    @staticmethod
    def _external_name(ref: str) -> str:
        return ref.rstrip("/").split("/")[-1]

    async def poll_forever(self) -> None:
        """POLL_SENTINEL mode: pick up New incidents without needing a Logic App."""
        interval = max(10, self.settings.poll_interval_seconds)
        log.info("Polling Sentinel for new incidents every %ss", interval)
        while True:
            try:
                for name in await self.connectors.siem.list_new():
                    if self.store.find_by_external(name) or name in self._inflight_refs:
                        continue
                    self._spawn(self._safe_handle(name), f"incident-{name}")
            except Exception as exc:
                log.error("Sentinel poll failed: %s", exc)
            await asyncio.sleep(interval)

    async def _safe_handle(self, ref: str) -> None:
        try:
            await self.handle(ref)
        except Exception:
            log.exception("Failed to handle incident %s", ref)

    # ------------------------------------------------------------------ fast path
    async def _run_agent(self, inc: Incident, name: str, fn: Callable[[], Awaitable[AgentOutput]],
                         timeout: float) -> Optional[AgentOutput]:
        run = AgentRun(agent=name)
        start = time.monotonic()
        out: Optional[AgentOutput] = None
        try:
            out = await asyncio.wait_for(fn(), timeout=timeout)
            run.summary, run.queries = out.summary, out.queries
            if out.errors:
                run.error = "; ".join(out.errors)[:600]
        except asyncio.TimeoutError:
            run.ok, run.error = False, f"timed out after {timeout:.1f}s (continuing without it)"
        except Exception as exc:
            run.ok, run.error = False, f"{exc.__class__.__name__}: {exc}"[:600]
            log.exception("Agent %s failed", name)
        run.duration_ms = int((time.monotonic() - start) * 1000)
        inc.agent_runs.append(run)
        inc.log(name, run.summary if run.ok else f"ERROR: {run.error}")
        return out

    async def process(self, incident: Incident) -> Incident:
        if self._sem is None:
            self._sem = asyncio.Semaphore(MAX_CONCURRENT_INCIDENTS)
        async with self._sem:
            self._remember(incident)
            async with self._lock(incident.id):
                try:
                    await self._fast_path(incident)
                finally:
                    self._save(incident)
            return incident

    async def _fast_path(self, inc: Incident) -> None:
        budget = self.settings.fast_path_budget_seconds
        t0 = time.monotonic()
        left = lambda: budget - (time.monotonic() - t0)  # noqa: E731
        ctx = self._ctx(inc)
        inc.started_at = utcnow()
        inc.status = Status.INVESTIGATING
        inc.log("orchestrator", f"Received '{inc.title}' from {inc.source} ({inc.external_id or inc.id}); "
                                f"{len(inc.entities.hosts)} host(s), {len(inc.entities.accounts)} account(s), "
                                f"{len(inc.entities.indicators)} indicator(s)")
        self._save(inc)

        def stage_timeout() -> float:
            return max(2.0, min(self.settings.agent_timeout_seconds, left() - CONTAIN_RESERVE))

        # ---- stage 1: parallel investigation
        initial = list(inc.entities.indicators)
        t = stage_timeout()
        await asyncio.gather(
            self._run_agent(inc, "Threat Intel Enrichment", lambda: investigate.enrich_indicators(ctx, initial), t),
            self._run_agent(inc, "User Activity", lambda: investigate.investigate_users(ctx), t),
            self._run_agent(inc, "Endpoint & Network Traffic", lambda: investigate.investigate_hosts(ctx), t),
        )
        # ---- stage 2: follow the leads (new indicators, lateral spread)
        discovered = [i for i in inc.entities.indicators if i.key not in {x.key for x in initial}]
        t = stage_timeout()
        stage2 = [self._run_agent(inc, "Lateral Spread Hunt", lambda: investigate.investigate_prevalence(ctx), t)]
        if discovered:
            stage2.append(self._run_agent(inc, "Threat Intel (discovered indicators)",
                                          lambda: investigate.enrich_indicators(ctx, discovered), t))
        await asyncio.gather(*stage2)

        # ---- assess
        assess(inc, self.policy)
        inc.log("orchestrator", f"Assessment: {inc.verdict.value}, {inc.severity.value}, {inc.alert_class.value}, "
                                f"score {inc.assessment.score}/100, confidence {inc.assessment.confidence:.0%}")

        # ---- guardrails + containment
        plan_start, plan_started = time.monotonic(), utcnow()
        proposals = response.plan_actions(ctx)
        inc.actions.extend(proposals)
        for a in proposals:
            if a.status != ActionStatus.PLANNED:
                inc.log("Policy & Guardrail", f"{a.type.value} {a.target}: {a.status.value} - {a.policy_note}")
                self.store.audit(inc.id, a.status.value, "agent", action_id=a.id, action_type=a.type,
                                 detail={"target": a.target, "note": a.policy_note})
        to_run = [a for a in proposals if a.status == ActionStatus.PLANNED]
        if to_run:
            await asyncio.gather(*(response.execute_action(ctx, a) for a in to_run))
        inc.agent_runs.append(AgentRun(
            agent="Policy & Guardrail + Containment", started=plan_started, duration_ms=int((time.monotonic() - plan_start) * 1000),
            summary=f"{len(proposals)} action(s) proposed, {len(to_run)} executed autonomously, "
                    f"{sum(a.status == ActionStatus.FAILED for a in proposals)} failed, "
                    f"{sum(a.status == ActionStatus.PENDING_APPROVAL for a in proposals)} awaiting approval, "
                    f"{sum(a.status == ActionStatus.DENIED_BY_POLICY for a in proposals)} denied by guardrails"))
        self._update_status(inc, t0)

        # ---- escalation
        inc.disposition, inc.disposition_reason = self.policy.escalate(inc)
        if inc.disposition == Disposition.AUTO_CLOSE:
            inc.status = Status.CLOSED
        inc.log("orchestrator", f"Disposition: {inc.disposition.value.upper()} ({inc.disposition_reason})")

        # ---- report + delivery
        rep_start, rep_started = time.monotonic(), utcnow()
        generator = await report.write_report(ctx, time_budget=max(0.0, left() - DELIVERY_RESERVE))
        inc.agent_runs.append(AgentRun(agent="IR Report", started=rep_started, duration_ms=int((time.monotonic() - rep_start) * 1000),
                                       summary=f"Report v{inc.report_version} written by {generator}"))
        self._save(inc)
        await self._deliver(ctx, "page" if inc.disposition == Disposition.PAGE else "report",
                            timeout=max(1.5, left()))
        inc.fast_path_seconds = round(time.monotonic() - t0, 2)
        inc.log("orchestrator", f"Fast path complete in {inc.fast_path_seconds:.1f}s "
                                f"(budget {budget:.0f}s){' - OVER BUDGET' if inc.fast_path_seconds > budget else ''}")

        # ---- slow path
        if self.connectors.sandbox and inc.verdict != Verdict.FALSE_POSITIVE and \
                inc.entities.of_type(IndicatorType.FILE_HASH):
            self._spawn(self._sandbox_followup(inc.id), f"sandbox-{inc.id}")
        if any(a.status == ActionStatus.EXECUTED and "confirmation pending" in a.result for a in inc.actions):
            self._spawn(self._verify_isolation(inc.id), f"verify-{inc.id}")

    def _update_status(self, inc: Incident, t0: Optional[float] = None) -> None:
        if inc.status in (Status.REMEDIATED, Status.CLOSED):
            return
        contained = any(a.status == ActionStatus.EXECUTED and a.type in response.CONTAINMENT_TYPES
                        for a in inc.actions)
        if inc.verdict in (Verdict.FALSE_POSITIVE, Verdict.BENIGN_POSITIVE):
            return
        if contained:
            if inc.status != Status.CONTAINED:
                inc.status = Status.CONTAINED
                if inc.contained_at is None:
                    inc.contained_at = utcnow()
                    if t0 is not None:
                        inc.time_to_contain_seconds = round(time.monotonic() - t0, 2)
                    elif inc.started_at:
                        inc.time_to_contain_seconds = round((inc.contained_at - inc.started_at).total_seconds(), 2)
                inc.log("orchestrator", "Status -> CONTAINED")
        elif inc.status == Status.CONTAINED:
            inc.status = Status.INVESTIGATING
            inc.log("orchestrator", "Status -> INVESTIGATING (no active containment left)")

    async def _deliver(self, ctx: AgentContext, event: str, timeout: float) -> None:
        inc, c = ctx.incident, self.connectors

        async def guarded(name: str, coro: Awaitable) -> None:
            try:
                await asyncio.wait_for(coro, timeout=timeout)
            except Exception as exc:
                inc.log("delivery", f"{name} failed: {exc.__class__.__name__}: {exc}"[:300])
                log.warning("Delivery via %s failed: %s", name, exc)

        tasks = [guarded(n.name, n.send(inc, event)) for n in [c.feed, *c.notifiers]]
        tasks.append(guarded("SIEM write-back", c.siem.write_back(inc)))
        tasks.append(guarded("SIEM comment", c.siem.add_comment(inc, inc.report_markdown)))
        await asyncio.gather(*tasks)

    # ------------------------------------------------------------------ slow path
    async def _sandbox_followup(self, incident_id: str) -> None:
        inc = self.get(incident_id)
        if not inc:
            return
        ctx = self._ctx(inc)
        run = AgentRun(agent="Malware Analysis (sandbox)")
        start = time.monotonic()
        try:
            out = await asyncio.wait_for(investigate.analyze_malware(ctx), timeout=300)
            run.summary = out.summary
        except Exception as exc:
            run.ok, run.error = False, f"{exc.__class__.__name__}: {exc}"[:300]
        run.duration_ms = int((time.monotonic() - start) * 1000)
        if not inc.sandbox and run.ok:
            return  # nothing new to say
        async with self._lock(incident_id):
            inc.agent_runs.append(run)
            inc.log(run.agent, run.summary if run.ok else f"ERROR: {run.error}")
            if inc.sandbox:
                await self._act_on_sandbox(ctx)
            report.rerender(inc)
            self._save(inc)
            await self._deliver(ctx, "update", timeout=10)
            self._save(inc)

    async def _act_on_sandbox(self, ctx: AgentContext) -> None:
        """Block C2 infrastructure the sandbox revealed that the alert and telemetry did not."""
        inc = ctx.incident
        from .models import Indicator  # local import keeps the module header readable
        known = {i.key for i in inc.entities.indicators}
        new = []
        for ip in (inc.sandbox or {}).get("contacted_ips", []) or []:
            ind = Indicator(type=IndicatorType.IP, value=ip, context="discovered: sandbox detonation")
            if ind.key not in known:
                new.append(ind)
        for dom in (inc.sandbox or {}).get("contacted_domains", []) or []:
            ind = Indicator(type=IndicatorType.DOMAIN, value=dom, context="discovered: sandbox detonation")
            if ind.key not in known:
                new.append(ind)
        if not new:
            return
        inc.entities.indicators.extend(new)
        await investigate.enrich_indicators(ctx, new)
        if inc.verdict != Verdict.TRUE_POSITIVE:
            return
        proposals = response.plan_actions(ctx, indicators=new, include_hosts=False, include_accounts=False)
        inc.actions.extend(proposals)
        await asyncio.gather(*(response.execute_action(ctx, a) for a in proposals if a.status == ActionStatus.PLANNED))
        self._update_status(inc)

    async def _verify_isolation(self, incident_id: str) -> None:
        inc = self.get(incident_id)
        if not inc:
            return
        for _ in range(30):  # up to ~5 minutes
            await asyncio.sleep(10)
            pending = [a for a in inc.actions if a.status == ActionStatus.EXECUTED
                       and "confirmation pending" in a.result]
            if not pending:
                return
            changed = False
            for a in pending:
                ma = a.result.split("machine action ", 1)[-1].split(":", 1)[0]
                try:
                    status = await self.connectors.edr.action_status(ma)
                except Exception:
                    continue
                if status == "Succeeded":
                    a.result = f"Isolated (machine action {ma}: Succeeded, confirmed by device)"
                    changed = True
                elif status in {"Failed", "Cancelled", "TimeOut"}:
                    a.status = ActionStatus.FAILED
                    a.result = f"Isolation {status} on the device (machine action {ma})"
                    changed = True
            if changed:
                async with self._lock(incident_id):
                    self._update_status(inc)
                    report.rerender(inc)
                    self._save(inc)
                    event = "page" if any(a.status == ActionStatus.FAILED for a in inc.actions) else "update"
                    await self._deliver(self._ctx(inc), event, timeout=10)

    # ------------------------------------------------------------------ human decisions
    async def decide(self, incident_id: str, action_id: str, decision: str, actor: str) -> Incident:
        """decision: approve | reject | rollback"""
        inc = self.get(incident_id)
        if not inc:
            raise KeyError(f"Incident {incident_id} not found")
        self._remember(inc)
        async with self._lock(incident_id):
            action = inc.action(action_id)
            if not action:
                raise KeyError(f"Action {action_id} not found on incident {incident_id}")
            ctx = self._ctx(inc)
            if decision == "approve":
                if action.status not in (ActionStatus.PENDING_APPROVAL, ActionStatus.RECOMMENDED,
                                         ActionStatus.FAILED, ActionStatus.DENIED_BY_POLICY):
                    raise ValueError(f"Action is {action.status.value}; only pending, recommended, denied or "
                                     "failed actions can be approved")
                override = action.status == ActionStatus.DENIED_BY_POLICY
                self.store.audit(inc.id, "override" if override else "approved", actor, action_id=action.id,
                                 action_type=action.type, detail={"target": action.target})
                if override:
                    inc.log(actor, f"Human override of guardrail for {action.type.value} {action.target}")
                await response.execute_action(ctx, action, actor=actor)
            elif decision == "reject":
                if action.status not in (ActionStatus.PENDING_APPROVAL, ActionStatus.RECOMMENDED):
                    raise ValueError(f"Action is {action.status.value}; nothing to reject")
                action.status, action.decided_by = ActionStatus.REJECTED, actor
                inc.log(actor, f"Rejected {action.type.value} {action.target}")
                self.store.audit(inc.id, "rejected", actor, action_id=action.id, action_type=action.type,
                                 detail={"target": action.target})
            elif decision == "rollback":
                await response.rollback_action(ctx, action, actor)
            else:
                raise ValueError(f"Unknown decision {decision!r}")
            self._update_status(inc)
            report.rerender(inc)
            self._save(inc)
            await self._deliver(ctx, "update", timeout=10)
            self._save(inc)
            return inc

    async def set_status(self, incident_id: str, status: Status, actor: str,
                         verdict: Optional[Verdict] = None, note: str = "") -> Incident:
        inc = self.get(incident_id)
        if not inc:
            raise KeyError(f"Incident {incident_id} not found")
        if status not in (Status.REMEDIATED, Status.CLOSED, Status.INVESTIGATING):
            raise ValueError("Status can be set to remediated, closed or investigating")
        self._remember(inc)
        async with self._lock(incident_id):
            if verdict is not None:
                inc.verdict = verdict
            inc.status = status
            inc.log(actor, f"Status -> {status.value.upper()}" + (f" ({note})" if note else ""))
            self.store.audit(inc.id, f"status:{status.value}", actor, detail={"note": note,
                                                                               "verdict": inc.verdict.value})
            report.rerender(inc)
            self._save(inc)
            await self._deliver(self._ctx(inc), "update", timeout=10)
            self._save(inc)
            return inc
