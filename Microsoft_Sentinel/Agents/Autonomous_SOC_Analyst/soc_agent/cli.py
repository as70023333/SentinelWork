"""Command line interface.

    python -m soc_agent serve                 # API + dashboard on http://localhost:8080
    python -m soc_agent demo                  # run every demo scenario in the terminal
    python -m soc_agent demo -s ransomware_workstation
    python -m soc_agent run <sentinel-incident-arm-id-or-name>   # live: handle one real incident
    python -m soc_agent check                 # validate config, policy and (live) API permissions
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import textwrap
from typing import Any

from .config import load_settings

USE_COLOR = sys.stdout.isatty() and os.getenv("NO_COLOR") is None
_C = {"red": "31", "green": "32", "yellow": "33", "blue": "34", "cyan": "36", "grey": "90", "bold": "1"}


def c(text: Any, color: str) -> str:
    return f"\033[{_C[color]}m{text}\033[0m" if USE_COLOR else str(text)


SEV_COLOR = {"critical": "red", "high": "red", "medium": "yellow", "low": "green", "informational": "grey"}
DISP_COLOR = {"page": "red", "queue": "cyan", "auto_close": "green", "pending": "grey"}
ACT_COLOR = {"executed": "green", "pending_approval": "yellow", "denied_by_policy": "red", "failed": "red",
             "recommended": "grey", "rolled_back": "grey", "rejected": "grey"}


def _setup_logging(verbose: bool, quiet: bool) -> None:
    level = logging.INFO if verbose else logging.ERROR if quiet else logging.WARNING
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def print_incident(inc, expected: dict | None = None) -> bool:
    ok = True
    sev = c(inc.severity.value.upper(), SEV_COLOR.get(inc.severity.value, "grey"))
    disp = c(inc.disposition.value.upper(), DISP_COLOR.get(inc.disposition.value, "grey"))
    print(c(f"\n=== {inc.title}", "bold"))
    print(f"    {sev} | {inc.verdict.value} ({inc.assessment.confidence:.0%}) | {inc.alert_class.value} | "
          f"status {inc.status.value} | {disp} ({inc.disposition_reason})")
    ttc = f"{inc.time_to_contain_seconds:.2f}s" if inc.time_to_contain_seconds is not None else "n/a"
    fp = f"{inc.fast_path_seconds:.2f}s" if inc.fast_path_seconds is not None else "n/a"
    print(f"    time to contain {c(ttc, 'green')} | alert -> report delivered {c(fp, 'green')} | "
          f"evidence score {inc.assessment.score}/100 | report by {inc.report_generator}")
    for r in inc.agent_runs:
        mark = c("ok ", "green") if r.ok else c("ERR", "red")
        text = r.summary if r.ok else r.error
        print(c(f"    [{mark}] {r.agent:<38} {r.duration_ms:>6} ms  ", "grey") + textwrap.shorten(text or "", 110))
    for a in inc.actions:
        st = c(f"{a.status.value:<17}", ACT_COLOR.get(a.status.value, "grey"))
        print(f"    -> {a.type.value:<16} {a.target[:60]:<60} {st} {textwrap.shorten(a.result or a.policy_note, 70)}")
    print(textwrap.fill(inc.executive_summary, width=110, initial_indent="    ", subsequent_indent="    "))
    if expected:
        got = {"verdict": inc.verdict.value, "severity": inc.severity.value, "alert_class": inc.alert_class.value,
               "disposition": inc.disposition.value}
        diff = {k: (got.get(k), v) for k, v in expected.items() if got.get(k) != v}
        if diff:
            ok = False
            print(c(f"    EXPECTATION MISMATCH: {diff}", "red"))
        else:
            print(c("    matches the expected outcome for this scenario", "green"))
    return ok


async def cmd_demo(args) -> int:
    from .runtime import build_runtime
    from .store import Store

    os.environ.setdefault("SOC_MODE", "demo")
    settings = load_settings()
    if settings.is_live:
        print("The demo command only runs in demo mode (SOC_MODE=demo).")
        return 2
    if args.no_latency:
        settings.demo_latency = False
    rt = build_runtime(settings, store=Store(":memory:") if not args.persist else None)
    names = list(rt.connectors.world.scenarios) if args.scenario in (None, "all") else [args.scenario]
    all_ok = True
    try:
        for name in names:
            if name not in rt.connectors.world.scenarios:
                print(f"Unknown scenario {name!r}. Choose from: {', '.join(rt.connectors.world.scenarios)}")
                return 2
            print(c(f"\n>>> Firing demo alert: {rt.connectors.world.scenarios[name]['name']}", "cyan"))
            inc = await rt.orchestrator.handle(name)
            all_ok &= print_incident(inc, rt.connectors.world.scenarios[name].get("expected"))
            if args.report:
                print(c("\n--- IR report ---", "grey"))
                print(inc.report_markdown)
        if not args.no_wait:
            print(c("\n... waiting for slow-path work (sandbox detonations) to finish", "grey"))
            await rt.orchestrator.drain(timeout=60)
            for inc in rt.orchestrator.list():
                if inc.sandbox:
                    print(f"    sandbox update -> {inc.title}: {inc.sandbox.get('family')} "
                          f"(report v{inc.report_version})")
    finally:
        await rt.aclose()
    print(c("\nAll scenarios behaved as expected." if all_ok else "\nSome scenarios did not match!",
            "green" if all_ok else "red"))
    return 0 if all_ok else 1


async def cmd_run(args) -> int:
    from .runtime import build_runtime

    rt = build_runtime(load_settings())
    try:
        inc = await rt.orchestrator.handle(args.ref, force=args.force)
        print_incident(inc)
        if args.report:
            print(inc.report_markdown)
        await rt.orchestrator.drain(timeout=args.wait)
    finally:
        await rt.aclose()
    return 0


async def cmd_check(args) -> int:
    from .models import Indicator, IndicatorType
    from .policy import Policy

    settings = load_settings()
    failures = 0
    print(c(f"Mode: {settings.mode}", "bold"))
    problems = settings.validate()
    for p in problems:
        print(c(f"  [config] {p}", "red"))
    failures += len(problems)
    try:
        policy = Policy.load(settings.policy_path)
        print(c(f"  [policy] {settings.policy_path.name} OK: {len(policy.cfg.classification)} classification rules, "
                f"{len(policy.cfg.escalation)} escalation rules, autonomy "
                f"{'ON' if policy.cfg.autonomy.enabled else 'OFF'}", "green"))
    except Exception as exc:
        print(c(f"  [policy] INVALID: {exc}", "red"))
        return 1
    if problems:
        return 1

    from .runtime import build_runtime
    rt = build_runtime(settings)
    try:
        for k, v in rt.describe().items():
            print(f"  {k:<26} {v}")
        if not settings.is_live:
            print(c("\nDemo mode: nothing external to check. Run `python -m soc_agent demo`.", "green"))
            return 0
        from .connectors.defender import MDE, MDE_SCOPE
        from .connectors.http import request_json
        from .connectors.sentinel import ARM_SCOPE

        async def probe(name: str, coro) -> None:
            nonlocal failures
            try:
                result = await coro
                print(c(f"  [ok]   {name}", "green") + (f"  {result}" if result else ""))
            except Exception as exc:
                failures += 1
                print(c(f"  [FAIL] {name}: {exc}", "red"))

        tok = rt.connectors.siem.tokens  # type: ignore[attr-defined]
        print(c("\nMicrosoft APIs", "bold"))
        await probe("Azure AD token (ARM)", tok.token(ARM_SCOPE))
        await probe("Sentinel: list New incidents", _count(rt.connectors.siem.list_new()))
        la = rt.connectors.telemetry.la  # type: ignore[attr-defined]
        await probe("Log Analytics: SigninLogs query", _count(la.query("SigninLogs | take 1", "P1D")))
        hunting = rt.connectors.telemetry.hunting  # type: ignore[attr-defined]
        await probe("Defender XDR advanced hunting (Graph)", _count(hunting.query("DeviceInfo | take 1")))

        async def mde_machines():
            data = await request_json(rt.client, "GET", f"{MDE}/api/machines?$top=1",
                                      headers=await tok.headers(MDE_SCOPE))
            return f"{len((data or {}).get('value', []))} machine(s) readable"
        await probe("Defender for Endpoint API: read machines", mde_machines())
        print(c("\nThreat intel feeds (lookup of 8.8.8.8, a known-benign IP)", "bold"))
        probe_ind = Indicator(type=IndicatorType.IP, value="8.8.8.8")
        for p in rt.connectors.threat_intel:
            if IndicatorType.IP in p.supports:
                async def one(p=p):
                    r = await p.lookup(probe_ind)
                    return f"{r.verdict.value}: {r.summary}" if r else "no data (reachable)"
                await probe(p.name, one())
        if rt.connectors.llm:
            print(c("\nReport writer", "bold"))
            await probe(rt.connectors.llm.name, rt.connectors.llm.complete("Reply with OK.", "Say OK", 5))
    finally:
        await rt.aclose()
    print(c("\nAll checks passed." if not failures else f"\n{failures} check(s) failed.",
            "green" if not failures else "red"))
    return 0 if not failures else 1


async def _count(coro) -> str:
    rows = await coro
    return f"{len(rows)} row(s)"


def cmd_serve(args) -> int:
    import uvicorn

    from .api import create_app

    settings = load_settings()
    host = args.host or settings.host
    port = args.port or settings.port
    print(c(f"Autonomous SOC Analyst ({settings.mode} mode) -> http://{'localhost' if host == '0.0.0.0' else host}:{port}",
            "cyan"))
    uvicorn.run(create_app(settings), host=host, port=port, log_level="info" if args.verbose else "warning")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="soc_agent", description="Autonomous SOC Analyst for Microsoft Sentinel")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose logging")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("serve", help="run the API + dashboard")
    p.add_argument("--host")
    p.add_argument("--port", type=int)

    p = sub.add_parser("demo", help="run demo scenarios in the terminal")
    p.add_argument("-s", "--scenario", help="scenario id (default: all)")
    p.add_argument("--report", action="store_true", help="print the full IR report")
    p.add_argument("--no-latency", action="store_true", help="skip simulated API latency")
    p.add_argument("--no-wait", action="store_true", help="don't wait for sandbox follow-ups")
    p.add_argument("--persist", action="store_true", help="store incidents in the database (default: in memory)")

    p = sub.add_parser("run", help="handle one incident by reference (live: Sentinel ARM id or name)")
    p.add_argument("ref")
    p.add_argument("--force", action="store_true", help="process even if already handled")
    p.add_argument("--report", action="store_true")
    p.add_argument("--wait", type=float, default=60.0, help="seconds to wait for background work")

    sub.add_parser("check", help="validate configuration, policy and API permissions")

    args = parser.parse_args(argv)
    _setup_logging(args.verbose, quiet=args.cmd in {"demo", "check"})
    if args.cmd == "serve":
        return cmd_serve(args)
    runner = {"demo": cmd_demo, "run": cmd_run, "check": cmd_check}[args.cmd]
    try:
        return asyncio.run(runner(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
