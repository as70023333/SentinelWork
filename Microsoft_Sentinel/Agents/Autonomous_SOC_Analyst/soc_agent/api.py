"""HTTP API + dashboard (Starlette).

Endpoints
  GET  /                                   dashboard
  GET  /healthz                            liveness
  GET  /api/info                           mode, connectors, demo scenarios
  GET  /api/incidents                      incident list (summaries)
  GET  /api/incidents/{id}                 full incident + safe report HTML
  POST /api/incidents/{id}/actions/{aid}/{approve|reject|rollback}
  POST /api/incidents/{id}/status          {"status": "remediated|closed|investigating", "verdict"?, "note"?}
  POST /api/webhook/sentinel               Sentinel automation (Logic App) -> {"incidentArmId": "..."}
  POST /api/demo/run/{scenario}            demo mode only
  POST /api/demo/reset                     demo mode only
  GET  /api/environment                    simulated environment state + notification feed
  GET  /api/audit                          action audit log
"""
from __future__ import annotations

import asyncio
import contextlib
import hmac
import logging
from pathlib import Path
from typing import Any, Optional

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Route

from .config import Settings, load_settings
from .connectors.base import ConnectorError
from .models import Incident, Status, Verdict
from .render import markdown_to_safe_html
from .runtime import Runtime, build_runtime

log = logging.getLogger("soc_agent.api")
WEB_DIR = Path(__file__).resolve().parent / "web"


def incident_summary(inc: Incident) -> dict[str, Any]:
    return {
        "id": inc.id, "external_id": inc.external_id, "title": inc.title, "source": inc.source,
        "created": inc.created.isoformat(), "status": inc.status.value, "severity": inc.severity.value,
        "verdict": inc.verdict.value, "alert_class": inc.alert_class.value, "disposition": inc.disposition.value,
        "confidence": inc.assessment.confidence, "score": inc.assessment.score,
        "time_to_contain_seconds": inc.time_to_contain_seconds, "fast_path_seconds": inc.fast_path_seconds,
        "pending_approvals": sum(1 for a in inc.actions if a.status.value == "pending_approval"),
        "actions_executed": sum(1 for a in inc.actions if a.status.value == "executed"),
    }


def create_app(settings: Optional[Settings] = None, runtime: Optional[Runtime] = None) -> Starlette:
    settings = settings or (runtime.settings if runtime else load_settings())
    state: dict[str, Any] = {"runtime": runtime}

    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette):
        rt = state["runtime"] or build_runtime(settings)
        state["runtime"] = rt
        poller: Optional[asyncio.Task] = None
        if rt.settings.is_live and rt.settings.poll_sentinel:
            poller = asyncio.create_task(rt.orchestrator.poll_forever(), name="sentinel-poller")
        log.info("Autonomous SOC Analyst ready (%s mode)", rt.settings.mode)
        try:
            yield
        finally:
            if poller:
                poller.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await poller
            await rt.orchestrator.drain(timeout=5)
            await rt.aclose()

    def rt() -> Runtime:
        return state["runtime"]

    # ------------------------------------------------------------------ auth helpers
    def _key_ok(request: Request) -> bool:
        expected = rt().settings.webhook_key
        if not expected:
            return True
        supplied = request.headers.get("x-soc-key") or request.query_params.get("key") or ""
        auth = request.headers.get("authorization", "")
        if not supplied and auth.lower().startswith("bearer "):
            supplied = auth[7:]
        return hmac.compare_digest(supplied.encode(), expected.encode())

    def require_write(request: Request) -> Optional[JSONResponse]:
        if not _key_ok(request):
            return JSONResponse({"error": "missing or invalid API key (X-SOC-Key header)"}, status_code=401)
        return None

    def require_read(request: Request) -> Optional[JSONResponse]:
        if rt().settings.dashboard_public:
            return None
        return require_write(request)

    def actor(request: Request, body: dict[str, Any]) -> str:
        name = str(body.get("actor") or request.headers.get("x-soc-user") or "analyst").strip()
        return name[:80] or "analyst"

    async def json_body(request: Request) -> dict[str, Any]:
        try:
            data = await request.json()
        except Exception:
            return {}
        return data if isinstance(data, dict) else {}

    def demo_only() -> Optional[JSONResponse]:
        if rt().settings.is_live:
            return JSONResponse({"error": "only available in demo mode"}, status_code=404)
        return None

    # ------------------------------------------------------------------ routes
    async def dashboard(request: Request) -> Response:
        return FileResponse(WEB_DIR / "dashboard.html", headers={
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                                       "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                                       "connect-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff"})

    async def healthz(request: Request) -> Response:
        return JSONResponse({"ok": True, "mode": rt().settings.mode})

    async def info(request: Request) -> Response:
        if (err := require_read(request)):
            return err
        r = rt()
        return JSONResponse({
            **r.describe(),
            "write_key_required": bool(r.settings.webhook_key),
            "scenarios": r.connectors.world.scenario_list() if r.connectors.world else [],
        })

    async def list_incidents(request: Request) -> Response:
        if (err := require_read(request)):
            return err
        return JSONResponse([incident_summary(i) for i in rt().orchestrator.list(200)])

    async def get_incident(request: Request) -> Response:
        if (err := require_read(request)):
            return err
        inc = rt().orchestrator.get(request.path_params["incident_id"])
        if not inc:
            return JSONResponse({"error": "not found"}, status_code=404)
        data = inc.model_dump(mode="json", exclude={"raw"})
        data["report_html"] = markdown_to_safe_html(inc.report_markdown)
        return JSONResponse(data)

    async def decide(request: Request) -> Response:
        if (err := require_write(request)):
            return err
        if request.path_params["decision"] not in {"approve", "reject", "rollback"}:
            return JSONResponse({"error": "decision must be approve, reject or rollback"}, status_code=400)
        body = await json_body(request)
        try:
            inc = await rt().orchestrator.decide(request.path_params["incident_id"], request.path_params["action_id"],
                                                 request.path_params["decision"], actor(request, body))
        except KeyError as exc:
            return JSONResponse({"error": str(exc).strip("'")}, status_code=404)
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=409)
        except ConnectorError as exc:
            return JSONResponse({"error": str(exc)}, status_code=502)
        return JSONResponse(incident_summary(inc))

    async def set_status(request: Request) -> Response:
        if (err := require_write(request)):
            return err
        body = await json_body(request)
        try:
            status = Status(str(body.get("status", "")).lower())
            verdict = Verdict(str(body["verdict"]).lower()) if body.get("verdict") else None
        except ValueError:
            return JSONResponse({"error": "status must be remediated|closed|investigating; verdict must be "
                                          "true_positive|false_positive|benign_positive|undetermined"}, status_code=400)
        try:
            inc = await rt().orchestrator.set_status(request.path_params["incident_id"], status, actor(request, body),
                                                     verdict=verdict, note=str(body.get("note", ""))[:500])
        except KeyError as exc:
            return JSONResponse({"error": str(exc).strip("'")}, status_code=404)
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        return JSONResponse(incident_summary(inc))

    async def sentinel_webhook(request: Request) -> Response:
        if (err := require_write(request)):
            return err
        body = await json_body(request)
        ref = (body.get("incidentArmId") or body.get("incident_arm_id") or body.get("incidentId")
               or (body.get("object") or {}).get("id") or (body.get("object") or {}).get("name"))
        if not ref or not isinstance(ref, str):
            return JSONResponse({"error": "body must contain incidentArmId (the Sentinel incident ARM id)"},
                                status_code=400)
        try:
            inc = await rt().orchestrator.start(ref)
        except ConnectorError as exc:
            return JSONResponse({"error": str(exc)}, status_code=502)
        return JSONResponse({"accepted": True, "incident_id": inc.id, "external_id": inc.external_id},
                            status_code=202)

    async def demo_run(request: Request) -> Response:
        if (err := demo_only() or require_write(request)):
            return err
        scenario = request.path_params["scenario"]
        if scenario not in rt().connectors.world.scenarios:
            return JSONResponse({"error": f"unknown scenario {scenario}"}, status_code=404)
        inc = await rt().orchestrator.start(scenario)
        return JSONResponse({"accepted": True, "incident_id": inc.id}, status_code=202)

    async def demo_reset(request: Request) -> Response:
        if (err := demo_only() or require_write(request)):
            return err
        r = rt()
        await r.orchestrator.drain(timeout=10)
        r.store.clear()
        r.orchestrator._live.clear()
        r.connectors.world.reset()
        r.connectors.feed.items.clear()
        return JSONResponse({"ok": True})

    async def environment(request: Request) -> Response:
        if (err := require_read(request)):
            return err
        r = rt()
        return JSONResponse({"world": r.connectors.world.state() if r.connectors.world else None,
                             "feed": list(r.connectors.feed.items)[:30]})

    async def audit(request: Request) -> Response:
        if (err := require_read(request)):
            return err
        return JSONResponse(rt().store.audit_log(request.query_params.get("incident_id"), limit=300))

    routes = [
        Route("/", dashboard),
        Route("/healthz", healthz),
        Route("/api/info", info),
        Route("/api/incidents", list_incidents),
        Route("/api/incidents/{incident_id}", get_incident),
        Route("/api/incidents/{incident_id}/actions/{action_id}/{decision:str}", decide, methods=["POST"]),
        Route("/api/incidents/{incident_id}/status", set_status, methods=["POST"]),
        Route("/api/webhook/sentinel", sentinel_webhook, methods=["POST"]),
        Route("/api/demo/run/{scenario}", demo_run, methods=["POST"]),
        Route("/api/demo/reset", demo_reset, methods=["POST"]),
        Route("/api/environment", environment),
        Route("/api/audit", audit),
    ]
    return Starlette(routes=routes, lifespan=lifespan)
