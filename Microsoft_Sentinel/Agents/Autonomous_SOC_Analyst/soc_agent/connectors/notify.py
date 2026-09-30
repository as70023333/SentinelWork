"""Notification channels: console log, Microsoft Teams (Workflows webhook), generic webhook, pager."""
from __future__ import annotations

import logging
from typing import Any

import httpx

from ..models import ActionStatus, Disposition, Incident
from .base import Notifier
from .http import request_json

log = logging.getLogger("soc_agent.notify")

_EVENT_TITLE = {"report": "New incident handled", "update": "Incident report updated",
                "page": "PAGE: human attention required now"}


def incident_facts(incident: Incident) -> list[tuple[str, str]]:
    executed = [a for a in incident.actions if a.status == ActionStatus.EXECUTED]
    pending = [a for a in incident.actions if a.status == ActionStatus.PENDING_APPROVAL]
    facts = [
        ("Severity", incident.severity.value.upper()),
        ("Verdict", f"{incident.verdict.value.replace('_', ' ')} ({incident.assessment.confidence:.0%})"),
        ("Status", incident.status.value),
        ("Class", incident.alert_class.value.replace("_", " ")),
        ("Disposition", f"{incident.disposition.value.upper()} - {incident.disposition_reason}"),
        ("Actions taken", ", ".join(f"{a.type.value} {a.target}" for a in executed) or "none"),
    ]
    if pending:
        facts.append(("Awaiting approval", ", ".join(f"{a.type.value} {a.target}" for a in pending)))
    if incident.time_to_contain_seconds is not None:
        facts.append(("Time to contain", f"{incident.time_to_contain_seconds:.1f}s"))
    elif incident.fast_path_seconds is not None:
        facts.append(("Triage time", f"{incident.fast_path_seconds:.1f}s"))
    return facts


class ConsoleNotifier(Notifier):
    name = "console"

    async def send(self, incident: Incident, event: str) -> None:
        facts = "; ".join(f"{k}={v}" for k, v in incident_facts(incident)[:5])
        log.warning("[%s] %s | %s | %s", event.upper(), incident.title, facts, incident.executive_summary[:200])


class TeamsWorkflowNotifier(Notifier):
    """Posts an Adaptive Card to a Teams channel through a Power Automate / Teams Workflows
    'When a Teams webhook request is received' trigger."""
    name = "teams"

    def __init__(self, url: str, client: httpx.AsyncClient, public_url: str = ""):
        self.url, self.client, self.public_url = url, client, public_url

    def card(self, incident: Incident, event: str) -> dict[str, Any]:
        color = "Attention" if event == "page" or incident.disposition == Disposition.PAGE else \
            "Good" if incident.disposition == Disposition.AUTO_CLOSE else "Warning"
        body: list[dict[str, Any]] = [
            {"type": "TextBlock", "text": _EVENT_TITLE.get(event, event), "weight": "Bolder",
             "color": color, "size": "Small"},
            {"type": "TextBlock", "text": incident.title[:200], "weight": "Bolder", "size": "Large", "wrap": True},
            {"type": "FactSet", "facts": [{"title": k, "value": v[:300]} for k, v in incident_facts(incident)]},
            {"type": "TextBlock", "text": (incident.executive_summary or "Report pending.")[:1500], "wrap": True},
        ]
        content: dict[str, Any] = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                                   "type": "AdaptiveCard", "version": "1.4", "body": body}
        if self.public_url:
            content["actions"] = [{"type": "Action.OpenUrl", "title": "Open in SOC agent dashboard",
                                   "url": f"{self.public_url}/#/incident/{incident.id}"}]
        return {"type": "message", "attachments": [
            {"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None, "content": content}]}

    async def send(self, incident: Incident, event: str) -> None:
        await request_json(self.client, "POST", self.url, json=self.card(incident, event), retries=1)


def webhook_payload(incident: Incident, event: str, public_url: str = "") -> dict[str, Any]:
    return {
        "event": event,
        "incident_id": incident.id,
        "external_id": incident.external_id,
        "title": incident.title,
        "severity": incident.severity.value,
        "verdict": incident.verdict.value,
        "confidence": incident.assessment.confidence,
        "status": incident.status.value,
        "alert_class": incident.alert_class.value,
        "disposition": incident.disposition.value,
        "disposition_reason": incident.disposition_reason,
        "summary": incident.executive_summary,
        "report_markdown": incident.report_markdown,
        "actions": [{"type": a.type.value, "target": a.target, "status": a.status.value} for a in incident.actions],
        "time_to_contain_seconds": incident.time_to_contain_seconds,
        "url": f"{public_url}/#/incident/{incident.id}" if public_url else None,
    }


class WebhookNotifier(Notifier):
    """Generic JSON webhook (ServiceNow, Jira, Slack bridge, SOAR...). Receives every event."""
    name = "webhook"

    def __init__(self, url: str, client: httpx.AsyncClient, public_url: str = ""):
        self.url, self.client, self.public_url = url, client, public_url

    async def send(self, incident: Incident, event: str) -> None:
        await request_json(self.client, "POST", self.url, json=webhook_payload(incident, event, self.public_url),
                           retries=1)


class PagerNotifier(WebhookNotifier):
    """Only fires for 'page' events (PagerDuty/Opsgenie/on-call bridge)."""
    name = "pager"

    async def send(self, incident: Incident, event: str) -> None:
        if event == "page":
            await super().send(incident, event)
