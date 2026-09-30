"""Firewall blocking via a generic webhook, plus a composite that fans out to several blocklists."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import httpx

from ..models import Indicator
from .base import Blocklist, ConnectorError
from .http import request_json


class WebhookFirewall(Blocklist):
    """POSTs block/unblock requests to your firewall automation (Palo Alto, Fortinet, Check Point,
    an Azure Firewall IP-group Logic App, a SOAR, ...). Contract:

        POST {url}  {"action": "block"|"unblock", "type": "ip|domain|url|file_hash", "value": "...",
                     "title": "...", "description": "...", "expires": "2026-01-01T00:00:00Z", "ref": "..."}
        -> 2xx, optional JSON {"ref": "<id to use for unblock>"}
    """
    name = "Firewall webhook"

    def __init__(self, url: str, token: str, client: httpx.AsyncClient):
        self.url, self.token, self.client = url, token, client

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    async def block(self, indicator: Indicator, title: str, description: str, expires: datetime) -> str:
        body = {"action": "block", "type": indicator.type.value, "value": indicator.value, "title": title,
                "description": description,
                "expires": expires.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        data = await request_json(self.client, "POST", self.url, json=body, headers=self._headers(), retries=1) or {}
        ref = data.get("ref") if isinstance(data, dict) else None
        return "fw:" + json.dumps({"ref": ref, "type": indicator.type.value, "value": indicator.value})

    async def unblock(self, ref: str) -> None:
        try:
            info = json.loads(ref.split(":", 1)[1])
        except (IndexError, ValueError) as exc:
            raise ConnectorError(f"Bad firewall rollback reference {ref!r}") from exc
        await request_json(self.client, "POST", self.url, headers=self._headers(), retries=1,
                           json={"action": "unblock", "type": info.get("type"), "value": info.get("value"),
                                 "ref": info.get("ref")})


class CompositeBlocklist(Blocklist):
    """Blocks in every configured backend; the rollback reference remembers all of them."""
    name = "composite"

    def __init__(self, backends: list[Blocklist]):
        if not backends:
            raise ValueError("CompositeBlocklist needs at least one backend")
        self.backends = backends
        self.name = " + ".join(b.name for b in backends)

    async def block(self, indicator: Indicator, title: str, description: str, expires: datetime) -> str:
        refs, errors = [], []
        for b in self.backends:
            try:
                refs.append([b.name, await b.block(indicator, title, description, expires)])
            except ConnectorError as exc:
                errors.append(f"{b.name}: {exc}")
        if not refs:
            raise ConnectorError("; ".join(errors))
        return "multi:" + json.dumps({"refs": refs, "errors": errors})

    async def unblock(self, ref: str) -> None:
        if not ref.startswith("multi:"):
            raise ConnectorError(f"Bad composite rollback reference {ref!r}")
        info = json.loads(ref[len("multi:"):])
        by_name = {b.name: b for b in self.backends}
        for name, sub_ref in info.get("refs", []):
            backend = by_name.get(name)
            if backend:
                await backend.unblock(sub_ref)
