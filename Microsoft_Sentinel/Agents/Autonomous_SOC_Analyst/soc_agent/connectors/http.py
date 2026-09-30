"""Shared HTTP plumbing: JSON requests with bounded retries, and Azure AD tokens.

No Azure SDK is required: tokens come from the OAuth2 client-credentials flow or
from the platform's managed identity endpoint.
"""
from __future__ import annotations

import asyncio
import os
import re
import time
from typing import Any, Optional

import httpx

from .base import ConnectorError

RETRY_STATUSES = {429, 500, 502, 503, 504}
USER_AGENT = "autonomous-soc-analyst/1.0"


def make_client(timeout: float = 15.0) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=httpx.Timeout(timeout, connect=5.0),
                             headers={"User-Agent": USER_AGENT})


def _short(text: str, n: int = 300) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    return text if len(text) <= n else text[: n - 3] + "..."


async def request_json(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    ok_404: bool = False,
    retries: int = 2,
    **kwargs: Any,
) -> Optional[Any]:
    """Send a request and return parsed JSON (None for 204 / empty / allowed 404).

    Retries 429/5xx a bounded number of times, honouring Retry-After up to 5 seconds so
    that a throttled API cannot blow the fast-path time budget.
    """
    attempt = 0
    while True:
        try:
            resp = await client.request(method, url, **kwargs)
        except httpx.HTTPError as exc:
            if attempt < retries:
                attempt += 1
                await asyncio.sleep(0.5 * attempt)
                continue
            raise ConnectorError(f"{method} {url.split('?')[0]} failed: {exc.__class__.__name__}: {exc}") from exc

        if resp.status_code in RETRY_STATUSES and attempt < retries:
            attempt += 1
            try:
                delay = float(resp.headers.get("Retry-After", "0"))
            except ValueError:
                delay = 0.0
            await asyncio.sleep(min(5.0, max(delay, 0.5 * attempt)))
            continue
        if resp.status_code == 404 and ok_404:
            return None
        if resp.status_code >= 400:
            raise ConnectorError(
                f"{method} {url.split('?')[0]} -> HTTP {resp.status_code}: {_short(resp.text)}",
                status=resp.status_code)
        if resp.status_code == 204 or not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return {"_text": resp.text}


class AzureTokenProvider:
    """Caches Azure AD access tokens per scope."""

    def __init__(self, tenant_id: str, client_id: str = "", client_secret: str = "",
                 use_managed_identity: bool = False, client: httpx.AsyncClient | None = None):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.use_managed_identity = use_managed_identity
        self._client = client or make_client()
        self._cache: dict[str, tuple[str, float]] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    async def token(self, scope: str) -> str:
        cached = self._cache.get(scope)
        if cached and cached[1] - 120 > time.time():
            return cached[0]
        lock = self._locks.setdefault(scope, asyncio.Lock())
        async with lock:
            cached = self._cache.get(scope)
            if cached and cached[1] - 120 > time.time():
                return cached[0]
            if self.use_managed_identity:
                tok, exp = await self._managed_identity(scope)
            else:
                tok, exp = await self._client_credentials(scope)
            self._cache[scope] = (tok, exp)
            return tok

    async def headers(self, scope: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {await self.token(scope)}"}

    async def _client_credentials(self, scope: str) -> tuple[str, float]:
        if not (self.tenant_id and self.client_id and self.client_secret):
            raise ConnectorError("Azure credentials missing: set AZURE_TENANT_ID, AZURE_CLIENT_ID, "
                                 "AZURE_CLIENT_SECRET (or USE_MANAGED_IDENTITY=true)")
        url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        data = await request_json(self._client, "POST", url, data={
            "client_id": self.client_id, "client_secret": self.client_secret,
            "scope": scope, "grant_type": "client_credentials"})
        if not data or "access_token" not in data:
            raise ConnectorError(f"Token response for {scope} did not contain an access_token")
        return data["access_token"], time.time() + float(data.get("expires_in", 3599))

    async def _managed_identity(self, scope: str) -> tuple[str, float]:
        resource = scope[:-len("/.default")] if scope.endswith("/.default") else scope
        endpoint, header = os.getenv("IDENTITY_ENDPOINT"), os.getenv("IDENTITY_HEADER")
        params = {"resource": resource}
        if endpoint and header:   # App Service, Functions, Container Apps
            params["api-version"] = "2019-08-01"
            if self.client_id:
                params["client_id"] = self.client_id
            data = await request_json(self._client, "GET", endpoint, params=params,
                                      headers={"X-IDENTITY-HEADER": header})
        else:                     # Azure VM / VMSS / AKS pod identity via IMDS
            params["api-version"] = "2018-02-01"
            if self.client_id:
                params["client_id"] = self.client_id
            data = await request_json(self._client, "GET",
                                      "http://169.254.169.254/metadata/identity/oauth2/token",
                                      params=params, headers={"Metadata": "true"})
        if not data or "access_token" not in data:
            raise ConnectorError("Managed identity endpoint did not return an access_token")
        try:
            expires = float(data.get("expires_on", 0))
        except (TypeError, ValueError):
            expires = 0.0
        if expires <= time.time():
            expires = time.time() + float(data.get("expires_in", 3000) or 3000)
        return data["access_token"], expires


# ----------------------------------------------------------------------- KQL safety
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
_UPN_RE = re.compile(r"^[A-Za-z0-9._%+'#$!&*=?^`{|}~-]+@[A-Za-z0-9.-]+$")
_HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")


def kql_string(value: str) -> str:
    """Return a safely quoted KQL string literal."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ").replace("\r", " ") + '"'


def require_hostname(value: str) -> str:
    if not _HOST_RE.match(value or ""):
        raise ConnectorError(f"Refusing to query with unexpected hostname value: {value!r}")
    return value


def require_upn(value: str) -> str:
    if not _UPN_RE.match(value or ""):
        raise ConnectorError(f"Refusing to query with unexpected UPN value: {value!r}")
    return value


def is_hash(value: str) -> bool:
    return bool(_HASH_RE.match(value or ""))
