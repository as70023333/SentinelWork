"""Identity containment: Microsoft Entra ID (Graph) and on-prem Active Directory (Azure Automation)."""
from __future__ import annotations

from urllib.parse import quote

import httpx

from ..models import Account
from .base import ConnectorError, IdentityProvider, UserInfo
from .http import AzureTokenProvider, request_json

GRAPH = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"


class EntraIdentity(IdentityProvider):
    def __init__(self, tokens: AzureTokenProvider, client: httpx.AsyncClient):
        self.tokens, self.client = tokens, client

    async def _h(self) -> dict[str, str]:
        return await self.tokens.headers(GRAPH_SCOPE)

    @staticmethod
    def _id(account: Account, info: UserInfo | None = None) -> str:
        ident = (info.object_id if info and info.object_id else None) or account.object_id or account.upn
        return quote(ident, safe="@")

    async def lookup(self, account: Account) -> UserInfo:
        headers = await self._h()
        sel = "id,displayName,userPrincipalName,accountEnabled,onPremisesSyncEnabled,onPremisesSamAccountName"
        u = await request_json(self.client, "GET", f"{GRAPH}/users/{self._id(account)}?$select={sel}",
                               headers=headers, ok_404=True)
        if not u:
            return UserInfo(upn=account.upn)
        info = UserInfo(upn=u.get("userPrincipalName") or account.upn, object_id=u.get("id"),
                        display_name=u.get("displayName") or "", enabled=u.get("accountEnabled"),
                        on_prem_synced=bool(u.get("onPremisesSyncEnabled")),
                        sam_account_name=u.get("onPremisesSamAccountName"))
        if not info.object_id:
            return info
        try:
            roles = await request_json(
                self.client, "GET",
                f"{GRAPH}/users/{quote(info.object_id)}/memberOf/microsoft.graph.directoryRole?$select=displayName",
                headers=headers) or {}
            info.privileged_roles = [r.get("displayName", "") for r in roles.get("value", []) if r.get("displayName")]
        except ConnectorError:
            pass  # missing RoleManagement.Read.Directory permission: treat as unknown
        try:
            risk = await request_json(self.client, "GET",
                                      f"{GRAPH}/identityProtection/riskyUsers/{quote(info.object_id)}",
                                      headers=headers, ok_404=True)
            if risk:
                info.risk_level = str(risk.get("riskLevel") or "none").lower()
        except ConnectorError:
            pass  # Entra ID P2 not licensed or permission missing
        return info

    async def _set_enabled(self, account: Account, info: UserInfo, enabled: bool) -> str:
        if info.on_prem_synced:
            raise ConnectorError(
                f"{account.upn} is synchronized from on-prem AD, so Entra ID cannot change accountEnabled. "
                "Set IDENTITY_BACKEND=both (or onprem) to disable it in Active Directory.")
        await request_json(self.client, "PATCH", f"{GRAPH}/users/{self._id(account, info)}",
                           headers=await self._h(), json={"accountEnabled": enabled}, retries=1)
        return f"entra:{info.object_id or account.upn}"

    async def disable(self, account: Account, info: UserInfo, reason: str) -> str:
        return await self._set_enabled(account, info, False)

    async def enable(self, account: Account, info: UserInfo, reason: str) -> str:
        return await self._set_enabled(account, info, True)

    async def revoke_sessions(self, account: Account, info: UserInfo) -> str:
        await request_json(self.client, "POST", f"{GRAPH}/users/{self._id(account, info)}/revokeSignInSessions",
                           headers=await self._h(), retries=1)
        return f"entra-revoke:{info.object_id or account.upn}"


class OnPremADIdentity(IdentityProvider):
    """Calls an Azure Automation webhook that runs deploy/runbooks/Invoke-SocADUserAction.ps1
    on a Hybrid Runbook Worker inside the domain."""

    def __init__(self, webhook_url: str, client: httpx.AsyncClient, lookup_delegate: IdentityProvider | None = None):
        self.webhook_url, self.client, self.lookup_delegate = webhook_url, client, lookup_delegate

    async def lookup(self, account: Account) -> UserInfo:
        if self.lookup_delegate:
            return await self.lookup_delegate.lookup(account)
        return UserInfo(upn=account.upn, sam_account_name=account.sam_account_name, on_prem_synced=True)

    async def _run(self, action: str, account: Account, info: UserInfo, reason: str) -> str:
        if not self.webhook_url:
            raise ConnectorError("AD_AUTOMATION_WEBHOOK_URL is not configured")
        body = {"action": action, "userPrincipalName": account.upn,
                "samAccountName": info.sam_account_name or account.sam_account_name, "reason": reason[:500],
                "requestedBy": "autonomous-soc-analyst"}
        data = await request_json(self.client, "POST", self.webhook_url, json=body, retries=1) or {}
        jobs = data.get("JobIds") or data.get("jobIds") or []
        return f"ad-runbook:{jobs[0] if jobs else 'submitted'}"

    async def disable(self, account: Account, info: UserInfo, reason: str) -> str:
        return await self._run("disable", account, info, reason)

    async def enable(self, account: Account, info: UserInfo, reason: str) -> str:
        return await self._run("enable", account, info, reason)

    async def revoke_sessions(self, account: Account, info: UserInfo) -> str:
        if self.lookup_delegate:
            return await self.lookup_delegate.revoke_sessions(account, info)
        raise ConnectorError("Session revocation requires Entra ID (IDENTITY_BACKEND=both)")


class HybridIdentity(IdentityProvider):
    """IDENTITY_BACKEND=both: synced users are disabled in AD, cloud-only users in Entra ID;
    sessions are always revoked in Entra ID."""

    def __init__(self, entra: EntraIdentity, onprem: OnPremADIdentity):
        self.entra, self.onprem = entra, onprem

    async def lookup(self, account: Account) -> UserInfo:
        return await self.entra.lookup(account)

    async def disable(self, account: Account, info: UserInfo, reason: str) -> str:
        if info.on_prem_synced:
            return await self.onprem.disable(account, info, reason)
        return await self.entra.disable(account, info, reason)

    async def enable(self, account: Account, info: UserInfo, reason: str) -> str:
        if info.on_prem_synced:
            return await self.onprem.enable(account, info, reason)
        return await self.entra.enable(account, info, reason)

    async def revoke_sessions(self, account: Account, info: UserInfo) -> str:
        return await self.entra.revoke_sessions(account, info)
