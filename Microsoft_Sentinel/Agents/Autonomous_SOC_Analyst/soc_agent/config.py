"""Runtime settings, read from environment variables (and an optional .env file)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

try:  # python-dotenv is optional
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _float(name: str, default: float) -> float:
    raw = os.getenv(name)
    try:
        return float(raw) if raw not in (None, "") else default
    except ValueError:
        raise ValueError(f"Environment variable {name} must be a number, got {raw!r}") from None


def _int(name: str, default: int) -> int:
    return int(_float(name, default))


def _str(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()


@dataclass
class Settings:
    mode: str = "demo"                     # demo | live
    policy_path: Path = PROJECT_ROOT / "config" / "ir_policy.yaml"
    db_path: Path = PROJECT_ROOT / "data" / "soc_agent.db"
    demo_data_dir: Path = PROJECT_ROOT / "demo_data"
    demo_latency: bool = True              # simulate realistic API latency in demo mode

    host: str = "0.0.0.0"
    port: int = 8080
    public_url: str = ""                   # e.g. https://soc-agent.contoso.com (links in notifications)
    webhook_key: str = ""                  # shared secret for inbound webhooks / API writes
    dashboard_public: bool = True          # read-only dashboard without a key

    # time budget
    fast_path_budget_seconds: float = 28.0
    agent_timeout_seconds: float = 10.0

    # ingestion
    poll_sentinel: bool = False
    poll_interval_seconds: int = 30

    # Azure / Microsoft
    azure_tenant_id: str = ""
    azure_client_id: str = ""
    azure_client_secret: str = ""
    use_managed_identity: bool = False
    sentinel_subscription_id: str = ""
    sentinel_resource_group: str = ""
    sentinel_workspace_name: str = ""
    sentinel_workspace_id: str = ""        # Log Analytics workspace (customer) id, for KQL
    write_back_to_sentinel: bool = True

    # Containment backends
    identity_backend: str = "entra"        # entra | onprem | both
    ad_automation_webhook_url: str = ""    # Azure Automation webhook for on-prem AD runbook
    firewall_backend: str = "defender"     # defender | webhook | both
    firewall_webhook_url: str = ""
    firewall_webhook_token: str = ""

    # Threat intel keys (any subset)
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""
    greynoise_api_key: str = ""
    abusech_auth_key: str = ""             # MalwareBazaar / URLhaus
    ti_use_defender: bool = True           # Microsoft Defender TI via Sentinel TI table

    # Notifications
    teams_webhook_url: str = ""            # Teams Workflows "When a webhook request is received"
    generic_webhook_url: str = ""          # e.g. ServiceNow / PagerDuty / Jira bridge
    pager_webhook_url: str = ""            # called only when disposition == page

    # LLM report writer
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-5-5"
    llm_timeout_seconds: float = 12.0

    extra: dict = field(default_factory=dict)

    @property
    def is_live(self) -> bool:
        return self.mode == "live"

    @property
    def azure_configured(self) -> bool:
        return bool(self.azure_tenant_id and ((self.azure_client_id and self.azure_client_secret)
                                               or self.use_managed_identity))

    @property
    def sentinel_configured(self) -> bool:
        return bool(self.sentinel_subscription_id and self.sentinel_resource_group
                    and self.sentinel_workspace_name)

    def validate(self) -> list[str]:
        """Return a list of configuration problems (empty list = OK)."""
        problems: list[str] = []
        if self.mode not in {"demo", "live"}:
            problems.append(f"SOC_MODE must be 'demo' or 'live' (got {self.mode!r})")
        if not self.policy_path.exists():
            problems.append(f"IR policy file not found: {self.policy_path}")
        if self.identity_backend not in {"entra", "onprem", "both"}:
            problems.append("IDENTITY_BACKEND must be entra, onprem or both")
        if self.firewall_backend not in {"defender", "webhook", "both"}:
            problems.append("FIREWALL_BACKEND must be defender, webhook or both")
        if self.is_live:
            if not self.azure_configured:
                problems.append("Live mode needs AZURE_TENANT_ID plus AZURE_CLIENT_ID/AZURE_CLIENT_SECRET "
                                "(or USE_MANAGED_IDENTITY=true)")
            if not self.sentinel_configured:
                problems.append("Live mode needs SENTINEL_SUBSCRIPTION_ID, SENTINEL_RESOURCE_GROUP and "
                                "SENTINEL_WORKSPACE_NAME")
            if not self.sentinel_workspace_id:
                problems.append("Live mode needs SENTINEL_WORKSPACE_ID (Log Analytics workspace ID) for KQL")
            if self.identity_backend in {"onprem", "both"} and not self.ad_automation_webhook_url:
                problems.append("IDENTITY_BACKEND includes onprem but AD_AUTOMATION_WEBHOOK_URL is empty")
            if self.firewall_backend in {"webhook", "both"} and not self.firewall_webhook_url:
                problems.append("FIREWALL_BACKEND includes webhook but FIREWALL_WEBHOOK_URL is empty")
            if not self.webhook_key:
                problems.append("Live mode requires SOC_WEBHOOK_KEY so the API cannot be driven anonymously")
        if self.fast_path_budget_seconds <= 0:
            problems.append("FAST_PATH_BUDGET_SECONDS must be positive")
        return problems


def load_settings(env_file: str | os.PathLike | None = None) -> Settings:
    if load_dotenv is not None:
        load_dotenv(env_file or PROJECT_ROOT / ".env", override=False)

    def path(name: str, default: Path) -> Path:
        raw = _str(name)
        if not raw:
            return default
        p = Path(raw)
        return p if p.is_absolute() else PROJECT_ROOT / p

    return Settings(
        mode=_str("SOC_MODE", "demo").lower(),
        policy_path=path("SOC_POLICY_PATH", PROJECT_ROOT / "config" / "ir_policy.yaml"),
        db_path=path("SOC_DB_PATH", PROJECT_ROOT / "data" / "soc_agent.db"),
        demo_data_dir=path("SOC_DEMO_DATA_DIR", PROJECT_ROOT / "demo_data"),
        demo_latency=_bool("DEMO_LATENCY", True),
        host=_str("SOC_HOST", "0.0.0.0"),
        port=_int("SOC_PORT", 8080),
        public_url=_str("SOC_PUBLIC_URL").rstrip("/"),
        webhook_key=_str("SOC_WEBHOOK_KEY"),
        dashboard_public=_bool("SOC_DASHBOARD_PUBLIC", True),
        fast_path_budget_seconds=_float("FAST_PATH_BUDGET_SECONDS", 28.0),
        agent_timeout_seconds=_float("AGENT_TIMEOUT_SECONDS", 10.0),
        poll_sentinel=_bool("POLL_SENTINEL", False),
        poll_interval_seconds=_int("POLL_INTERVAL_SECONDS", 30),
        azure_tenant_id=_str("AZURE_TENANT_ID"),
        azure_client_id=_str("AZURE_CLIENT_ID"),
        azure_client_secret=_str("AZURE_CLIENT_SECRET"),
        use_managed_identity=_bool("USE_MANAGED_IDENTITY", False),
        sentinel_subscription_id=_str("SENTINEL_SUBSCRIPTION_ID"),
        sentinel_resource_group=_str("SENTINEL_RESOURCE_GROUP"),
        sentinel_workspace_name=_str("SENTINEL_WORKSPACE_NAME"),
        sentinel_workspace_id=_str("SENTINEL_WORKSPACE_ID"),
        write_back_to_sentinel=_bool("WRITE_BACK_TO_SENTINEL", True),
        identity_backend=_str("IDENTITY_BACKEND", "entra").lower(),
        ad_automation_webhook_url=_str("AD_AUTOMATION_WEBHOOK_URL"),
        firewall_backend=_str("FIREWALL_BACKEND", "defender").lower(),
        firewall_webhook_url=_str("FIREWALL_WEBHOOK_URL"),
        firewall_webhook_token=_str("FIREWALL_WEBHOOK_TOKEN"),
        virustotal_api_key=_str("VIRUSTOTAL_API_KEY"),
        abuseipdb_api_key=_str("ABUSEIPDB_API_KEY"),
        otx_api_key=_str("OTX_API_KEY"),
        greynoise_api_key=_str("GREYNOISE_API_KEY"),
        abusech_auth_key=_str("ABUSECH_AUTH_KEY"),
        ti_use_defender=_bool("TI_USE_DEFENDER", True),
        teams_webhook_url=_str("TEAMS_WEBHOOK_URL"),
        generic_webhook_url=_str("GENERIC_WEBHOOK_URL"),
        pager_webhook_url=_str("PAGER_WEBHOOK_URL"),
        anthropic_api_key=_str("ANTHROPIC_API_KEY"),
        anthropic_model=_str("ANTHROPIC_MODEL", "claude-sonnet-5-5"),
        llm_timeout_seconds=_float("LLM_TIMEOUT_SECONDS", 12.0),
    )
