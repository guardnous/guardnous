from pydantic_settings import BaseSettings
from pydantic import field_validator
from typing import Optional


class Settings(BaseSettings):
    APP_NAME: str = "GuardNous"
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "development"  # development | staging | production

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://guardnous:guardnous@localhost:7000/guardnous"
    DATABASE_URL_SYNC: str = "postgresql+psycopg2://guardnous:guardnous@localhost:7000/guardnous"

    # Redis
    REDIS_URL: str = "redis://localhost:7001/0"

    # JWT
    SECRET_KEY: str = "change-me-in-production-use-openssl-rand-hex-32"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    # Password for the seeded admin, used only when that account is first created.
    # Empty: a random one is generated and logged once.
    INITIAL_ADMIN_PASSWORD: str = ""

    # Encryption key for VCS tokens (Fernet, 32-byte base64-encoded)
    ENCRYPTION_KEY: str = "change-me-generate-with-cryptography-fernet-generate-key"

    # GitHub OAuth
    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""
    GITHUB_CALLBACK_URL: str = ""  # auto-derived from BACKEND_URL if empty
    GITHUB_REDIRECT_URI: str = ""  # auto-derived from FRONTEND_URL if empty

    # GitHub App (enterprise — preferred over OAuth)
    GITHUB_APP_ID: str = ""
    GITHUB_APP_SLUG: str = "guardnous"
    GITHUB_APP_PRIVATE_KEY: str = ""  # PEM content (\\n-escaped) or absolute file path
    GITHUB_APP_WEBHOOK_SECRET: str = ""
    GITHUB_APP_CALLBACK_URL: str = ""  # auto-derived from FRONTEND_URL if empty

    # GitLab OAuth
    GITLAB_CLIENT_ID: str = ""
    GITLAB_CLIENT_SECRET: str = ""
    GITLAB_CALLBACK_URL: str = ""
    GITLAB_REDIRECT_URI: str = ""

    # Bitbucket OAuth
    BITBUCKET_CLIENT_ID: str = ""
    BITBUCKET_CLIENT_SECRET: str = ""
    BITBUCKET_REDIRECT_URI: str = ""

    # Azure DevOps OAuth
    AZURE_DEVOPS_CLIENT_ID: str = ""
    AZURE_DEVOPS_CLIENT_SECRET: str = ""
    AZURE_DEVOPS_REDIRECT_URI: str = ""

    # Legacy aliases (kept for backward compat)
    AZURE_CLIENT_ID: str = ""
    AZURE_CLIENT_SECRET: str = ""
    AZURE_CALLBACK_URL: str = ""

    # SMTP — Email delivery
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_USE_TLS: bool = True
    SMTP_FROM_EMAIL: str = "noreply@guardnous.io"
    SMTP_FROM_NAME: str = "GuardNous"

    # Webhook
    WEBHOOK_SECRET: str = "change-me-webhook-secret"

    # NVD API
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_API_KEY: Optional[str] = None
    DEPENDENCY_LICENSE_LOOKUP: bool = False  # opt-in: sends package names and versions to api.deps.dev

    # Celery
    CELERY_BROKER_URL: str = "redis://localhost:7001/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:7001/2"

    # CORS — accepts JSON list '["http://a","http://b"]' or comma-separated 'http://a,http://b'
    CORS_ORIGINS: list[str] = ["http://localhost:7003", "http://localhost:7002"]
    CORS_ALLOW_ALL: bool = False  # Set True for development or when behind a reverse proxy

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def _parse_cors_origins(cls, v):
        if isinstance(v, str):
            v = v.strip()
            if v.startswith("["):
                import json
                return json.loads(v)
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    # Demo installations only: allows sample (fictional) data to be loaded.
    # Never enable for a customer deployment.
    DEMO_DATA_ENABLED: bool = False

    # External scanner binaries are checked against a pinned SHA-256 before
    # every execution. enforce = block on mismatch, warn = log and run, off = skip.
    PLUGIN_INTEGRITY_MODE: str = "enforce"

    # Rate limiting
    RATE_LIMIT_ENABLED: bool = True
    # Number of trusted reverse proxies in front of the API. When > 0 the client
    # IP is read from X-Forwarded-For (that many hops from the right); leave 0
    # when the API is reached directly, otherwise the header can be spoofed.
    TRUSTED_PROXY_COUNT: int = 0

    # Frontend URL (for onboarding links)
    FRONTEND_URL: str = "http://localhost:7003"

    # Backend URL (for webhook callbacks and API self-references)
    BACKEND_URL: str = "http://localhost:7002"

    # Super admin email (for platform admin access)
    SUPER_ADMIN_EMAIL: str = "admin@guardnous.com"

    # ── AI / Agentic layer ──────────────────────────────────────────────
    # Provider-agnostic. Runs fully offline with "mock" (no API key required).
    # Public HTTPS address under which /.well-known/openid-configuration and jwks.json
    # are reachable from the internet. Cloud providers fetch them to verify tokens
    # GuardNous signs, so cloud accounts can be connected without stored secrets.
    # Empty = BACKEND_URL when that is https; otherwise secretless connection is off.
    OIDC_ISSUER_URL: str = ""
    # Optional public S3 URL of the generic AWS onboarding template, for a one-click
    # "Launch stack" link. Without it users download the template and deploy it.
    AWS_ONBOARDING_TEMPLATE_URL: str = ""
    # Days allowed to fix a finding, counted from when it was first seen. 0 = no SLA for that severity.
    SLA_DAYS_CRITICAL: int = 7
    SLA_DAYS_HIGH: int = 30
    SLA_DAYS_MEDIUM: int = 90
    SLA_DAYS_LOW: int = 180
    SLA_DAYS_INFO: int = 0
    AGENT_ENABLED: bool = True
    LLM_PROVIDER: str = "mock"  # mock | openai | azure | anthropic | ollama
    LLM_API_KEY: str = ""
    LLM_MODEL: str = "gpt-4o-mini"
    LLM_BASE_URL: str = ""  # override for azure / ollama / openai-compatible gateways
    LLM_API_VERSION: str = "2024-06-01"  # azure only
    LLM_TEMPERATURE: float = 0.2
    LLM_MAX_TOKENS: int = 1200
    AGENT_MAX_STEPS: int = 6  # max tool-calling iterations per turn
    # Durable agent runs
    AGENT_RUN_MAX_STEPS: int = 12             # model calls per run before it must conclude
    AGENT_RUN_STEP_CEILING: int = 24          # the most an agent's own step budget may raise that to
    # Start a Triage Agent run by itself when an assessment leaves open findings.
    # It only proposes; someone with agents:manage approves the list.
    AGENT_AUTO_TRIAGE_AFTER_SCAN: bool = False
    AGENT_RUN_MAX_TOKENS: int = 4096          # minimum output allowance per model call in a run
    AGENT_MONTHLY_TOKEN_BUDGET: int = 0       # per organization, input + output; 0 = unlimited
    AGENT_APPROVAL_TTL_HOURS: int = 72        # an undecided approval expires and counts as rejected
    AGENT_ALLOW_SELF_APPROVAL: bool = False   # let the requester approve their own external actions
    AGENT_RUN_STALE_MINUTES: int = 15         # a running run with no heartbeat this long is failed
    LLM_INPUT_PRICE_PER_MTOK: float = 0.0     # USD per million tokens; 0 = cost not shown
    LLM_OUTPUT_PRICE_PER_MTOK: float = 0.0

    # ── Edition ──────────────────────────────────────────────────────────
    # "community" (default, open-source) or "enterprise" (commercial license)
    EDITION: str = "community"

    # ── Stripe billing (optional — only used when EDITION=enterprise) ───
    STRIPE_SECRET_KEY: str = ""
    STRIPE_PUBLISHABLE_KEY: str = ""
    STRIPE_WEBHOOK_SECRET: str = ""
    STRIPE_PRICE_PRO: str = "price_pro_monthly"
    STRIPE_PRICE_ENTERPRISE: str = "price_enterprise_monthly"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()

# Auto-derive OAuth callback URLs from BACKEND_URL / FRONTEND_URL
_be = settings.BACKEND_URL.rstrip("/")
_fe = settings.FRONTEND_URL.rstrip("/")
if not settings.GITHUB_CALLBACK_URL:
    settings.GITHUB_CALLBACK_URL = f"{_be}/api/v1/integrations/github/callback"
if not settings.GITHUB_REDIRECT_URI:
    settings.GITHUB_REDIRECT_URI = f"{_fe}/integrations/callback"
if not settings.GITHUB_APP_CALLBACK_URL:
    settings.GITHUB_APP_CALLBACK_URL = f"{_fe}/integrations/callback"
if not settings.GITLAB_CALLBACK_URL:
    settings.GITLAB_CALLBACK_URL = f"{_be}/api/v1/integrations/gitlab/callback"
if not settings.GITLAB_REDIRECT_URI:
    settings.GITLAB_REDIRECT_URI = f"{_fe}/integrations/callback"
if not settings.BITBUCKET_REDIRECT_URI:
    settings.BITBUCKET_REDIRECT_URI = f"{_fe}/integrations/callback"
if not settings.AZURE_DEVOPS_REDIRECT_URI:
    settings.AZURE_DEVOPS_REDIRECT_URI = f"{_fe}/integrations/callback"
if not settings.AZURE_CALLBACK_URL:
    settings.AZURE_CALLBACK_URL = f"{_be}/api/v1/integrations/azure/callback"


def _validate_settings():
    import logging

    _log = logging.getLogger("guardnous.config")
    _is_prod = settings.ENVIRONMENT.lower() == "production"

    # --- SECRET_KEY ---
    if "change-me" in settings.SECRET_KEY:
        if _is_prod:
            raise RuntimeError(
                "CRITICAL: SECRET_KEY contains default placeholder and ENVIRONMENT=production. "
                "Set a secure random key: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        if settings.DEBUG:
            import secrets

            settings.SECRET_KEY = secrets.token_hex(32)
            _log.warning(
                "SECRET_KEY not set — auto-generated for dev. "
                "Set SECRET_KEY in .env for production."
            )
        else:
            raise RuntimeError(
                "CRITICAL: SECRET_KEY contains default placeholder. "
                "Set a secure random key: python -c \"import secrets; print(secrets.token_hex(32))\""
            )

    # --- DATABASE_URL ---
    _default_db = "localhost:7000/guardnous"
    if _is_prod and _default_db in settings.DATABASE_URL:
        raise RuntimeError(
            "CRITICAL: DATABASE_URL points to the default local database and ENVIRONMENT=production. "
            "Set DATABASE_URL to your production database connection string."
        )

    # --- ENCRYPTION_KEY ---
    if "change-me" in settings.ENCRYPTION_KEY or not settings.ENCRYPTION_KEY:
        if _is_prod:
            raise RuntimeError(
                "CRITICAL: ENCRYPTION_KEY contains default placeholder and ENVIRONMENT=production. "
                "Generate with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            )
        if settings.DEBUG:
            from cryptography.fernet import Fernet

            settings.ENCRYPTION_KEY = Fernet.generate_key().decode()
            _log.warning(
                "ENCRYPTION_KEY not set — auto-generated for dev. "
                "Set ENCRYPTION_KEY in .env for production. Encrypted data "
                "will NOT survive restarts without a stable key."
            )
        else:
            raise RuntimeError(
                "CRITICAL: ENCRYPTION_KEY contains default placeholder. "
                "Generate with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            )

    # --- WEBHOOK_SECRET ---
    # VCS webhooks are verified with each organization's own secret
    # (Organization.webhook_secret); this global value is not used for that.
    if "change-me" in settings.WEBHOOK_SECRET:
        settings.WEBHOOK_SECRET = ""


_validate_settings()
