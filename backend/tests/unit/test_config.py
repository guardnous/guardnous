"""Tests for core application configuration."""
import os

os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only"
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///test.db")
os.environ.setdefault("DATABASE_URL_SYNC", "sqlite:///test.db")

from app.core.config import settings


class TestSettingsDefaults:
    def test_app_name(self):
        assert settings.APP_NAME == "GuardNous"

    def test_app_version(self):
        assert settings.APP_VERSION == "2.0.0"

    def test_access_token_expiry(self):
        assert settings.ACCESS_TOKEN_EXPIRE_MINUTES == 60

    def test_super_admin_email(self):
        assert settings.SUPER_ADMIN_EMAIL == "admin@guardnous.com"

    def test_algorithm_default(self):
        assert settings.ALGORITHM == "HS256"

    def test_llm_defaults(self):
        assert settings.LLM_PROVIDER == "mock"
        assert settings.LLM_MODEL == "gpt-4o-mini"
        assert settings.LLM_TEMPERATURE == 0.2
        assert settings.LLM_MAX_TOKENS == 1200

    def test_agent_max_steps(self):
        assert settings.AGENT_MAX_STEPS == 6

    def test_cors_origins_is_list(self):
        assert isinstance(settings.CORS_ORIGINS, list)


class TestSettingsOverride:
    def test_secret_key_from_env(self):
        assert settings.SECRET_KEY == "test-secret-key-for-testing-only"
