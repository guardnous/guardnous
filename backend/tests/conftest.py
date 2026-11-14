"""Shared test fixtures for the GuardNous test suite.

Provides:
- Async test DB (SQLite) with auto create/drop
- httpx.AsyncClient wired to the FastAPI app
- Auth helpers (register, login, get token headers)
- Factory helpers for scans and findings
- Sample IaC file fixtures
"""
import os
import pytest
from datetime import datetime, timezone

# ── Test environment ──────────────────────────────────────────────────────────
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///test.db"
os.environ["DATABASE_URL_SYNC"] = "sqlite:///test.db"
os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only"
os.environ["LLM_PROVIDER"] = "mock"
# The in-memory rate limiter would throttle fixtures that register/login per test
os.environ["RATE_LIMIT_ENABLED"] = "false"
if not os.environ.get("GUARDNOUS_PLUGIN_CACHE"):
    import tempfile
    os.environ["GUARDNOUS_PLUGIN_CACHE"] = tempfile.mkdtemp(prefix="gn-plugin-cache-")
if not os.environ.get("ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["ENCRYPTION_KEY"] = Fernet.generate_key().decode()

from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession

from app.main import app
from app.core.database import engine, Base, async_session
from app.models.finding import Finding
from app.models.scan import Scan

# ── Constants ─────────────────────────────────────────────────────────────────
TEST_PASSWORD = "Test123!"
TEST_EMAIL = "admin@testcorp.com"
TEST_ORG = "TestCorp"
TEST_NAME = "Test Admin"


# ── Database lifecycle ────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
async def setup_db():
    """Create all tables and seed RBAC before each test; drop them after.

    Permissions and system roles are seeded the same way application startup
    does, so a registered user gets a real role instead of no permissions.
    """
    from app.core.seed import _seed_default_tenant, _seed_permissions, _seed_system_roles

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with async_session() as db:
        await _seed_default_tenant(db)
        perm_map = await _seed_permissions(db)
        await _seed_system_roles(db, perm_map)
        await db.commit()
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


# ── HTTP client ───────────────────────────────────────────────────────────────

@pytest.fixture
async def client():
    """Async HTTP client wired to the FastAPI app via ASGITransport."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# ── Auth helpers ──────────────────────────────────────────────────────────────

async def register_user(
    client: AsyncClient,
    email: str = TEST_EMAIL,
    password: str = TEST_PASSWORD,
    full_name: str = TEST_NAME,
    org_name: str = TEST_ORG,
) -> dict:
    """Register a user and return the response JSON."""
    resp = await client.post("/api/v1/auth/register", json={
        "email": email,
        "password": password,
        "full_name": full_name,
        "organization_name": org_name,
    })
    assert resp.status_code == 201, f"Registration failed: {resp.text}"
    return resp.json()


async def login_user(
    client: AsyncClient,
    email: str = TEST_EMAIL,
    password: str = TEST_PASSWORD,
) -> dict:
    """Login and return the response JSON (contains access_token)."""
    resp = await client.post("/api/v1/auth/login", data={
        "username": email,
        "password": password,
    })
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    return resp.json()


async def get_auth_headers(
    client: AsyncClient,
    email: str = TEST_EMAIL,
    password: str = TEST_PASSWORD,
    full_name: str = TEST_NAME,
    org_name: str = TEST_ORG,
) -> dict:
    """Register + login and return Authorization headers."""
    await register_user(client, email, password, full_name, org_name)
    data = await login_user(client, email, password)
    return {"Authorization": f"Bearer {data['access_token']}"}


@pytest.fixture
async def auth_headers(client: AsyncClient) -> dict:
    """Fixture: register default user, login, return auth headers."""
    return await get_auth_headers(client)


@pytest.fixture
async def registered_user(client: AsyncClient) -> dict:
    """Fixture: register default user and return user data."""
    return await register_user(client)


# ── DB session for direct inserts ─────────────────────────────────────────────

@pytest.fixture
async def db_session():
    """Yield a raw async DB session for direct model inserts in tests."""
    async with async_session() as session:
        yield session


# ── Factory helpers ───────────────────────────────────────────────────────────

async def create_scan_in_db(
    db: AsyncSession,
    organization_id: int,
    scan_type: str = "terraform",
    status: str = "completed",
    file_name: str = "main.tf",
) -> "Scan":
    """Insert a Scan row directly and return it."""
    from app.models.scan import Scan

    scan = Scan(
        organization_id=organization_id,
        scan_type=scan_type,
        status=status,
        source="# test source",
        file_name=file_name,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)
    return scan


async def create_finding_in_db(
    db: AsyncSession,
    scan_id: int,
    severity: str = "HIGH",
    title: str = "Test Finding",
    rule_id: str = "TEST-001",
    status: str = "open",
) -> "Finding":
    """Insert a Finding row directly and return it."""
    from app.models.finding import Finding

    finding = Finding(
        scan_id=scan_id,
        rule_id=rule_id,
        title=title,
        description="Test finding description",
        severity=severity,
        category="iac",
        cloud_provider="aws",
        resource_type="aws_s3_bucket",
        resource_name="test-bucket",
        file_path="main.tf",
        line_number=10,
        remediation="Fix the thing",
        is_fixed=False,
        is_ignored=False,
        status=status,
    )
    db.add(finding)
    await db.flush()
    await db.refresh(finding)
    return finding


# ── Sample IaC file fixtures (preserved from original) ───────────────────────

@pytest.fixture
def sample_terraform():
    return open(
        os.path.join(os.path.dirname(__file__), "..", "sample_files", "insecure.tf")
    ).read()


@pytest.fixture
def sample_cloudformation():
    return open(
        os.path.join(os.path.dirname(__file__), "..", "sample_files", "insecure.yaml")
    ).read()


@pytest.fixture
def sample_bicep():
    return open(
        os.path.join(os.path.dirname(__file__), "..", "sample_files", "insecure.bicep")
    ).read()


@pytest.fixture
def secure_terraform():
    return '''
provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "secure" {
  bucket = "secure-bucket"
  tags = {
    Environment = "prod"
    Owner       = "security-team"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure" {
  bucket = aws_s3_bucket.secure.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "secure" {
  bucket                  = aws_s3_bucket.secure.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "secure" {
  bucket        = aws_s3_bucket.secure.id
  target_bucket = aws_s3_bucket.secure.id
  target_prefix = "logs/"
}

resource "aws_db_instance" "secure" {
  identifier              = "secure-db"
  engine                  = "mysql"
  instance_class          = "db.t3.micro"
  username                = var.db_username
  password                = var.db_password
  storage_encrypted       = true
  publicly_accessible     = false
  backup_retention_period = 14
  monitoring_interval     = 60
  monitoring_role_arn     = var.monitoring_role_arn
  ca_cert_identifier      = "rds-ca-2019"
  tags = {
    Environment = "prod"
  }
}

resource "aws_security_group" "secure" {
  name = "secure-sg"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.1.0/24"]
  }

  tags = {
    Environment = "prod"
  }
}
'''
