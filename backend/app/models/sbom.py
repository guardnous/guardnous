from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String, UniqueConstraint
from sqlalchemy.sql import func

from app.core.database import Base


class ScanDependencyInventory(Base):
    """The dependencies a repository scan parsed, kept so an SBOM can be exported later."""

    __tablename__ = "scan_dependency_inventories"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, unique=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    # [{"ecosystem", "name", "version", "path", "dev", "direct"}, ...] — one entry per manifest declaration
    components = Column(JSON, nullable=False, default=list)
    component_count = Column(Integer, nullable=False, default=0)
    # Result of the last licence lookup for this inventory; null until one has run
    licenses = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class PackageLicense(Base):
    """Licences of a published package version, as reported by deps.dev.

    Shared by all organizations: it holds only what the public registry data
    says about a public package. Packages deps.dev does not know are never
    written here, so a private package name cannot end up in this table.
    """

    __tablename__ = "package_licenses"

    id = Column(Integer, primary_key=True)
    system = Column(String(20), nullable=False)
    name = Column(String(300), nullable=False)
    version = Column(String(100), nullable=False)
    licenses = Column(JSON, nullable=False, default=list)  # SPDX expressions
    fetched_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("system", "name", "version", name="uq_package_licenses_package"),
    )
