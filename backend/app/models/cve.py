from sqlalchemy import Column, Integer, String, DateTime, Float, JSON, Text, Boolean
from sqlalchemy.sql import func
from app.core.database import Base


class CVE(Base):
    __tablename__ = "cves"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(50), unique=True, nullable=False, index=True)
    description = Column(Text)
    severity = Column(String(20), index=True)  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score = Column(Float)
    cvss_vector = Column(String(200))
    affected_packages = Column(JSON, default=list)
    fix_versions = Column(JSON, default=list)
    references = Column(JSON, default=list)  # [{"url": "...", "source_type": "official|vendor|aggregator|other"}]
    published_date = Column(DateTime(timezone=True))
    last_modified = Column(DateTime(timezone=True))
    fetched_at = Column(DateTime(timezone=True), server_default=func.now())
    source = Column(String(20), default="nvd", index=True)  # nvd, ghsa, osv
    epss_score = Column(Float, nullable=True)  # 0.0-1.0 exploit probability
    epss_percentile = Column(Float, nullable=True)  # 0.0-1.0 relative ranking
    is_kev = Column(Boolean, default=False, index=True)  # CISA Known Exploited Vulnerabilities catalog
    kev_date_added = Column(String(20), nullable=True)  # ISO date the CVE was added to CISA KEV
