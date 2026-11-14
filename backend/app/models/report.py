from sqlalchemy import Column, Integer, String, DateTime, JSON, ForeignKey, Text, LargeBinary
from sqlalchemy.sql import func
from app.core.database import Base
from sqlalchemy.orm import relationship


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    report_type = Column(String(50), default="security")  # security, compliance, executive
    format = Column(String(20), default="html")  # html, json, pdf
    status = Column(String(50), default="pending")  # pending, generating, completed, failed
    content = Column(Text)  # HTML/JSON content
    pdf_data = Column(LargeBinary, nullable=True)  # PDF binary data
    scan_ids = Column(JSON, default=list)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="SET NULL"), nullable=True)
    file_name = Column(String(500))  # meaningful filename for download
    metadata_ = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    organization = relationship("Organization", back_populates="reports")
