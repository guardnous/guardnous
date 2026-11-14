from pydantic import BaseModel
from datetime import datetime
from typing import Optional


class ReportCreate(BaseModel):
    title: str = "Security Report"
    report_type: str = "security"  # security, compliance, executive
    format: str = "html"  # html, json, pdf, csv
    scan_ids: list[int] = []


class ReportResponse(BaseModel):
    id: int
    organization_id: int
    title: str
    report_type: str
    format: str
    status: str
    content: Optional[str] = None
    scan_ids: Optional[list] = []
    scan_id: Optional[int] = None
    file_name: Optional[str] = None
    file_size: Optional[int] = None
    name: Optional[str] = None
    created_at: datetime
    has_pdf: bool = False

    model_config = {"from_attributes": True}

    @classmethod
    def from_orm_with_pdf(cls, report):
        data = {
            "id": report.id,
            "organization_id": report.organization_id,
            "title": report.title,
            "report_type": report.report_type,
            "format": report.format,
            "status": report.status,
            "content": report.content,
            "scan_ids": report.scan_ids or [],
            "scan_id": report.scan_id,
            "file_name": report.file_name,
            "file_size": len(report.pdf_data) if report.pdf_data else None,
            "name": report.title,
            "created_at": report.created_at,
            "has_pdf": report.pdf_data is not None and len(report.pdf_data) > 0 if report.pdf_data else False,
        }
        return cls(**data)


class ReportViewResponse(BaseModel):
    id: int
    title: str
    report_type: str
    format: str
    status: str
    scan_id: Optional[int] = None
    file_name: Optional[str] = None
    created_at: datetime
    report_data: Optional[dict] = None
