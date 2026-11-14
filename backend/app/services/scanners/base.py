from dataclasses import dataclass, field
from typing import Optional
from abc import ABC, abstractmethod


@dataclass
class ScanResult:
    rule_id: str
    title: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str = "iac"
    cloud_provider: str = "aws"
    resource_type: str = ""
    resource_name: str = ""
    file_path: str = ""
    line_number: int = 0
    code_snippet: str = ""
    remediation: str = ""
    cve_id: Optional[str] = None
    metadata: dict = field(default_factory=dict)


class BaseScanner(ABC):
    @abstractmethod
    def scan(self, content: str, file_name: str = "") -> list[ScanResult]:
        pass

    @abstractmethod
    def detect_cloud_provider(self, content: str) -> str:
        pass
