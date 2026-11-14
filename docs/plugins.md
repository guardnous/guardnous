# Scanner plugins

[← Back to the README](../README.md)

### Adding a New Scanner

Put one Python file in `backend/app/services/plugins/adapters/` and restart the API and the workers. Every concrete `PluginAdapter` subclass defined in that file is registered, and it is enabled if its `health()` reports it available. A file that fails to load is skipped, the other scanners keep working, and the failure is shown on the Plugins page.

An adapter implements three methods. This one is complete and works as written:

```python
"""Flags plain-HTTP URLs in Terraform files."""
from __future__ import annotations

import re
from typing import Any

from app.services.plugins.base import PluginAdapter, PluginCapability, PluginHealth, PluginMetadata
from app.services.scanners.base import ScanResult

_HTTP_URL = re.compile(r"http://[^\s\"']+")


class PlainHttpAdapter(PluginAdapter):
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="plain_http",                 # unique id
            display_name="Plain HTTP URLs",
            version="1.0.0",
            description="Reports URLs that use http:// instead of https://.",
            homepage="https://example.com/plain-http",
            icon="Link",                       # lucide-react icon name
            capabilities=[PluginCapability.IAC_TERRAFORM],
            is_native=True,                    # runs in-process
            default_config={"severity": "MEDIUM"},
        )

    def health(self) -> PluginHealth:
        return PluginHealth(available=True, version="1.0.0")

    def scan(self, content: str, file_name: str = "", config: dict[str, Any] | None = None) -> list[ScanResult]:
        cfg = {**self.metadata().default_config, **(config or {})}
        results = []
        for number, line in enumerate(content.splitlines(), start=1):
            for url in _HTTP_URL.findall(line):
                results.append(ScanResult(
                    rule_id="PLAIN-HTTP-001",
                    title="Unencrypted HTTP URL",
                    description=f"{url} is fetched without TLS.",
                    severity=cfg["severity"],  # CRITICAL, HIGH, MEDIUM, LOW or INFO
                    category="iac",
                    file_path=file_name,
                    line_number=number,
                    code_snippet=line.strip(),
                    remediation="Use https://.",
                    metadata={"source": "plain_http"},
                ))
        return results
```

For a command-line tool, set `_binary = "<tool>"` on the class and `requires_binary=True` in the metadata, and have `health()` return `PluginHealth(available=False, message=...)` when `shutil.which` does not find it. The binary integrity check then applies to it as it does to the shipped scanners.

An adapter is code that runs inside the API and the workers, with their access. Only the packaged adapters directory is searched and that cannot be changed by a setting. Review an adapter as you would review any code you deploy.

### Scanner Trust Model

All 5 external adapters shell out to **real CLI binaries** installed on the host or container. We parse their structured output (JSON/SARIF) — we don't re-implement their detection logic. If you trust Checkov and Trivy individually, you can trust GuardNous's output from them.

---

