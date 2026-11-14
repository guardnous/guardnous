"""Scanner adapters are found by looking in the adapters package, not listed by hand.

The example adapter below is also the reference for the "Adding a New Scanner"
documentation: it is written to a temporary package and loaded by the same
function the application uses, so it is known to work with the real base class.
"""

import sys
import textwrap

import pytest

from app.services.plugins import registry as registry_module
from app.services.plugins.integrity import ensure_adapter_integrity
from app.services.plugins.registry import ADAPTERS_PACKAGE, PluginRegistry, discover_adapters, get_load_errors
from tests.test_agent_runtime import _user

SHIPPED = [
    "native_terraform", "native_cloudformation", "native_bicep", "native_secrets",
    "checkov", "trivy", "gitleaks", "semgrep", "tfsec",
]

EXAMPLE_ADAPTER = '''
"""Flags plain-HTTP URLs in Terraform files. A complete, minimal scanner adapter."""

from __future__ import annotations

import re
from typing import Any

from app.services.plugins.base import PluginAdapter, PluginCapability, PluginHealth, PluginMetadata
from app.services.scanners.base import ScanResult

_HTTP_URL = re.compile(r"http://[^\\s\\"']+")


class PlainHttpAdapter(PluginAdapter):
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="plain_http",                      # unique; this is the plugin's id everywhere
            display_name="Plain HTTP URLs",
            version="1.0.0",
            description="Reports URLs that use http:// instead of https://.",
            homepage="https://example.com/plain-http",
            icon="Link",
            capabilities=[PluginCapability.IAC_TERRAFORM],
            is_native=True,                         # runs in-process; no external program
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
                    severity=cfg["severity"],
                    category="iac",
                    file_path=file_name,
                    line_number=number,
                    code_snippet=line.strip(),
                    remediation="Use https://.",
                    metadata={"source": "plain_http"},
                ))
        return results
'''

EXTERNAL_TOOL_MISSING = '''
import shutil

from app.services.plugins.base import PluginAdapter, PluginCapability, PluginHealth, PluginMetadata


class NotInstalledAdapter(PluginAdapter):
    _binary = "guardnous-test-tool-that-is-not-installed"

    def metadata(self):
        return PluginMetadata(
            name="not_installed", display_name="Not installed", version="1.0.0", description="", homepage="",
            icon="Box", capabilities=[PluginCapability.SAST], requires_binary=True,
        )

    def health(self):
        found = shutil.which(self._binary)
        return PluginHealth(available=bool(found), message="" if found else f"'{self._binary}' not found on PATH")

    def scan(self, content, file_name="", config=None):
        return []
'''

NOT_ADAPTERS = '''
from abc import abstractmethod

from app.services.plugins.adapters.tfsec_adapter import TfsecAdapter   # imported, not defined here
from app.services.plugins.base import PluginAdapter, PluginHealth, PluginMetadata


class SharedBase(PluginAdapter):
    """Abstract: no scan()."""

    def health(self):
        return PluginHealth(available=True)

    @abstractmethod
    def flavour(self) -> str: ...


class _PrivateAdapter(PluginAdapter):
    def metadata(self):
        return PluginMetadata(name="private", display_name="", version="1", description="", homepage="", icon="",
                              capabilities=[])

    def health(self):
        return PluginHealth(available=True)

    def scan(self, content, file_name="", config=None):
        return []


class Helper:
    pass
'''

DUPLICATE_NAME = EXAMPLE_ADAPTER.replace("class PlainHttpAdapter", "class SecondPlainHttpAdapter")

CANNOT_BE_CREATED = '''
from app.services.plugins.base import PluginAdapter, PluginHealth, PluginMetadata


class NeedsArgumentsAdapter(PluginAdapter):
    def __init__(self, endpoint):
        self.endpoint = endpoint

    def metadata(self):
        return PluginMetadata(name="needs_arguments", display_name="", version="1", description="", homepage="",
                              icon="", capabilities=[])

    def health(self):
        return PluginHealth(available=True)

    def scan(self, content, file_name="", config=None):
        return []
'''


@pytest.fixture
def adapters_package(tmp_path, monkeypatch):
    """Write modules into a throwaway package and return (package name, writer)."""
    name = f"gn_test_adapters_{abs(hash(str(tmp_path)))}"
    package = tmp_path / name
    package.mkdir()
    (package / "__init__.py").write_text("")
    monkeypatch.syspath_prepend(str(tmp_path))

    def write(module: str, source: str) -> None:
        (package / f"{module}.py").write_text(textwrap.dedent(source))

    yield name, write
    for loaded in [m for m in sys.modules if m == name or m.startswith(f"{name}.")]:
        del sys.modules[loaded]


def test_every_shipped_adapter_is_still_registered_in_the_same_order():
    registry = PluginRegistry()

    errors = discover_adapters(registry)

    assert errors == []
    assert list(registry.list_all()) == SHIPPED
    assert [meta.name for meta in registry.list_plugins()] == SHIPPED
    for name in SHIPPED[:4]:                                            # native scanners are always on
        assert registry.is_enabled(name)
    for name, adapter in registry.list_all().items():                   # the rest only when their tool is installed
        assert registry.is_enabled(name) == adapter.health().available


def test_a_file_dropped_in_the_package_is_found_and_can_scan(adapters_package):
    package, write = adapters_package
    write("plain_http_adapter", EXAMPLE_ADAPTER)
    registry = PluginRegistry()

    assert discover_adapters(registry, package) == []

    adapter = registry.get("plain_http")
    assert adapter is not None and registry.is_enabled("plain_http")
    assert adapter.accepts("main.tf") and not adapter.accepts("notes.txt")
    results = adapter.scan('resource "x" "y" {\n  url = "http://internal.example/api"\n}\n', "main.tf")
    assert [(r.rule_id, r.severity, r.file_path, r.line_number) for r in results] == [
        ("PLAIN-HTTP-001", "MEDIUM", "main.tf", 2),
    ]
    assert adapter.scan("url = http://a.example", "main.tf", {"severity": "HIGH"})[0].severity == "HIGH"
    assert ensure_adapter_integrity(adapter) is None                    # no external binary: nothing to verify


def test_a_broken_file_is_reported_and_the_others_still_load(adapters_package, caplog):
    package, write = adapters_package
    write("a_broken_adapter", "import a_module_that_does_not_exist_anywhere\n")
    write("b_syntax_adapter", "class Oops(:\n")
    write("c_needs_arguments_adapter", CANNOT_BE_CREATED)
    write("plain_http_adapter", EXAMPLE_ADAPTER)
    registry = PluginRegistry()

    with caplog.at_level("ERROR", logger=registry_module.__name__):
        errors = discover_adapters(registry, package)

    assert list(registry.list_all()) == ["plain_http"]
    assert [(e["module"], e["adapter"]) for e in errors] == [
        (f"{package}.a_broken_adapter", ""),
        (f"{package}.b_syntax_adapter", ""),
        (f"{package}.c_needs_arguments_adapter", "NeedsArgumentsAdapter"),
    ]
    assert "ModuleNotFoundError" in errors[0]["error"] and "SyntaxError" in errors[1]["error"]
    assert f"{package}.a_broken_adapter" in caplog.text                 # the log names the file


def test_abstract_private_and_imported_classes_are_not_registered(adapters_package):
    package, write = adapters_package
    write("helpers", NOT_ADAPTERS)
    write("_ignored_module", "raise RuntimeError('modules starting with an underscore are not imported')\n")
    registry = PluginRegistry()

    assert discover_adapters(registry, package) == []
    assert registry.count == 0                                          # in particular: no second tfsec


def test_the_first_adapter_keeps_a_name_and_the_second_is_reported(adapters_package):
    package, write = adapters_package
    write("a_first", EXAMPLE_ADAPTER)
    write("b_second", DUPLICATE_NAME)
    registry = PluginRegistry()

    errors = discover_adapters(registry, package)

    assert type(registry.get("plain_http")).__module__ == f"{package}.a_first"
    assert len(errors) == 1 and errors[0]["adapter"] == "SecondPlainHttpAdapter"
    assert "Duplicate adapter name 'plain_http'" in errors[0]["error"] and "a_first.PlainHttpAdapter" in errors[0]["error"]


def test_an_adapter_whose_tool_is_missing_is_listed_but_disabled(adapters_package):
    package, write = adapters_package
    write("not_installed_adapter", EXTERNAL_TOOL_MISSING)
    write("plain_http_adapter", EXAMPLE_ADAPTER)
    registry = PluginRegistry()

    assert discover_adapters(registry, package) == []

    assert list(registry.list_all()) == ["not_installed", "plain_http"]            # sorted by module name
    assert not registry.is_enabled("not_installed") and registry.is_enabled("plain_http")
    assert list(registry.list_enabled()) == ["plain_http"]


def test_a_package_that_cannot_be_imported_is_an_error_not_a_crash():
    registry = PluginRegistry()

    errors = discover_adapters(registry, "gn_no_such_adapters_package")

    assert registry.count == 0 and errors[0]["module"] == "gn_no_such_adapters_package"


def test_the_application_only_looks_in_its_own_adapters_package():
    from app.core.config import settings

    assert ADAPTERS_PACKAGE == "app.services.plugins.adapters"
    assert not [name for name in type(settings).model_fields if "ADAPTER" in name]  # no setting can redirect discovery


async def test_a_new_adapter_and_the_load_errors_are_visible_through_the_api(
    db_session, client, adapters_package, monkeypatch,
):
    package, write = adapters_package
    write("a_broken_adapter", "raise RuntimeError('cannot start')\n")
    write("plain_http_adapter", EXAMPLE_ADAPTER)
    registry = PluginRegistry()
    errors = discover_adapters(registry, ADAPTERS_PACKAGE) + discover_adapters(registry, package)
    monkeypatch.setattr(registry_module, "_global_registry", registry)
    monkeypatch.setattr(registry_module, "_load_errors", errors)
    _, headers = await _user(db_session, client)

    listed = (await client.get("/api/v1/plugins", headers=headers)).json()
    by_name = {p["name"]: p for p in listed["plugins"]}
    assert [p["name"] for p in listed["plugins"]] == [*SHIPPED, "plain_http"]
    assert by_name["plain_http"]["enabled"] and by_name["plain_http"]["health"]["available"]
    assert by_name["plain_http"]["plugin_type"] == "native"

    resp = await client.get("/api/v1/plugins/load-errors", headers=headers)
    assert resp.status_code == 200, resp.text                           # not taken for /{plugin_name}
    assert resp.json()["total"] == 1
    assert resp.json()["load_errors"] == [
        {"module": f"{package}.a_broken_adapter", "adapter": "", "error": "RuntimeError: cannot start"},
    ]
    assert get_load_errors() == resp.json()["load_errors"]
    assert (await client.get("/api/v1/plugins/load-errors")).status_code in (401, 403)

    integrity = await client.get("/api/v1/plugins/integrity", headers=headers)
    assert integrity.status_code == 200                                 # the new adapter does not upset the gate
    assert "plain_http" not in [item["plugin"] for item in integrity.json()["items"]]

    toggled = await client.post("/api/v1/plugins/plain_http/toggle", headers=headers, json={"enabled": False})
    assert toggled.status_code == 200
    assert not registry.is_enabled("plain_http")
