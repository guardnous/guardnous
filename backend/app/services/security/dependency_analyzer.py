"""
Enterprise Dependency Analyzer — parses package manifests and
cross-references with CVE database for known vulnerable dependencies.

Supports: package.json, requirements.txt, go.mod, Gemfile, pom.xml,
build.gradle, Cargo.toml, composer.json, Pipfile
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class Dependency:
    name: str
    version: Optional[str]
    ecosystem: str  # npm, pypi, go, rubygems, maven, cargo, composer
    file_path: str
    line_number: int = 0
    is_dev: bool = False   # declared for development/test only (devDependencies, require-dev, test scope, ...)
    direct: bool = True    # manifests declare direct dependencies; lock files are not parsed


@dataclass
class VulnerableDependency:
    dependency: Dependency
    cve_id: str
    severity: str
    title: str
    description: str
    fixed_version: Optional[str]
    cvss_score: Optional[float]
    remediation: str


MANIFEST_PARSERS = {}


def _register(file_names: list[str]):
    def wrapper(fn):
        for name in file_names:
            MANIFEST_PARSERS[name] = fn
        return fn
    return wrapper


@_register(["package.json"])
def _parse_package_json(content: str, file_path: str) -> list[Dependency]:
    deps = []
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return deps

    for section in ("dependencies", "devDependencies", "peerDependencies"):
        pkgs = data.get(section, {})
        if not isinstance(pkgs, dict):
            continue
        for name, version in pkgs.items():
            v = str(version).lstrip("^~>=<")
            deps.append(Dependency(name=name, version=v, ecosystem="npm", file_path=file_path,
                                   is_dev=section == "devDependencies"))
    return deps


@_register(["requirements.txt", "requirements-dev.txt", "requirements.in"])
def _parse_requirements_txt(content: str, file_path: str) -> list[Dependency]:
    deps = []
    file_name = file_path.replace("\\", "/").split("/")[-1].lower()
    is_dev = "dev" in file_name or "test" in file_name
    for i, line in enumerate(content.split("\n"), 1):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:[=<>!~]+\s*([^\s,;#]+))?", line)
        if m:
            deps.append(Dependency(
                name=m.group(1).lower(),
                version=m.group(2),
                ecosystem="pypi",
                file_path=file_path,
                line_number=i,
                is_dev=is_dev,
            ))
    return deps


@_register(["Pipfile"])
def _parse_pipfile(content: str, file_path: str) -> list[Dependency]:
    deps = []
    in_packages = False
    is_dev = False
    for i, line in enumerate(content.split("\n"), 1):
        stripped = line.strip()
        if stripped.startswith("["):
            in_packages = "packages" in stripped.lower()
            is_dev = "dev-packages" in stripped.lower()
            continue
        if in_packages and "=" in stripped:
            m = re.match(r'^([A-Za-z0-9_.-]+)\s*=\s*"?([^"]+)"?', stripped)
            if m:
                name = m.group(1).lower()
                version = m.group(2).strip().lstrip("=<>~!")
                if version == "*":
                    version = None
                deps.append(Dependency(name=name, version=version, ecosystem="pypi",
                                       file_path=file_path, line_number=i, is_dev=is_dev))
    return deps


@_register(["go.mod"])
def _parse_go_mod(content: str, file_path: str) -> list[Dependency]:
    deps = []
    in_require = False
    for i, line in enumerate(content.split("\n"), 1):
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require = True
            continue
        if stripped == ")":
            in_require = False
            continue
        if in_require or stripped.startswith("require "):
            m = re.match(r"(?:require\s+)?(\S+)\s+(v[\d.]+\S*)", stripped)
            if m:
                deps.append(Dependency(name=m.group(1), version=m.group(2),
                                       ecosystem="go", file_path=file_path, line_number=i))
    return deps


@_register(["Gemfile"])
def _parse_gemfile(content: str, file_path: str) -> list[Dependency]:
    deps = []
    dev_group = False
    for i, line in enumerate(content.split("\n"), 1):
        group = re.match(r"^\s*group\s+(.+?)\s+do\b", line)
        if group:
            names = set(re.findall(r":(\w+)", group.group(1)))
            dev_group = bool(names) and names <= {"development", "test"}
            continue
        if re.match(r"^\s*end\b", line):
            dev_group = False
            continue
        m = re.match(r"""^\s*gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?""", line)
        if m:
            version = m.group(2)
            if version:
                version = version.lstrip("~>=< ")
            deps.append(Dependency(name=m.group(1), version=version,
                                   ecosystem="rubygems", file_path=file_path, line_number=i,
                                   is_dev=dev_group))
    return deps


@_register(["pom.xml"])
def _parse_pom_xml(content: str, file_path: str) -> list[Dependency]:
    deps = []
    # Simple regex-based parser for Maven dependencies

    def tag(block: str, name: str) -> Optional[str]:
        m = re.search(rf"<{name}>\s*([^<]+?)\s*</{name}>", block)
        return m.group(1) if m else None

    for block in re.findall(r"<dependency>(.*?)</dependency>", content, re.DOTALL):
        block = re.sub(r"<exclusions>.*?</exclusions>", "", block, flags=re.DOTALL)
        group_id, artifact_id = tag(block, "groupId"), tag(block, "artifactId")
        if not group_id or not artifact_id:
            continue
        deps.append(Dependency(name=f"{group_id}:{artifact_id}", version=tag(block, "version"),
                               ecosystem="maven", file_path=file_path,
                               is_dev=tag(block, "scope") == "test"))
    return deps


@_register(["Cargo.toml"])
def _parse_cargo_toml(content: str, file_path: str) -> list[Dependency]:
    deps = []
    in_deps = False
    is_dev = False
    for i, line in enumerate(content.split("\n"), 1):
        stripped = line.strip()
        if stripped.startswith("["):
            section = stripped.lower()
            in_deps = "dependencies" in section
            is_dev = "dev-dependencies" in section or "build-dependencies" in section
            continue
        if in_deps and "=" in stripped:
            m = re.match(r'^([A-Za-z0-9_-]+)\s*=\s*"([^"]+)"', stripped)
            if m:
                deps.append(Dependency(name=m.group(1), version=m.group(2).lstrip("^~"),
                                       ecosystem="cargo", file_path=file_path, line_number=i,
                                       is_dev=is_dev))
            else:
                # version = { version = "x.y" } style
                m2 = re.match(r'^([A-Za-z0-9_-]+)\s*=\s*\{.*version\s*=\s*"([^"]+)"', stripped)
                if m2:
                    deps.append(Dependency(name=m2.group(1), version=m2.group(2).lstrip("^~"),
                                           ecosystem="cargo", file_path=file_path, line_number=i,
                                           is_dev=is_dev))
    return deps


@_register(["composer.json"])
def _parse_composer_json(content: str, file_path: str) -> list[Dependency]:
    deps = []
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return deps

    for section in ("require", "require-dev"):
        pkgs = data.get(section, {})
        if not isinstance(pkgs, dict):
            continue
        for name, version in pkgs.items():
            if name == "php" or name.startswith("ext-"):
                continue
            deps.append(Dependency(name=name, version=str(version).lstrip("^~>=<"),
                                   ecosystem="composer", file_path=file_path,
                                   is_dev=section == "require-dev"))
    return deps


@_register(["build.gradle", "build.gradle.kts"])
def _parse_build_gradle(content: str, file_path: str) -> list[Dependency]:
    deps = []
    # Matches: implementation 'group:artifact:version'  (and api/compile/testImplementation/etc.)
    # Both single and double quoted, Groovy and Kotlin DSL.
    pattern = re.compile(
        r"""(implementation|api|compile|testImplementation|runtimeOnly|"""
        r"""compileOnly|annotationProcessor|classpath|kapt)\s*"""
        r"""[(\s]?['\"]([\w.\-]+):([\w.\-]+):([\w.\-]+)['\"]""")
    for i, line in enumerate(content.split("\n"), 1):
        m = pattern.search(line)
        if m:
            group, artifact, version = m.group(2), m.group(3), m.group(4)
            deps.append(Dependency(name=f"{group}:{artifact}", version=version,
                                   ecosystem="maven", file_path=file_path, line_number=i,
                                   is_dev=m.group(1).startswith("test")))
    return deps


def supported_manifest_types() -> list[dict]:
    """Return the distinct manifest types this analyzer can parse.

    Filenames are grouped by their parser function, so each logical manifest
    type is listed once with all the file patterns it covers. Used to expose
    SBOM capabilities via the API.
    """
    by_parser: dict = {}
    for file_name, fn in MANIFEST_PARSERS.items():
        by_parser.setdefault(fn, []).append(file_name)

    types = []
    for fn, files in by_parser.items():
        label = fn.__name__.replace("_parse_", "").replace("_", ".")
        types.append({
            "type": label,
            "files": sorted(files),
            "ecosystem": _PARSER_ECOSYSTEM.get(fn.__name__, "unknown"),
        })
    return sorted(types, key=lambda t: t["type"])


_PARSER_ECOSYSTEM = {
    "_parse_package_json": "npm",
    "_parse_requirements_txt": "pypi",
    "_parse_pipfile": "pypi",
    "_parse_go_mod": "go",
    "_parse_gemfile": "rubygems",
    "_parse_pom_xml": "maven",
    "_parse_cargo_toml": "cargo",
    "_parse_composer_json": "composer",
    "_parse_build_gradle": "maven",
}


class DependencyAnalyzer:
    """Parse package manifests and check against known CVEs."""

    SUPPORTED_FILES = set(MANIFEST_PARSERS.keys())

    def is_manifest(self, file_path: str) -> bool:
        """Check if a file path is a recognized package manifest."""
        file_name = file_path.replace("\\", "/").split("/")[-1]
        return file_name in self.SUPPORTED_FILES

    def parse_manifest(self, content: str, file_path: str) -> list[Dependency]:
        """Parse a single manifest file into a list of dependencies."""
        file_name = file_path.replace("\\", "/").split("/")[-1]
        parser = MANIFEST_PARSERS.get(file_name)
        if not parser:
            return []
        try:
            return parser(content, file_path)
        except Exception as e:
            logger.warning(f"Failed to parse {file_path}: {e}")
            return []

    def check_vulnerabilities(
        self, dependencies: list[Dependency], cve_records: list[dict]
    ) -> list[VulnerableDependency]:
        """
        Cross-reference dependencies against CVE records from the DB.
        cve_records: list of dicts with keys: cve_id, severity, description,
                     affected_package, affected_versions, fixed_version, cvss_score
        """
        vuln_index: dict[str, list[dict]] = {}
        for cve in cve_records:
            pkg = (cve.get("affected_package") or "").lower()
            if pkg:
                vuln_index.setdefault(pkg, []).append(cve)

        findings: list[VulnerableDependency] = []
        for dep in dependencies:
            pkg_lower = dep.name.lower()
            matches = vuln_index.get(pkg_lower, [])
            for cve in matches:
                findings.append(VulnerableDependency(
                    dependency=dep,
                    cve_id=cve.get("cve_id", "UNKNOWN"),
                    severity=cve.get("severity", "MEDIUM"),
                    title=f"Vulnerable dependency: {dep.name}",
                    description=cve.get("description", "")[:500],
                    fixed_version=cve.get("fixed_version"),
                    cvss_score=cve.get("cvss_score"),
                    remediation=f"Upgrade {dep.name} to {cve.get('fixed_version', 'latest')}",
                ))

        return findings

    def analyze(
        self, files: dict[str, str], cve_records: list[dict] | None = None
    ) -> tuple[list[Dependency], list[VulnerableDependency], dict]:
        """
        Full analysis: parse all manifests, check vulnerabilities.
        files: {file_path: content}
        Returns (all_deps, vulnerable_deps, stats)
        """
        all_deps: list[Dependency] = []
        for path, content in files.items():
            if self.is_manifest(path):
                deps = self.parse_manifest(content, path)
                all_deps.extend(deps)

        vuln_deps: list[VulnerableDependency] = []
        if cve_records:
            vuln_deps = self.check_vulnerabilities(all_deps, cve_records)

        stats = {
            "total_dependencies": len(all_deps),
            "manifests_parsed": len({d.file_path for d in all_deps}),
            "vulnerable_count": len(vuln_deps),
            "by_ecosystem": {},
            "by_severity": {
                "CRITICAL": sum(1 for v in vuln_deps if v.severity == "CRITICAL"),
                "HIGH": sum(1 for v in vuln_deps if v.severity == "HIGH"),
                "MEDIUM": sum(1 for v in vuln_deps if v.severity == "MEDIUM"),
                "LOW": sum(1 for v in vuln_deps if v.severity == "LOW"),
            },
        }
        for d in all_deps:
            stats["by_ecosystem"][d.ecosystem] = stats["by_ecosystem"].get(d.ecosystem, 0) + 1

        return all_deps, vuln_deps, stats

    # ── SBOM Export (CycloneDX 1.5) ──────────────────────────────

    @staticmethod
    def export_sbom(
        dependencies: list["Dependency"],
        vulnerable: list["VulnerableDependency"] | None = None,
        *,
        repo_name: str = "unknown",
        licenses: dict[str, list[str]] | None = None,
        vulnerabilities: list[dict] | None = None,
        tool_version: str = "1.0.0",
    ) -> dict:
        """
        Export a CycloneDX 1.5 JSON SBOM from parsed dependencies.

        A package declared in several manifests becomes one component (its
        Package URL is the ``bom-ref``); it is ``required`` when any manifest
        declares it for production. Versions are the ones the manifests
        declare, so a version range is represented by its lower bound, and a
        version that is not a concrete release is left out.

        licenses:        {purl: [SPDX expression, ...]}
        vulnerabilities: [{"id", "severity", "score", "description", "recommendation",
                           "source": {"name", "url"}, "refs": [purl, ...], "detail",
                           "properties": {name: value}}]; an entry whose refs match no
                           component is attached to the repository itself.
        vulnerable:      results of ``check_vulnerabilities`` (matched by package name only).
        """
        import uuid
        from datetime import datetime, timezone

        merged: dict[str, dict] = {}
        for dep in dependencies:
            version = concrete_version(dep.version)
            purl = package_url(dep.ecosystem, dep.name, dep.version)
            entry = merged.get(purl)
            if entry is None:
                entry = merged[purl] = {
                    "dep": dep, "version": version, "files": [], "dev": True, "direct": False,
                }
            if dep.file_path and dep.file_path not in entry["files"]:
                entry["files"].append(dep.file_path)
            entry["dev"] = entry["dev"] and dep.is_dev
            entry["direct"] = entry["direct"] or dep.direct

        components = []
        for purl, entry in merged.items():
            dep = entry["dep"]
            comp: dict = {"type": "library", "bom-ref": purl}
            if dep.ecosystem == "maven" and ":" in dep.name:
                comp["group"], comp["name"] = dep.name.split(":", 1)
            else:
                comp["name"] = dep.name
            if entry["version"]:
                comp["version"] = entry["version"]
            comp["scope"] = "optional" if entry["dev"] else "required"
            licence_entries = _cyclonedx_licenses((licenses or {}).get(purl) or [])
            if licence_entries:
                comp["licenses"] = licence_entries
            comp["purl"] = purl
            properties = [
                {"name": "guardnous:ecosystem", "value": dep.ecosystem},
                {"name": "guardnous:scope", "value": "development" if entry["dev"] else "production"},
                {"name": "guardnous:dependency", "value": "direct" if entry["direct"] else "transitive"},
            ]
            properties += [{"name": "guardnous:source_file", "value": f} for f in entry["files"]]
            if dep.version and not entry["version"]:
                properties.append({"name": "guardnous:declared_version", "value": str(dep.version)})
            comp["properties"] = properties
            components.append(comp)

        root_ref = f"repo:{repo_name}"
        entries = list(vulnerabilities or [])
        for v in vulnerable or []:
            entries.append({
                "id": v.cve_id,
                "severity": v.severity,
                "score": v.cvss_score,
                "description": v.description,
                "recommendation": f"Upgrade to {v.fixed_version}" if v.fixed_version else None,
                "refs": [package_url(v.dependency.ecosystem, v.dependency.name, v.dependency.version)],
                "detail": "Matched by package name only; the affected version range was not checked.",
            })

        by_id: dict[str, dict] = {}
        for item in entries:
            vuln_id = item.get("id")
            if not vuln_id:
                continue
            refs = [r for r in (item.get("refs") or []) if r in merged] or [root_ref]
            out = by_id.get(vuln_id)
            if out is None:
                out = by_id[vuln_id] = {"id": vuln_id, "affects": []}
                source = item.get("source") or {}
                if source.get("name"):
                    out["source"] = {k: v for k, v in source.items() if v}
                rating: dict = {}
                if isinstance(item.get("score"), (int, float)) and item["score"]:
                    rating["score"] = float(item["score"])
                severity = str(item.get("severity") or "").lower()
                rating["severity"] = severity if severity in _CDX_SEVERITIES else "unknown"
                out["ratings"] = [rating]
                if item.get("description"):
                    out["description"] = item["description"]
                if item.get("recommendation"):
                    out["recommendation"] = item["recommendation"]
                # Nothing here proves the vulnerable code is reachable or even
                # present at the resolved version, so the state stays "in_triage".
                out["analysis"] = {"state": "in_triage"}
                if item.get("detail"):
                    out["analysis"]["detail"] = item["detail"]
                props = [{"name": k, "value": str(v)} for k, v in (item.get("properties") or {}).items()]
                if props:
                    out["properties"] = props
            for ref in refs:
                if {"ref": ref} not in out["affects"]:
                    out["affects"].append({"ref": ref})

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "tools": {"components": [{
                    "type": "application",
                    "group": "GuardNous",
                    "name": "guardnous-sca",
                    "version": tool_version,
                }]},
                "component": {
                    "type": "application",
                    "name": repo_name,
                    "bom-ref": root_ref,
                },
                "properties": [
                    {"name": "guardnous:version_source", "value": "manifest-declared"},
                    {"name": "guardnous:dependency_depth", "value": "direct-only"},
                ],
            },
            "components": components,
        }
        if by_id:
            sbom["vulnerabilities"] = list(by_id.values())

        return sbom


# ── Package URLs (https://github.com/package-url/purl-spec) ──────

PURL_TYPES = {
    "pypi": "pypi",
    "npm": "npm",
    "go": "golang",
    "maven": "maven",
    "nuget": "nuget",
    "rubygems": "gem",
    "cargo": "cargo",
    "composer": "composer",
}

_CDX_SEVERITIES = {"critical", "high", "medium", "low", "info", "none", "unknown"}

_CONCRETE_VERSION = re.compile(r"^v?\d+(?:\.\d+)*(?:[.\-+_][0-9A-Za-z.\-+_]*)?$")
_WILDCARD_PART = re.compile(r"(?:^|\.)[xX*](?:$|[.\-])")


def concrete_version(version: Optional[str]) -> Optional[str]:
    """The version if it names one release; None for ranges, wildcards, tags and URLs."""
    v = (version or "").strip()
    if not v or not _CONCRETE_VERSION.match(v) or _WILDCARD_PART.search(v):
        return None
    return v


def normalized_name(ecosystem: str, name: str) -> str:
    """The package name as its registry compares it."""
    name = (name or "").strip()
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem in ("npm", "composer", "go"):
        return name.lower()
    return name


def package_url(ecosystem: str, name: str, version: Optional[str] = None) -> str:
    """Package URL for a dependency, e.g. ``pkg:npm/%40scope/name@1.0.0``.

    The namespace separator differs per ecosystem: ``/`` for npm scopes, Go
    module paths and Composer vendors, ``:`` between Maven group and artifact.
    Every segment is percent-encoded. The version is included only when it is
    a concrete release.
    """
    from urllib.parse import quote

    purl_type = PURL_TYPES.get(ecosystem, "generic")
    name = normalized_name(ecosystem, name)
    if ecosystem == "maven":
        segments = name.split(":")[:2]
    elif ecosystem in ("npm", "go", "composer"):
        segments = name.split("/")
    else:
        segments = [name]
    path = "/".join(quote(s, safe="") for s in segments if s)
    purl = f"pkg:{purl_type}/{path}"
    v = concrete_version(version)
    return f"{purl}@{quote(v, safe='')}" if v else purl


def _cyclonedx_licenses(expressions: list[str]) -> list[dict]:
    """CycloneDX ``licenses`` for the SPDX expressions reported for a package."""
    from app.services.security.licenses import is_spdx_id

    expressions = [e.strip() for e in expressions if e and e.strip()]
    if not expressions:
        return []
    if any(" " in e or "(" in e for e in expressions):
        if any("non-standard" in e.lower() for e in expressions):
            return [{"license": {"name": e}} for e in expressions]
        if len(expressions) == 1:
            return [{"expression": expressions[0]}]
        return [{"expression": " AND ".join(f"({e})" for e in expressions)}]
    return [{"license": {"id": e} if is_spdx_id(e) else {"name": e}} for e in expressions]
