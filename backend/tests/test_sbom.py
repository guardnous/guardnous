"""SBOM export and licence checks: what a scan stores, what is exported, who may export it."""

import json
import re
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models.cve import CVE
from app.models.rbac import Role, UserRole
from app.models.sbom import PackageLicense, ScanDependencyInventory
from app.services.security import licenses
from app.services.security.dependency_analyzer import DependencyAnalyzer, concrete_version, package_url
from app.services.security.sbom_store import store_scan_inventory
from tests.conftest import create_finding_in_db, create_scan_in_db
from tests.test_agent_runtime import _user, get_auth_headers_for

MANIFESTS = {
    "web/package.json": json.dumps({
        "dependencies": {"@angular/core": "^17.0.0", "lodash": "4.17.20", "left-pad": "*"},
        "devDependencies": {"jest": "29.7.0"},
    }),
    "api/requirements.txt": "Django==3.2.0\ntyping_extensions==4.9.0\nrequests>=2.31.0\n",
    "svc/go.mod": "module example.com/svc\n\nrequire (\n\tgithub.com/gorilla/mux v1.8.0\n)\n",
    "java/pom.xml": """
        <project><dependencies>
          <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId>
            <version>2.14.1</version></dependency>
          <dependency><groupId>junit</groupId><artifactId>junit</artifactId>
            <version>4.13.2</version><scope>test</scope></dependency>
        </dependencies></project>""",
    "ruby/Gemfile": "source 'https://rubygems.org'\ngem 'rails', '7.0.4'\n",
    "rust/Cargo.toml": '[package]\nname = "x"\n\n[dependencies]\nserde = "1.0.190"\n',
    "php/composer.json": json.dumps({"require": {"php": ">=8.1", "monolog/monolog": "^3.5.0"}}),
    # the same package declared again elsewhere: one component, two source files
    "tools/package.json": json.dumps({"devDependencies": {"lodash": "4.17.20"}}),
}

EXPECTED_PURLS = {
    "pkg:npm/%40angular/core@17.0.0",
    "pkg:npm/lodash@4.17.20",
    "pkg:npm/left-pad",                      # "*" is not a version
    "pkg:npm/jest@29.7.0",
    "pkg:pypi/django@3.2.0",
    "pkg:pypi/typing-extensions@4.9.0",
    "pkg:pypi/requests@2.31.0",
    "pkg:golang/github.com/gorilla/mux@v1.8.0",
    "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
    "pkg:maven/junit/junit@4.13.2",
    "pkg:gem/rails@7.0.4",
    "pkg:cargo/serde@1.0.190",
    "pkg:composer/monolog/monolog@3.5.0",
}

PURL = re.compile(r"^pkg:(npm|pypi|golang|maven|gem|cargo|composer)/[A-Za-z0-9._~%/-]+(@[A-Za-z0-9._~%+-]+)?$")


async def _repo_scan(db, org, manifests=MANIFESTS, repo="acme/shop"):
    """A finished repository scan whose dependencies were stored the way the scan job stores them."""
    scan = await create_scan_in_db(db, org, scan_type="full")
    scan.repository_name = repo
    await db.flush()
    if manifests is not None:
        deps, _, _ = DependencyAnalyzer().analyze(manifests)
        await db.run_sync(lambda session: store_scan_inventory(session, scan, deps))
    await db.commit()
    return scan


async def _with_role(db, user, slug):
    """Make the user an ordinary member holding exactly one system role."""
    role = (await db.execute(select(Role).where(Role.slug == slug))).scalar_one()
    await db.execute(UserRole.__table__.delete().where(UserRole.user_id == user.id))
    db.add(UserRole(user_id=user.id, role_id=role.id))
    user.role = "member"
    await db.commit()


def _cve(cve_id, affected, **fields):
    return CVE(cve_id=cve_id, description=f"{cve_id} description", severity=fields.pop("severity", "HIGH"),
               affected_packages=affected, **fields)


async def _export(client, headers, scan):
    resp = await client.get(f"/api/v1/sbom/scans/{scan.id}", headers=headers)
    assert resp.status_code == 200, resp.text
    return resp, json.loads(resp.content)


async def _summary(client, headers, scan):
    resp = await client.get(f"/api/v1/sbom/scans/{scan.id}/summary", headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.fixture
def deps_dev(monkeypatch):
    """Stand in for api.deps.dev. `replies` maps "system/name@version" to licences, a status or an error."""
    calls: list[str] = []
    replies: dict = {}
    real_client = httpx.AsyncClient

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "api.deps.dev"
        m = re.match(r"^/v3/systems/([^/]+)/packages/([^/]+)/versions/([^/]+)$", request.url.raw_path.decode())
        assert m, f"unexpected deps.dev path {request.url.raw_path!r}"
        key = f"{m.group(1)}/{m.group(2)}@{m.group(3)}"
        calls.append(key)
        reply = replies.get(key, 404)
        if isinstance(reply, Exception):
            raise reply
        if isinstance(reply, int):
            return httpx.Response(reply, json={"error": "no"})
        return httpx.Response(200, json={"versionKey": {}, "licenses": reply})

    monkeypatch.setattr(licenses.httpx, "AsyncClient",
                        lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw))
    return SimpleNamespace(calls=calls, replies=replies)


@pytest.fixture
def lookup_on(monkeypatch):
    monkeypatch.setattr(settings, "DEPENDENCY_LICENSE_LOOKUP", True)


# ── Package URLs ────────────────────────────────────────────────────

@pytest.mark.parametrize("ecosystem, name, version, expected", [
    ("npm", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21"),
    ("npm", "@scope/name", "1.0.0", "pkg:npm/%40scope/name@1.0.0"),
    ("pypi", "Typing_Extensions", "4.9.0", "pkg:pypi/typing-extensions@4.9.0"),
    ("go", "github.com/Gorilla/Mux", "v1.8.0", "pkg:golang/github.com/gorilla/mux@v1.8.0"),
    ("go", "gopkg.in/yaml.v2", "v2.4.0+incompatible", "pkg:golang/gopkg.in/yaml.v2@v2.4.0%2Bincompatible"),
    ("maven", "org.apache.commons:commons-lang3", "3.12.0", "pkg:maven/org.apache.commons/commons-lang3@3.12.0"),
    ("rubygems", "rails", "7.0.4", "pkg:gem/rails@7.0.4"),
    ("cargo", "serde", "1.0.190", "pkg:cargo/serde@1.0.190"),
    ("composer", "Monolog/Monolog", "3.5.0", "pkg:composer/monolog/monolog@3.5.0"),
    ("npm", "left-pad", None, "pkg:npm/left-pad"),
    ("maven", "com.acme:lib", "${lib.version}", "pkg:maven/com.acme/lib"),
])
def test_package_urls_follow_the_purl_rules_of_each_ecosystem(ecosystem, name, version, expected):
    assert package_url(ecosystem, name, version) == expected


def test_only_a_concrete_release_counts_as_a_version():
    assert [concrete_version(v) for v in ("1.2.3", "v1.8.0", "1.0.0-beta.1", "5.3.0.RELEASE")] == \
        ["1.2.3", "v1.8.0", "1.0.0-beta.1", "5.3.0.RELEASE"]
    assert [concrete_version(v) for v in ("*", "latest", "1.x", "1.0 <2", "git+https://x/y.git", "", None)] == [None] * 7


def test_manifests_tell_development_from_production_dependencies():
    deps, _, _ = DependencyAnalyzer().analyze({
        **MANIFESTS,
        "Pipfile": '[packages]\nflask = "==3.0.0"\n\n[dev-packages]\npytest = "==8.0.0"\n',
        "Gemfile": "gem 'puma', '6.4.0'\ngroup :development, :test do\n  gem 'rspec', '3.12.0'\nend\ngem 'pg', '1.5.4'\n",
        "Cargo.toml": '[dependencies]\ntokio = "1.35.0"\n\n[dev-dependencies]\ncriterion = "0.5.1"\n',
        "composer.json": json.dumps({"require-dev": {"phpunit/phpunit": "^10.5.0"}}),
        "build.gradle": "implementation 'com.google.guava:guava:32.1.3-jre'\ntestImplementation 'org.mockito:mockito-core:5.8.0'\n",
        "requirements-dev.txt": "black==24.1.0\n",
    })
    dev = {d.name for d in deps if d.is_dev}

    assert dev == {"jest", "lodash", "junit:junit", "pytest", "rspec", "criterion", "phpunit/phpunit",
                   "org.mockito:mockito-core", "black"}
    assert {d.name for d in deps if d.name == "lodash" and not d.is_dev}      # also a production dependency
    assert all(d.direct for d in deps)


# ── The exported document ───────────────────────────────────────────

async def test_export_is_a_valid_cyclonedx_document_with_a_purl_for_every_component(db_session, client):
    user, headers = await _user(db_session, client)
    scan = await _repo_scan(db_session, user.organization_id)

    resp, bom = await _export(client, headers, scan)

    assert resp.headers["content-type"].startswith("application/vnd.cyclonedx+json")
    assert resp.headers["content-disposition"] == f'attachment; filename="sbom-acme-shop-{scan.id}.cdx.json"'
    assert (bom["bomFormat"], bom["specVersion"]) == ("CycloneDX", "1.5")
    assert re.fullmatch(r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", bom["serialNumber"])
    assert type(bom["version"]) is int and bom["version"] >= 1
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", bom["metadata"]["timestamp"])
    assert bom["metadata"]["tools"]["components"][0]["name"] == "guardnous-sca"
    assert bom["metadata"]["component"] == {"type": "application", "name": "acme/shop", "bom-ref": "repo:acme/shop"}

    components = bom["components"]
    assert {c["purl"] for c in components} == EXPECTED_PURLS
    refs = [c["bom-ref"] for c in components] + [bom["metadata"]["component"]["bom-ref"]]
    assert len(refs) == len(set(refs))
    for c in components:
        assert c["type"] == "library" and c["name"] and PURL.match(c["purl"]), c
        assert c["scope"] in ("required", "optional")
        assert ("@" in c["purl"].split("/", 1)[1]) == ("version" in c)          # a version exactly when it is known
        assert "licenses" not in c                                             # lookup is off by default
    by_purl = {c["purl"]: c for c in components}
    assert (by_purl["pkg:maven/junit/junit@4.13.2"]["group"], by_purl["pkg:maven/junit/junit@4.13.2"]["name"]) == ("junit", "junit")
    assert by_purl["pkg:npm/%40angular/core@17.0.0"]["name"] == "@angular/core"
    assert {"name": "guardnous:declared_version", "value": "*"} in by_purl["pkg:npm/left-pad"]["properties"]
    # scope: development only when no manifest needs it in production
    assert by_purl["pkg:npm/jest@29.7.0"]["scope"] == "optional"
    assert by_purl["pkg:maven/junit/junit@4.13.2"]["scope"] == "optional"
    lodash = by_purl["pkg:npm/lodash@4.17.20"]
    assert lodash["scope"] == "required"
    assert [p["value"] for p in lodash["properties"] if p["name"] == "guardnous:source_file"] == \
        ["web/package.json", "tools/package.json"]
    assert "vulnerabilities" not in bom                                        # nothing in the CVE table


async def test_vulnerabilities_come_from_the_cve_table_and_point_at_real_components(db_session, client):
    user, headers = await _user(db_session, client)
    scan = await _repo_scan(db_session, user.organization_id)
    db_session.add_all([
        _cve("CVE-2021-23337", [{"vendor": "npm", "product": "lodash", "version_start": "< 4.17.21", "version_end": ""}],
             fix_versions=["4.17.21"], cvss_score=7.2, epss_score=0.42, source="ghsa"),
        _cve("CVE-2021-44228", [{"vendor": "maven", "product": "org.apache.logging.log4j:log4j-core",
                                 "version_start": ">= 2.0.0", "version_end": ""}],
             severity="CRITICAL", cvss_score=10.0, is_kev=True, source="ghsa"),
        _cve("CVE-2021-33203", [{"vendor": "djangoproject", "product": "django", "version_start": "3.2", "version_end": "3.2.4"}],
             severity="MEDIUM", cvss_score=4.9),
        # none of these may match:
        _cve("CVE-2019-10744", [{"vendor": "npm", "product": "lodash", "version_start": "< 4.17.12", "version_end": ""}]),  # fixed before 4.17.20
        _cve("CVE-2000-0001", [{"vendor": "pip", "product": "lodash", "version_start": "", "version_end": ""}]),            # another ecosystem
        _cve("CVE-2000-0002", [{"vendor": "acme", "product": "requests", "version_start": "", "version_end": ""}]),         # CPE name, no range
        _cve("CVE-2000-0003", [{"vendor": "djangoproject", "product": "django", "version_start": "", "version_end": "3.1.9"}]),  # older branch
        _cve("CVE-2000-0004", [{"vendor": "rails", "product": "core", "version_start": "", "version_end": "99"}]),          # not @angular/core
        _cve("CVE-2000-0005", [{"vendor": "npm", "product": "lodash-es", "version_start": "< 9", "version_end": ""}]),      # a different package
    ])
    reported = await create_finding_in_db(db_session, scan.id, title="Outdated base image")
    reported.cve_id = "CVE-2099-0001"
    await db_session.commit()

    _, bom = await _export(client, headers, scan)

    vulns = {v["id"]: v for v in bom["vulnerabilities"]}
    assert set(vulns) == {"CVE-2021-23337", "CVE-2021-44228", "CVE-2021-33203", "CVE-2099-0001"}
    known_refs = {c["bom-ref"] for c in bom["components"]} | {bom["metadata"]["component"]["bom-ref"]}
    assert all(a["ref"] in known_refs for v in vulns.values() for a in v["affects"])

    lodash = vulns["CVE-2021-23337"]
    assert lodash["affects"] == [{"ref": "pkg:npm/lodash@4.17.20"}]
    assert lodash["ratings"] == [{"score": 7.2, "severity": "high"}]
    assert lodash["source"]["url"] == "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"
    assert "4.17.21" in lodash["recommendation"]
    props = {p["name"]: p["value"] for p in lodash["properties"]}
    assert props["guardnous:match_basis"] == "ecosystem and package name" and props["guardnous:epss_score"] == "0.42"
    assert "inside the affected range" in props["guardnous:version_check"]
    # how sure the match is, stated in the document itself
    assert lodash["analysis"]["state"] == "in_triage" and "not resolved from a lock file" in lodash["analysis"]["detail"]

    log4j = vulns["CVE-2021-44228"]
    assert log4j["affects"] == [{"ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}]
    assert {"name": "guardnous:cisa_kev", "value": "true"} in log4j["properties"]
    assert "upper bound is not known" in log4j["analysis"]["detail"]

    assert vulns["CVE-2021-33203"]["affects"] == [{"ref": "pkg:pypi/django@3.2.0"}]
    assert "vendor not verified" in vulns["CVE-2021-33203"]["analysis"]["detail"]
    # a CVE the scan reported without naming a package is attached to the repository, not to a guess
    assert vulns["CVE-2099-0001"]["affects"] == [{"ref": "repo:acme/shop"}]
    assert f"finding #{reported.id}" in vulns["CVE-2099-0001"]["analysis"]["detail"]

    summary = await _summary(client, headers, scan)
    assert (summary["vulnerable_components"], summary["vulnerabilities"]) == (3, 4)


async def test_summary_counts_components_by_ecosystem_and_scope(db_session, client):
    user, headers = await _user(db_session, client)
    scan = await _repo_scan(db_session, user.organization_id)

    summary = await _summary(client, headers, scan)

    assert summary["component_count"] == len(EXPECTED_PURLS) and summary["manifests"] == len(MANIFESTS)
    assert summary["by_ecosystem"] == {"npm": 4, "pypi": 3, "maven": 2, "go": 1, "rubygems": 1, "cargo": 1, "composer": 1}
    assert summary["by_scope"] == {"production": 11, "development": 2}
    assert summary["without_version"] == 1 and summary["dependency_depth"] == "direct"
    assert (summary["vulnerable_components"], summary["vulnerabilities"]) == (0, 0)


# ── Who may see and export it ───────────────────────────────────────

async def test_a_scan_of_another_organization_does_not_exist(db_session, client):
    user, headers = await _user(db_session, client)
    other, _ = await _user(db_session, client, email="other@elsewhere.test", org="Other Org")
    theirs = await _repo_scan(db_session, other.organization_id)

    for method, path in (("get", ""), ("get", "/summary"), ("post", "/licenses/refresh")):
        resp = await getattr(client, method)(f"/api/v1/sbom/scans/{theirs.id}{path}", headers=headers)
        assert resp.status_code == 404 and resp.json()["detail"] == "Scan not found"


async def test_export_needs_the_export_permission_and_the_summary_only_read(db_session, client):
    user, headers = await _user(db_session, client)
    scan = await _repo_scan(db_session, user.organization_id)

    await _with_role(db_session, user, "viewer")
    headers = await get_auth_headers_for(client, user.email)
    denied = await client.get(f"/api/v1/sbom/scans/{scan.id}", headers=headers)
    assert denied.status_code == 403 and "scans:export" in denied.json()["detail"]
    assert (await _summary(client, headers, scan))["component_count"] == len(EXPECTED_PURLS)
    refresh = await client.post(f"/api/v1/sbom/scans/{scan.id}/licenses/refresh", headers=headers)
    assert refresh.status_code == 403

    for slug in ("auditor", "security_engineer"):
        await _with_role(db_session, user, slug)
        await _export(client, headers, scan)


async def test_a_scan_without_a_stored_inventory_says_so_instead_of_exporting_an_empty_sbom(db_session, client):
    user, headers = await _user(db_session, client)
    old = await _repo_scan(db_session, user.organization_id, manifests=None)
    upload = await create_scan_in_db(db_session, user.organization_id)        # a single uploaded file
    without_manifests = await _repo_scan(db_session, user.organization_id, manifests={"main.tf": "# nothing"})
    quick = await _repo_scan(db_session, user.organization_id, manifests=None)
    quick.scan_type = "repository"                                            # the quick scan parses no manifests
    await db_session.commit()
    resp = await client.get(f"/api/v1/sbom/scans/{quick.id}", headers=headers)
    assert resp.status_code == 409 and "full repository assessment" in resp.json()["detail"]

    for path in ("", "/summary"):
        resp = await client.get(f"/api/v1/sbom/scans/{old.id}{path}", headers=headers)
        assert resp.status_code == 409
        assert resp.json()["detail"] == ("This assessment was run before dependency inventories were stored. "
                                         "Run it again to export an SBOM.")
        resp = await client.get(f"/api/v1/sbom/scans/{upload.id}{path}", headers=headers)
        assert resp.status_code == 404 and "repository assessments" in resp.json()["detail"]

    # scanned with the inventory stored, and the repository really has no manifests: a valid, empty SBOM
    _, bom = await _export(client, headers, without_manifests)
    assert bom["components"] == []


async def test_storing_again_replaces_the_inventory_of_that_scan(db_session, client):
    user, _ = await _user(db_session, client)
    scan = await _repo_scan(db_session, user.organization_id)
    deps, _, _ = DependencyAnalyzer().analyze({"package.json": json.dumps({"dependencies": {"express": "4.18.2"}})})

    await db_session.run_sync(lambda session: store_scan_inventory(session, scan, deps))
    await db_session.commit()

    rows = (await db_session.execute(select(ScanDependencyInventory))).scalars().all()
    assert len(rows) == 1 and rows[0].organization_id == user.organization_id
    assert rows[0].components == [{"ecosystem": "npm", "name": "express", "version": "4.18.2",
                                   "path": "package.json", "dev": False, "direct": True}]


# ── Licences ────────────────────────────────────────────────────────

@pytest.mark.parametrize("expression, category", [
    ("MIT", "permissive"),
    ("apache-2.0", "permissive"),
    ("BSD-3-Clause", "permissive"),
    ("LGPL-2.1-or-later", "weak_copyleft"),
    ("MPL-2.0", "weak_copyleft"),
    ("GPL-3.0-only", "strong_copyleft"),
    ("GPL-2.0+", "strong_copyleft"),
    ("AGPL-3.0-or-later", "strong_copyleft"),
    ("CC-BY-NC-4.0", "restrictive"),
    ("MIT OR Apache-2.0", "permissive"),
    ("MIT OR GPL-3.0-only", "permissive"),                      # OR: the most permissive choice
    ("MIT AND GPL-3.0-only", "strong_copyleft"),                # AND: the most restrictive
    ("(MIT OR GPL-2.0-only) AND LGPL-3.0-only", "weak_copyleft"),
    ("MIT AND (AGPL-3.0-only OR SSPL-1.0)", "strong_copyleft"),
    ("GPL-2.0-only WITH Classpath-exception-2.0", "weak_copyleft"),
    ("MIT OR Some-Unlisted-License", "permissive"),
    ("MIT AND Some-Unlisted-License", "unknown"),
    ("GPL-3.0-only AND Some-Unlisted-License", "strong_copyleft"),
    ("non-standard", "unknown"),
    ("MIT OR", "unknown"),
    ("", "unknown"),
])
def test_spdx_expressions_are_classified(expression, category):
    assert licenses.classify_expression(expression) == category


def test_default_policy_flags_copyleft_only_in_production_dependencies():
    assert licenses.license_status("strong_copyleft", is_dev=False) == "review_needed"
    assert licenses.license_status("restrictive", is_dev=False) == "review_needed"
    assert licenses.license_status("strong_copyleft", is_dev=True) == "ok"
    assert licenses.license_status("weak_copyleft", is_dev=False) == "ok"
    assert licenses.license_status("permissive", is_dev=False) == "ok"
    assert licenses.license_status("unknown", is_dev=False) == "unknown"
    assert licenses.classify_licenses(["MIT", "GPL-2.0-only"]) == "strong_copyleft"      # both apply
    assert licenses.classify_licenses([]) == "unknown"


async def test_licences_are_not_looked_up_unless_the_setting_is_on(db_session, client, deps_dev):
    user, headers = await _user(db_session, client)
    scan = await _repo_scan(db_session, user.organization_id)

    summary = await _summary(client, headers, scan)
    await _export(client, headers, scan)
    refresh = await client.post(f"/api/v1/sbom/scans/{scan.id}/licenses/refresh", headers=headers)

    assert deps_dev.calls == []
    assert summary["licenses"]["status"] == "not_checked" and summary["licenses"]["lookup_enabled"] is False
    assert summary["licenses"]["setting"] == "DEPENDENCY_LICENSE_LOOKUP"
    assert "DEPENDENCY_LICENSE_LOOKUP=true" in summary["licenses"]["message"]
    assert refresh.status_code == 409 and "DEPENDENCY_LICENSE_LOOKUP" in refresh.json()["detail"]


async def test_licences_are_looked_up_once_cached_and_judged_by_the_default_policy(
    db_session, client, deps_dev, lookup_on,
):
    user, headers = await _user(db_session, client)
    scan = await _repo_scan(db_session, user.organization_id)
    deps_dev.replies.update({
        "npm/%40angular%2Fcore@17.0.0": ["MIT"],
        "npm/lodash@4.17.20": ["AGPL-3.0-only"],                 # production: review
        "npm/jest@29.7.0": ["AGPL-3.0-only"],                    # development only: reported, not flagged
        "pypi/django@3.2.0": ["BSD-3-Clause"],
        "pypi/typing-extensions@4.9.0": ["PSF-2.0"],
        "pypi/requests@2.31.0": ["Apache-2.0"],
        "go/github.com%2Fgorilla%2Fmux@v1.8.0": ["BSD-3-Clause"],
        "maven/org.apache.logging.log4j%3Alog4j-core@2.14.1": ["Apache-2.0"],
        "maven/junit%3Ajunit@4.13.2": ["EPL-1.0"],
        "rubygems/rails@7.0.4": ["MIT OR GPL-3.0-only"],
        "cargo/serde@1.0.190": ["MIT OR Apache-2.0"],
    })

    summary = await _summary(client, headers, scan)

    # one request per package that has a supported ecosystem and a concrete version
    assert sorted(deps_dev.calls) == sorted(deps_dev.replies)
    lic = summary["licenses"]
    assert lic["status"] == "checked" and lic["source"] == "deps.dev"
    assert lic["by_category"] == {"permissive": 8, "weak_copyleft": 1, "strong_copyleft": 2, "restrictive": 0, "unknown": 2}
    # Composer is not covered by deps.dev; "*" is not a version that can be looked up
    assert lic["unknown_reasons"] == {"unsupported_ecosystem": 1, "no_version": 1}
    assert lic["review_needed"] == [{
        "package": "lodash", "version": "4.17.20", "ecosystem": "npm", "license": "AGPL-3.0-only",
        "category": "strong_copyleft", "scope": "production",
        "manifest_path": "web/package.json", "manifest_paths": ["web/package.json", "tools/package.json"],
    }]
    assert not any("composer" in c or "packagist" in c or "left-pad" in c for c in deps_dev.calls)

    # asking again, exporting, and another organization's scan of the same packages: no new requests
    asked = len(deps_dev.calls)
    await _summary(client, headers, scan)
    _, bom = await _export(client, headers, scan)
    other, other_headers = await _user(db_session, client, email="other@elsewhere.test", org="Other Org")
    theirs = await _repo_scan(db_session, other.organization_id)
    assert (await _summary(client, other_headers, theirs))["licenses"]["by_category"] == lic["by_category"]
    assert len(deps_dev.calls) == asked

    by_purl = {c["purl"]: c for c in bom["components"]}
    assert by_purl["pkg:npm/lodash@4.17.20"]["licenses"] == [{"license": {"id": "AGPL-3.0-only"}}]
    assert by_purl["pkg:cargo/serde@1.0.190"]["licenses"] == [{"expression": "MIT OR Apache-2.0"}]
    assert "licenses" not in by_purl["pkg:composer/monolog/monolog@3.5.0"]
    assert "licenses" not in by_purl["pkg:npm/left-pad"]

    # the shared cache holds public package data only
    cached = (await db_session.execute(select(PackageLicense))).scalars().all()
    assert len(cached) == len(deps_dev.replies)
    assert {c.name for c in cached if c.system == "maven"} == {"org.apache.logging.log4j:log4j-core", "junit:junit"}

    # a refresh asks again
    refreshed = await client.post(f"/api/v1/sbom/scans/{scan.id}/licenses/refresh", headers=headers)
    assert refreshed.status_code == 200 and refreshed.json()["licenses"]["by_category"] == lic["by_category"]
    assert len(deps_dev.calls) == 2 * asked
    assert len((await db_session.execute(select(PackageLicense))).scalars().all()) == len(deps_dev.replies)


async def test_a_failed_lookup_means_unknown_and_a_private_package_is_not_cached(
    db_session, client, deps_dev, lookup_on,
):
    user, headers = await _user(db_session, client)
    scan = await _repo_scan(db_session, user.organization_id, manifests={"package.json": json.dumps({"dependencies": {
        "express": "4.18.2", "@acme/internal-billing": "2.0.0", "flaky": "1.0.0", "unreachable": "1.0.0",
        "odd": "1.0.0", "unlicensed": "1.0.0",
    }})})
    deps_dev.replies.update({
        "npm/express@4.18.2": ["MIT"],
        "npm/flaky@1.0.0": 503,
        "npm/unreachable@1.0.0": httpx.ConnectError("no route"),
        "npm/odd@1.0.0": ["non-standard"],
        "npm/unlicensed@1.0.0": [],
    })                                                    # the private package: 404, deps.dev does not know it

    summary = await _summary(client, headers, scan)

    lic = summary["licenses"]
    assert lic["status"] == "partial"
    assert lic["by_category"] == {"permissive": 1, "weak_copyleft": 0, "strong_copyleft": 0, "restrictive": 0, "unknown": 5}
    assert lic["unknown_reasons"] == {"not_found": 1, "failed": 2, "unrecognised_license": 1, "no_license_data": 1}
    assert lic["not_looked_up"] == 2 and lic["review_needed"] == []
    assert {c.name for c in (await db_session.execute(select(PackageLicense))).scalars().all()} == \
        {"express", "odd", "unlicensed"}

    # the export still works; a licence deps.dev could not name is given as text, not as an SPDX id
    _, bom = await _export(client, headers, scan)
    by_name = {c["name"]: c for c in bom["components"]}
    assert by_name["odd"]["licenses"] == [{"license": {"name": "non-standard"}}]
    assert "licenses" not in by_name["flaky"] and "licenses" not in by_name["@acme/internal-billing"]
    assert len(deps_dev.calls) == 6                       # failures are not retried on every page view


async def test_lookups_per_scan_are_capped_and_the_rest_is_reported(db_session, client, deps_dev, lookup_on, monkeypatch):
    monkeypatch.setattr(licenses, "MAX_LOOKUPS", 3)
    user, headers = await _user(db_session, client)
    scan = await _repo_scan(db_session, user.organization_id, manifests={
        "package.json": json.dumps({"dependencies": {f"pkg-{i}": "1.0.0" for i in range(5)}}),
    })
    deps_dev.replies.update({f"npm/pkg-{i}@1.0.0": ["MIT"] for i in range(5)})

    lic = (await _summary(client, headers, scan))["licenses"]

    assert len(deps_dev.calls) == 3
    assert lic["status"] == "partial" and lic["not_looked_up"] == 2
    assert lic["by_category"]["permissive"] == 3 and lic["unknown_reasons"] == {"skipped": 2}
