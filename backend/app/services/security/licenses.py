"""Licences of dependencies: lookup, classification and the default policy.

Licences come from the public deps.dev API (Open Source Insights). A lookup
sends the package name and version to that service, so it only happens when
``DEPENDENCY_LICENSE_LOOKUP`` is turned on. Results for packages deps.dev knows
are cached in ``package_licenses``; a failed lookup means "unknown", never an
error for the caller.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from urllib.parse import quote

import httpx
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.sbom import PackageLicense

logger = logging.getLogger(__name__)

# ── Categories and the default policy ───────────────────────────────

PERMISSIVE = "permissive"
WEAK_COPYLEFT = "weak_copyleft"
STRONG_COPYLEFT = "strong_copyleft"
RESTRICTIVE = "restrictive"          # non-commercial, source-available and similar
UNKNOWN = "unknown"

CATEGORIES = [PERMISSIVE, WEAK_COPYLEFT, STRONG_COPYLEFT, RESTRICTIVE, UNKNOWN]

OK = "ok"
REVIEW_NEEDED = "review_needed"

# The default policy: what a licence category means for a dependency, by scope.
# A licence status is not a security severity. Development-only dependencies
# are not distributed with the product, so they are reported but not flagged.
LICENSE_POLICY: dict[str, dict[str, str]] = {
    PERMISSIVE:      {"production": OK,            "development": OK},
    WEAK_COPYLEFT:   {"production": OK,            "development": OK},
    STRONG_COPYLEFT: {"production": REVIEW_NEEDED, "development": OK},
    RESTRICTIVE:     {"production": REVIEW_NEEDED, "development": OK},
    UNKNOWN:         {"production": UNKNOWN,       "development": UNKNOWN},
}

# SPDX identifiers the policy knows, in their canonical spelling.
SPDX_CATEGORIES: dict[str, str] = {
    **dict.fromkeys([
        "MIT", "MIT-0", "Apache-2.0", "Apache-1.1", "ISC", "0BSD", "BSD-1-Clause", "BSD-2-Clause",
        "BSD-2-Clause-Patent", "BSD-3-Clause", "BSD-3-Clause-Clear", "BSD-4-Clause", "Unlicense",
        "CC0-1.0", "CC-BY-3.0", "CC-BY-4.0", "Zlib", "BSL-1.0", "PSF-2.0", "Python-2.0", "PostgreSQL",
        "X11", "WTFPL", "BlueOak-1.0.0", "Artistic-2.0", "OpenSSL", "Ruby", "NCSA", "UPL-1.0",
        "AFL-2.1", "AFL-3.0", "Unicode-DFS-2016", "Unicode-3.0", "HPND", "curl", "libpng-2.0",
        "MulanPSL-2.0", "JSON",
    ], PERMISSIVE),
    **dict.fromkeys([
        "LGPL-2.0", "LGPL-2.0-only", "LGPL-2.0-or-later", "LGPL-2.1", "LGPL-2.1-only",
        "LGPL-2.1-or-later", "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later",
        "MPL-1.1", "MPL-2.0", "EPL-1.0", "EPL-2.0", "CDDL-1.0", "CDDL-1.1",
    ], WEAK_COPYLEFT),
    **dict.fromkeys([
        "GPL-1.0-only", "GPL-1.0-or-later", "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
        "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
        "AGPL-1.0-only", "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
        "EUPL-1.1", "EUPL-1.2", "OSL-3.0",
    ], STRONG_COPYLEFT),
    **dict.fromkeys([
        "SSPL-1.0", "BUSL-1.1", "Elastic-2.0",
        "CC-BY-NC-3.0", "CC-BY-NC-4.0", "CC-BY-NC-SA-3.0", "CC-BY-NC-SA-4.0",
        "CC-BY-NC-ND-3.0", "CC-BY-NC-ND-4.0",
        "PolyForm-Noncommercial-1.0.0", "PolyForm-Small-Business-1.0.0",
    ], RESTRICTIVE),
}

# Families, for identifiers not listed above (older or rarer versions). First match wins.
_PREFIX_CATEGORIES: list[tuple[str, str]] = [
    ("agpl-", STRONG_COPYLEFT),
    ("lgpl-", WEAK_COPYLEFT),
    ("gpl-", STRONG_COPYLEFT),
    ("bsd-", PERMISSIVE),
    ("epl-", WEAK_COPYLEFT),
    ("mpl-", WEAK_COPYLEFT),
    ("cc-by-nc", RESTRICTIVE),
    ("polyform-", RESTRICTIVE),
]

# "GPL-2.0-only WITH Classpath-exception-2.0" may be linked like a weak-copyleft library.
_LINKING_EXCEPTIONS = ("classpath-exception", "gcc-exception", "linking-exception", "llvm-exception")

_BY_LOWER = {k.lower(): v for k, v in SPDX_CATEGORIES.items()}
_RANK = {PERMISSIVE: 0, WEAK_COPYLEFT: 1, STRONG_COPYLEFT: 2, RESTRICTIVE: 3}


def is_spdx_id(value: str) -> bool:
    """True for an SPDX identifier this module knows in its canonical spelling."""
    return value in SPDX_CATEGORIES


def _classify_id(identifier: str) -> str:
    key = identifier.strip().lower().rstrip("+")
    if key in _BY_LOWER:
        return _BY_LOWER[key]
    for prefix, category in _PREFIX_CATEGORIES:
        if key.startswith(prefix):
            return category
    return UNKNOWN


def _any_of(categories: list[str]) -> str:
    """OR: the licensee chooses, so the most permissive known option counts."""
    known = [c for c in categories if c != UNKNOWN]
    return min(known, key=_RANK.__getitem__) if known else UNKNOWN


def _all_of(categories: list[str]) -> str:
    """AND: every licence applies, so the most restrictive one counts."""
    known = [c for c in categories if c != UNKNOWN]
    worst = max(known, key=_RANK.__getitem__) if known else UNKNOWN
    if UNKNOWN in categories and worst not in (STRONG_COPYLEFT, RESTRICTIVE):
        return UNKNOWN          # an unidentified licence also applies; nothing can be concluded
    return worst


class _Parser:
    """Simple SPDX expressions: identifiers, AND, OR, WITH and parentheses."""

    def __init__(self, expression: str):
        self.tokens = re.findall(r"\(|\)|[^\s()]+", expression)
        self.pos = 0

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _take(self) -> str:
        token = self._peek()
        if token is None:
            raise ValueError("unexpected end of licence expression")
        self.pos += 1
        return token

    def parse(self) -> str:
        category = self._or()
        if self._peek() is not None:
            raise ValueError("unexpected token in licence expression")
        return category

    def _or(self) -> str:
        parts = [self._and()]
        while (self._peek() or "").upper() == "OR":
            self._take()
            parts.append(self._and())
        return _any_of(parts)

    def _and(self) -> str:
        parts = [self._with()]
        while (self._peek() or "").upper() == "AND":
            self._take()
            parts.append(self._with())
        return _all_of(parts)

    def _with(self) -> str:
        category = self._atom()
        if (self._peek() or "").upper() == "WITH":
            self._take()
            exception = self._take().lower()
            if category == STRONG_COPYLEFT and any(e in exception for e in _LINKING_EXCEPTIONS):
                return WEAK_COPYLEFT
        return category

    def _atom(self) -> str:
        token = self._take()
        if token == "(":
            category = self._or()
            if self._take() != ")":
                raise ValueError("unbalanced parentheses in licence expression")
            return category
        if token == ")" or token.upper() in ("AND", "OR", "WITH"):
            raise ValueError("misplaced operator in licence expression")
        return _classify_id(token)


def classify_expression(expression: str) -> str:
    """Category of one SPDX expression, e.g. ``MIT OR GPL-3.0-only`` -> permissive."""
    if not expression or not expression.strip():
        return UNKNOWN
    try:
        return _Parser(expression).parse()
    except ValueError:
        return UNKNOWN


def classify_licenses(expressions: list[str] | None) -> str:
    """Category of a package given every licence reported for it (all of them apply)."""
    expressions = [e for e in (expressions or []) if e and e.strip()]
    if not expressions:
        return UNKNOWN
    return _all_of([classify_expression(e) for e in expressions])


def license_status(category: str, is_dev: bool) -> str:
    """What the default policy says about a dependency: ok, review_needed or unknown."""
    return LICENSE_POLICY.get(category, LICENSE_POLICY[UNKNOWN])["development" if is_dev else "production"]


# ── Lookup (deps.dev) ───────────────────────────────────────────────

DEPS_DEV_URL = "https://api.deps.dev/v3"

# Our ecosystem -> deps.dev system. Composer (Packagist) is not covered by deps.dev.
DEPS_DEV_SYSTEMS = {
    "npm": "npm",
    "pypi": "pypi",
    "go": "go",
    "maven": "maven",        # name is "group:artifact"
    "cargo": "cargo",
    "rubygems": "rubygems",
}

MAX_LOOKUPS = 500            # requests to deps.dev for one inventory
CONCURRENCY = 8
REQUEST_TIMEOUT = httpx.Timeout(6.0, connect=3.0)
TIME_BUDGET_SECONDS = 25.0   # for one inventory; what is not reached stays unknown and is retried later
ABORT_AFTER_FAILURES = 6     # consecutive transport failures: the service is unreachable, stop asking

# Where a package's answer came from; everything except the first two means "licence unknown".
FOUND, CACHED = "deps.dev", "cache"
NOT_FOUND, FAILED, SKIPPED = "not_found", "failed", "skipped"
UNSUPPORTED, NO_VERSION = "unsupported_ecosystem", "no_version"

FINAL_SOURCES = {FOUND, CACHED, NOT_FOUND, UNSUPPORTED, NO_VERSION}   # a retry would not change these

PackageKey = tuple[str, str, str]      # (ecosystem, name, version)


def _system_name(ecosystem: str, name: str) -> str:
    """The package name as deps.dev expects it."""
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem == "npm":
        return name.lower()
    return name


async def _fetch(client: httpx.AsyncClient, key: PackageKey) -> tuple[str, list[str]]:
    ecosystem, name, version = key
    url = (
        f"{DEPS_DEV_URL}/systems/{DEPS_DEV_SYSTEMS[ecosystem]}"
        f"/packages/{quote(_system_name(ecosystem, name), safe='')}"
        f"/versions/{quote(version, safe='')}"
    )
    try:
        response = await client.get(url)
    except httpx.HTTPError:
        return FAILED, []
    if response.status_code == 404:
        return NOT_FOUND, []
    if response.status_code != 200:
        return FAILED, []
    try:
        licenses = response.json().get("licenses") or []
    except ValueError:
        return FAILED, []
    return FOUND, [str(x) for x in licenses if isinstance(x, str) and x.strip()]


async def _read_cache(db: AsyncSession, keys: list[PackageKey]) -> dict[PackageKey, PackageLicense]:
    found: dict[PackageKey, PackageLicense] = {}
    by_system: dict[str, list[PackageKey]] = {}
    for key in keys:
        by_system.setdefault(key[0], []).append(key)
    for ecosystem, group in by_system.items():
        wanted = {(_system_name(ecosystem, k[1]), k[2]): k for k in group}
        names = sorted({n for n, _ in wanted})
        for i in range(0, len(names), 400):
            rows = (await db.execute(select(PackageLicense).where(
                PackageLicense.system == DEPS_DEV_SYSTEMS[ecosystem],
                PackageLicense.name.in_(names[i:i + 400]),
            ))).scalars().all()
            for row in rows:
                key = wanted.get((row.name, row.version))
                if key:
                    found[key] = row
    return found


async def _write_cache(db: AsyncSession, fetched: dict[PackageKey, list[str]]) -> None:
    """Remember what deps.dev reported. Another request may store the same package first."""
    existing = await _read_cache(db, list(fetched))
    for key, licenses in fetched.items():
        ecosystem, name, version = key
        name = _system_name(ecosystem, name)
        if len(name) > 300 or len(version) > 100:
            continue
        row = existing.get(key)
        if row is not None:
            row.licenses = licenses
            continue
        try:
            async with db.begin_nested():
                db.add(PackageLicense(
                    system=DEPS_DEV_SYSTEMS[ecosystem], name=name, version=version, licenses=licenses,
                ))
        except IntegrityError:
            pass


async def lookup_licenses(
    db: AsyncSession,
    packages: list[tuple[str, str, str | None]],
    *,
    use_cache: bool = True,
) -> dict[tuple[str, str, str | None], dict]:
    """Licences for (ecosystem, name, version) packages.

    Returns ``{package: {"licenses": [SPDX expression, ...], "source": ...}}`` for
    every package given. Only packages with a supported ecosystem and a concrete
    version are looked up, at most ``MAX_LOOKUPS`` of them over the network.
    """
    from app.services.security.dependency_analyzer import concrete_version

    results: dict[tuple[str, str, str | None], dict] = {}
    wanted: list[PackageKey] = []
    for package in dict.fromkeys(packages):
        ecosystem, name, version = package
        if ecosystem not in DEPS_DEV_SYSTEMS:
            results[package] = {"licenses": [], "source": UNSUPPORTED}
        elif not concrete_version(version):
            results[package] = {"licenses": [], "source": NO_VERSION}
        else:
            wanted.append((ecosystem, name, str(version)))

    if use_cache and wanted:
        cached = await _read_cache(db, wanted)
        for key, row in cached.items():
            results[key] = {"licenses": list(row.licenses or []), "source": CACHED}
        wanted = [k for k in wanted if k not in cached]

    for key in wanted[MAX_LOOKUPS:]:
        results[key] = {"licenses": [], "source": SKIPPED}
    wanted = wanted[:MAX_LOOKUPS]
    if not wanted:
        return results

    semaphore = asyncio.Semaphore(CONCURRENCY)
    deadline = time.monotonic() + TIME_BUDGET_SECONDS
    failures_in_a_row = 0
    fetched: dict[PackageKey, list[str]] = {}

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, headers={"Accept": "application/json"}) as client:

        async def one(key: PackageKey) -> None:
            nonlocal failures_in_a_row
            async with semaphore:
                if failures_in_a_row >= ABORT_AFTER_FAILURES or time.monotonic() >= deadline:
                    results[key] = {"licenses": [], "source": SKIPPED}
                    return
                source, licenses = await _fetch(client, key)
                failures_in_a_row = failures_in_a_row + 1 if source == FAILED else 0
                results[key] = {"licenses": licenses, "source": source}
                if source == FOUND:
                    fetched[key] = licenses

        await asyncio.gather(*(one(k) for k in wanted))

    if failures_in_a_row >= ABORT_AFTER_FAILURES:
        logger.warning("Licence lookup stopped: deps.dev did not answer %d requests in a row", failures_in_a_row)
    if fetched:
        await _write_cache(db, fetched)
    return results
