# SARIF import

[← Back to the README](../README.md)

GuardNous accepts **SARIF v2.1.0** (Static Analysis Results Interchange Format) — the industry standard output from 100+ security tools. Import results from any scanner without writing a custom adapter.

### Supported Scanners (via SARIF)

Any tool that produces SARIF v2.1.0, including: **SonarQube**, **CodeQL**, **ESLint**, **Bandit**, **Gosec**, **Grype**, **KICS**, **Terrascan**, **Prowler**, **ScoutSuite**, **Snyk CLI**, **Fortify**, **Veracode**, **Checkmarx**, **Anchore**, and more.

### Import API

```bash
# JSON body
curl -X POST http://localhost:7002/api/v1/imports/sarif \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"sarif_data": <sarif-json>, "scan_name": "SonarQube weekly"}'

# File upload
curl -X POST http://localhost:7002/api/v1/imports/sarif/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@results.sarif" -F "scan_name=CodeQL nightly"

# List imports
curl http://localhost:7002/api/v1/imports/ -H "Authorization: Bearer $TOKEN"

# Supported formats
curl http://localhost:7002/api/v1/imports/formats
```

### What Happens on Import

1. **Parse** — Multi-run SARIF is flattened; each result becomes a finding
2. **Normalize severity** — 5-layer resolution: custom properties → CVSS score → level → rule config → fallback
3. **Attribute scanner** — Each finding is tagged with the originating tool name
4. **Extract CVEs** — Pulled from rule IDs, properties, and tags
5. **Infer category & cloud** — Keyword matching against rule metadata for automatic classification
6. **Deduplicate** — SARIF fingerprints are preserved; identical re-imports are idempotent
7. **Apply policies** — Imported findings run through the policy-as-code engine like any native scan

---

