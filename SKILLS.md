# GuardNous — Agent Tools

In this codebase a "skill" is a **tool**: a function an AI agent can call. There are
**72 tools**. Each of the 20 agents is given a subset (11 to 34 of them), and an
organization's roles can narrow that further.

The source of truth is the code. If this file and the code disagree, the code is right:

| What | Where |
|------|-------|
| Tool definitions the model sees | `backend/app/services/agents/tools.py` (`TOOL_SCHEMAS`) |
| Which agent may call which tool | `backend/app/services/agents/registry.py` |
| Which tools change something | `backend/app/services/agents/runtime.py` (`TOOL_RISK`) |
| Input and output checks | `backend/app/services/agents/guardrails.py` |

## What the tools can and cannot do

- **67 tools only read.** They query the organization's own findings, scans, CVE data,
  synced cloud resources and knowledge graph, or they produce text (a plan, a runbook,
  a ticket draft, a PDF).
- **5 tools change something.** They are listed first below. Every one of them stops and
  waits for a person. Three act outside GuardNous and need a second person.
- Many of the read tools named after a domain (`assess_dlp`, `investigate_api`,
  `analyze_kubernetes` and similar) work by **filtering and grouping the findings already
  in the database**. They do not probe endpoints or networks themselves. If no scanner
  has produced findings for that domain, they return little.
- Eleven tools read **real resources synced from connected AWS accounts**: the five
  cloud inventory tools, plus `scan_exposed_ports`, `audit_iam_permissions`,
  `check_encryption_posture`, `assess_backup_security`, `evaluate_waf_rules`,
  `investigate_dns` (Route 53 only) and `investigate_tls` (ACM certificates and load
  balancers). Azure and GCP accounts can be connected, but posture rules exist for AWS only.
- **Four tools have no data source yet** and say so instead of guessing. They return
  `data_source: not_connected`: `enrich_ioc` and `check_reputation` (no threat
  intelligence connector), `assess_endpoint_security` (no EDR connector) and
  `detect_cost_anomalies` (billing data is not read).

## Tools that change something (5)

| Tool | What it does | Approval |
|------|--------------|----------|
| `triage_finding` | Sets one finding's triage status inside GuardNous | The requester, or someone with `agents:manage`, confirms |
| `triage_findings` | Sets the status of up to 400 findings from one reviewed list. Findings with one cause can share a decision (`finding_ids`). Decisions that hide a finding are listed first, each with its reason | The same; the whole list is approved or rejected once |
| `open_fix_pull_request` | Commits a fix to a new branch and opens a pull request on GitHub, GitLab (merge request), Bitbucket Cloud or Azure DevOps | A second person approves the exact diff |
| `remediate_cloud_finding` | Changes the resource in the connected AWS account to fix a `GN-AWS-*` finding | A second person approves; the account role must allow fixes |
| `send_slack_message` | Posts to the organization's connected Slack channel | A second person approves the exact message |

For the three outside actions, the person who started the run cannot approve it. Nothing
is committed, changed or sent until approval, and the file is checked again for changes
before the commit.

A triage decision is also applied to the same finding (same rule, file and resource) in
other scans of the same repository, and is kept when the repository is scanned again. A
finding marked resolved that a later scan finds again is reopened with a note.

## Findings, scans and risk (12)

| Tool | What it returns |
|------|-----------------|
| `list_triage_queue` | Open findings waiting for a decision, from the latest assessment of each target only, most severe first, with evidence: whether the CVE is known to be exploited, how long the finding has existed, and whether the path looks like test code (a hint, never a verdict) |
| `list_findings` | Open findings, filtered by severity, category or cloud |
| `get_finding` | One finding with code snippet, resource and remediation |
| `get_severity_breakdown` | Open findings counted by severity |
| `get_risk_score` | Overall risk score (0–100) and per-cloud breakdown |
| `list_recent_scans` | Recent scans with status and risk score |
| `search_cves` | CVE database search by keyword and severity |
| `get_posture_trend` | Risk over recent scans: improving or worsening |
| `predict_risk_trend` | Projected risk from history and fix rate |
| `detect_anomalies` | Unusual changes in finding counts and severity mix |
| `auto_fix_finding` | A preview of the code fix (diff) for a repository finding; changes nothing |
| `get_knowledge_stats` | Statistics on remediation patterns learned so far |

## Cloud accounts (5) — real synced resources

| Tool | What it returns |
|------|-----------------|
| `cloud_inventory_summary` | Connected accounts, last sync, resource counts by type and region |
| `list_cloud_resources` | Resources with their configuration |
| `get_cloud_resource` | One resource's full configuration and its open posture findings |
| `cloud_posture_summary` | Open posture findings by severity and rule, and which checks passed |
| `internet_exposure` | What is reachable from the internet: public instances, open ports, public buckets |

## Compliance and governance (8)

`check_compliance`, `deep_compliance`, `generate_audit_report`, `track_compliance_drift`,
`check_policy_violations`, `map_data_flows`, `assess_dlp`, `assess_identity_governance`

These map open findings to controls in CIS, SOC 2, PCI DSS, HIPAA, ISO 27001 and NIST 800-53.

## Investigation by domain (21)

| Area | Tools |
|------|-------|
| AWS, Azure, GCP | `investigate_aws_iam`, `investigate_aws_network`, `investigate_azure_security`, `investigate_gcp_security` |
| Infrastructure as code and Kubernetes | `analyze_terraform`, `analyze_kubernetes` |
| Software supply chain | `analyze_supply_chain`, `check_dependency_health`, `investigate_secrets` |
| Containers and pipelines | `investigate_containers`, `investigate_cicd` |
| Application and network | `investigate_api`, `investigate_dns`, `investigate_tls`, `analyze_network_segmentation`, `scan_exposed_ports`, `evaluate_waf_rules` |
| Identity, data, endpoints | `audit_iam_permissions`, `check_encryption_posture`, `assess_backup_security`, `assess_endpoint_security` |

## Threat analysis (9)

`analyze_attack_surface`, `threat_modeling` (STRIDE), `map_mitre_attack`, `assess_zero_trust`,
`detect_cost_anomalies`, `enrich_ioc`, `check_reputation`, `incident_response`, `generate_remediation_guide`

`enrich_ioc`, `check_reputation` and `detect_cost_anomalies` currently report that no
data source is connected (see above).

## Reviewing text the user supplies (3)

`scan_code_snippet`, `analyze_dockerfile`, `review_github_actions` — pattern checks on
code, a Dockerfile or a workflow file passed in the request.

## Knowledge graph (4)

`query_blast_radius`, `get_related_entities`, `search_knowledge_graph`, `get_graph_stats`

## Writing documents and plans (4)

| Tool | What it produces |
|------|------------------|
| `draft_ticket` | Ticket text for a finding. It does not create a ticket anywhere |
| `generate_runbook` | A step-by-step runbook for a scenario |
| `quarantine_resource` | An isolation plan with rollback steps. It changes nothing |
| `export_pdf_report` | A PDF attached to the chat reply. Available in chat only |

## Working together (1)

`delegate_to_agent` — hands a sub-task to a specialist agent, with a depth limit.

## Guardrails (55 patterns)

| Check | Patterns | Applied to |
|-------|----------|-----------|
| Prompt injection | 25 | The text the user types |
| Personal data | 11 | The text the user types (replaced before the model sees it) and model output |
| Secrets (keys, tokens, passwords, private keys, connection strings) | 9 | Model output, and attached files before they are stored |
| Internal paths | 10 | Model output |

Typed messages are limited to about 8,000 tokens. Attached files are handled separately
(see `AGENTS.md`): only their text is kept, and credentials, card numbers and social
security numbers in them are replaced with a marker before storage and before any model
sees them.

## Adding a tool

1. Write the function in one of the `*_skills.py` modules or `tools.py`. It receives a
   `ToolContext` and must filter every query by `ctx.organization_id`.
2. Add its schema to `TOOL_SCHEMAS` and its entry to the dispatch table in `tools.py`.
3. Add it to the agents that should have it in `registry.py`.
4. If it changes anything, add it to `TOOL_RISK` in `runtime.py`. External changes need approval.
5. Add a test, and update the counts in this file and in `README.md`.
