# What has been verified

[← Back to the README](../README.md)

Every feature in GuardNous has automated tests. This page says something different: which
features have also been **run against the real service**, and which have so far only been run
against simulated ones. If an integration you need is in the second group, it may work first
time, or it may need a fix. Either way, a report helps: see [Help verify](#help-verify-an-integration).

Three levels are used:

- **Verified** — run end to end against the real service, by a person, and it worked.
- **Simulated only** — implemented and covered by automated tests that use simulated responses. Not yet run against the real service.
- **Preview** — written but not yet run at all in a real environment.

## Installation

| What | Status | Notes |
|---|---|---|
| Docker Compose with `scripts/setup.sh` | **Verified** | Clean clone, first sign-in, setup wizard, a Terraform scan and the main pages, on macOS (Apple silicon) |
| Docker Compose on Linux and on Windows (WSL) | Simulated only | CI builds the images on Linux; nobody has run the full install there yet |
| Kubernetes with the Helm chart | Preview | Not yet run on a cluster |

## Code hosts

| What | Status | Notes |
|---|---|---|
| GitHub: connect with a token, scan repositories | **Verified** | |
| GitHub: fix pull request after approval | **Verified** | The pull request is opened as the user whose token is connected |
| GitHub: scan on push and on pull request (webhooks) | Simulated only | |
| GitHub: connect as a GitHub App | Simulated only | |
| GitLab: connect, scan, webhooks, fix merge requests | Simulated only | |
| Bitbucket: connect, scan, webhooks, fix pull requests | Simulated only | |
| Azure DevOps: connect, scan, webhooks, fix pull requests | Simulated only | |

## Scanning

| What | Status | Notes |
|---|---|---|
| Built-in Terraform, CloudFormation, Bicep and secrets scanners | **Verified** | |
| Semgrep, Trivy, Checkov, tfsec, Gitleaks | **Verified** | All five start and report healthy on a clean install, and run in repository assessments |
| SARIF import | Simulated only | |
| SBOM export (CycloneDX 1.5) | Simulated only | No real assessment has been exported yet |
| Dependency licence lookup at deps.dev | Simulated only | |

## Cloud

| What | Status | Notes |
|---|---|---|
| AWS: connect without access keys, read an account, run the 44 rules | **Verified** | One account, four regions |
| AWS: reading every enabled region in one assessment | Simulated only | |
| AWS: the 5 fixes and their rollback | Simulated only | Checked against the AWS API definitions shipped with the AWS SDK, not yet applied to a real account |
| Azure: connect a subscription and inventory it | Simulated only | There are no posture rules for Azure yet |
| Google Cloud: connect a project and inventory it | Simulated only | There are no posture rules for Google Cloud yet |

## AI agents

| What | Status | Notes |
|---|---|---|
| Chat on live data, file attachments, PDF export | **Verified** | With Azure AI Foundry |
| Agent runs with approval | **Verified** | A fix pull request was proposed, approved by a second person and opened |
| Triage Agent: proposing decisions for a list of findings | **Verified** | Lists of 12 and 394 findings were proposed. See the [evaluation](evals/triage.md) |
| Triage Agent: starting by itself after an assessment | Simulated only | |
| Posting to Slack after approval | Simulated only | |
| OpenAI, Azure OpenAI, Anthropic and Ollama as the model provider | Simulated only | Only Azure AI Foundry has been used for real |
| Several agents answering one question | Simulated only | Steps run one after another, not in parallel |

## Platform

| What | Status | Notes |
|---|---|---|
| Sign-in, roles and permissions, organization switching, private chats | **Verified** | |
| PDF reports on demand | **Verified** | |
| Scheduled reports and e-mail delivery | Simulated only | |
| Two-factor sign-in | Simulated only | |
| End-to-end browser test suite (`e2e/`) | Preview | Written, not yet run against the current version |

## Help verify an integration

Verifying an integration is one of the most useful contributions, and it needs no knowledge of
the code: connect the service, try the listed actions, and report what happened.

1. Install GuardNous with `./scripts/setup.sh`.
2. Pick a row marked "Simulated only" for a service you have access to.
3. Try it, and open an issue with what you did, what you expected and what happened. If it
   worked, say so: that is what moves a row to **Verified**.

Please use a test account or a test repository, never production.
