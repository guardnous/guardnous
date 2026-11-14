# API reference

[← Back to the README](../README.md)

Full interactive docs at `/docs` (Swagger) and `/redoc` when the server is running.

### Key Endpoints

| Method | Endpoint | Description |
|---|---|---|
| **Auth & 2FA** | | |
| `POST` | `/api/v1/auth/login` | JWT token (form data: `username` + `password`); returns MFA challenge if 2FA enabled |
| `POST` | `/api/v1/auth/register` | Register user + org |
| `POST` | `/api/v1/auth/2fa/setup` | Generate TOTP secret + QR code URI |
| `POST` | `/api/v1/auth/2fa/confirm` | Verify TOTP code and enable 2FA |
| `POST` | `/api/v1/auth/verify-2fa` | Verify TOTP code during MFA login challenge |
| `POST` | `/api/v1/auth/2fa/disable` | Disable 2FA for the current user |
| `GET` | `/api/v1/auth/2fa/backup-codes` | Retrieve backup recovery codes |
| **Email Verification** | | |
| `GET` | `/api/v1/auth/verify-email?token=` | Verify email address via JWT token |
| `POST` | `/api/v1/auth/resend-verification` | Resend verification email (authenticated) |
| **Setup Wizard** | | |
| `GET` | `/api/v1/settings/setup-status` | Check if first-login setup is completed |
| `POST` | `/api/v1/settings/complete-setup` | Complete the 5-step setup wizard |
| **Dashboard** | | |
| `GET` | `/api/v1/dashboard/summary` | Dashboard statistics and risk score |
| **Scans & Findings** | | |
| `POST` | `/api/v1/scans/` | Trigger scan |
| `GET` | `/api/v1/findings` | List findings (filter by severity, status, assignee) |
| `POST` | `/api/v1/findings/bulk-update` | Bulk triage (up to 500) |
| `POST` | `/api/v1/findings/{id}/triage` | Set status + reason |
| `POST` | `/api/v1/findings/{id}/notes` | Add investigation note |
| **Scan Schedules** | | |
| `GET` | `/api/v1/scan-schedules` | List scan schedules |
| `POST` | `/api/v1/scan-schedules` | Create a scan schedule (cron or interval) |
| `PUT` | `/api/v1/scan-schedules/{id}` | Update a scan schedule |
| `DELETE` | `/api/v1/scan-schedules/{id}` | Delete a scan schedule |
| **Reports & Email** | | |
| `GET` | `/api/v1/reports` | List reports |
| `POST` | `/api/v1/reports/{id}/email` | Email a branded PDF report to specified recipients |
| **Report Schedules** | | |
| `GET` | `/api/v1/report-schedules` | List report schedules |
| `POST` | `/api/v1/report-schedules` | Create a scheduled report (cron-based email delivery) |
| `PUT` | `/api/v1/report-schedules/{id}` | Update a report schedule |
| `DELETE` | `/api/v1/report-schedules/{id}` | Delete a report schedule |
| **CVEs & Compliance** | | |
| `GET` | `/api/v1/cves` | Search CVE database |
| `GET` | `/api/v1/governance/frameworks` | List compliance frameworks |
| `GET` | `/api/v1/governance/frameworks/{id}/controls` | Controls of one framework |
| `POST` | `/api/v1/governance/evaluate` | Evaluate compliance |
| **Integrations** | | |
| `POST` | `/api/v1/integrations/connect` | Connect GitHub, GitLab, Bitbucket or Azure DevOps with a token |
| `POST` | `/api/v1/webhooks/github/{org_id}` (also `gitlab`, `bitbucket`, `azure-devops`) | Webhook receiver (auto-scan). Signed with the organization's secret from `GET /api/v1/integrations/webhook-config`; unsigned requests are rejected |
| **SARIF Import** | | |
| `POST` | `/api/v1/imports/sarif` | Import SARIF JSON |
| `POST` | `/api/v1/imports/sarif/upload` | Import SARIF file upload |
| `GET` | `/api/v1/imports/` | List imports |
| `GET` | `/api/v1/imports/formats` | Supported import formats |
| **AI Copilot** | | |
| `POST` | `/api/v1/agents/chat` | AI Copilot (streaming SSE — single or multi-agent) |
| `POST` | `/api/v1/agents/autofix` | Generate code fix for a finding |
| `POST` | `/api/v1/agents/auto-triage` | AI-powered triage with confidence scores |
| `GET` | `/api/v1/agents/knowledge/stats` | Fix pattern knowledge store statistics |
| `GET` | `/api/v1/agents/manifest` | Full agent manifest (20 agents, 72 tools, capabilities) |
| **AI Copilot Chat** | | |
| `POST` | `/api/v1/agents/chat/stream` | Send a message (optional `attachment_ids`); the reply streams as server-sent events |
| `POST` | `/api/v1/agents/chat/files` | Attach a file to the next message (multipart); returns its id |
| `GET` | `/api/v1/agents/chat/files/{id}/download` | Download a file the assistant produced |
| `GET` | `/api/v1/agents/messages/{id}/pdf` | Any answer as a PDF |
| **Agent Runs & Approvals** | | |
| `POST` | `/api/v1/agents/runs` | Start a background agent task |
| `GET` | `/api/v1/agents/runs` · `/runs/{id}` | List runs; one run with its steps |
| `POST` | `/api/v1/agents/runs/{id}/cancel` | Cancel a run |
| `GET` | `/api/v1/agents/approvals` | Actions waiting for a decision |
| `POST` | `/api/v1/agents/approvals/{id}/decision` | Approve or reject an action |
| `GET` | `/api/v1/agents/usage` | Token usage of agent runs |
| **Cloud Accounts & Posture** | | |
| `POST` | `/api/v1/cloud-accounts/aws/federated` | Start a keyless AWS connection for an account ID |
| `GET` | `/api/v1/cloud-accounts/{id}/aws-template` | CloudFormation template for that connection |
| `GET` | `/api/v1/cloud-posture` | Posture of all accounts, or one with `?account_id=` |
| `POST` | `/api/v1/cloud-posture/evaluate` | Run the rules again on already synced data |
| `POST` | `/api/v1/cloud-posture/changes/{id}/rollback` | Undo a change GuardNous made in the cloud |
| `GET` | `/.well-known/openid-configuration` · `/.well-known/jwks.json` | Public OIDC discovery and signing keys (no auth) |
| **Agent Audit** | | |
| `GET` | `/api/v1/agent-audit/recent` | Recent agent executions with tool traces |
| `GET` | `/api/v1/agent-audit/conversation/{id}` | Audit entries for one conversation |
| **Plugin Version Management** | | |
| `GET` | `/api/v1/plugins/{name}/versions` | List available versions for a plugin |
| `POST` | `/api/v1/plugins/{name}/versions/install` | Install a specific plugin version |
| `POST` | `/api/v1/plugins/{name}/versions/activate` | Make an installed version the active one |
| `GET` / `PUT` | `/api/v1/plugins/{name}/versions/policy` | Read or set the version policy (pin or follow updates) |
| `POST` | `/api/v1/plugins/{name}/versions/rollback` | Roll back to the previous version |
| `GET` | `/api/v1/plugins/{name}/health` | Health of one plugin |
| `GET` | `/api/v1/plugins/supply-chain/health` | Supply chain overview for all plugins (CVEs, integrity, last check) |
| `GET` | `/api/v1/plugins/integrity` | Recorded checksums of scanner binaries |
| **Password Reset** | | |
| `POST` | `/api/v1/auth/forgot-password` | Send password reset email |
| `POST` | `/api/v1/auth/reset-password` | Reset password with token |
| **Organization Management** | | |
| `POST` | `/api/v1/org/switch/{org_id}` | Switch active organization (re-issues JWT) |
| `GET` | `/api/v1/org/users/search?q=` | Search users within tenant |
| `POST` | `/api/v1/org/assign-user` | Assign user to an organization |
| `DELETE` | `/api/v1/org/remove-user` | Remove user from an organization |
| `GET` | `/api/v1/org/user-memberships/{id}` | List user's org memberships |
| **Integrations** | | |
| `DELETE` | `/api/v1/integrations/repos/{full_name}` | Remove onboarded repository from scanning |
| **Admin** | | |
| `POST` | `/api/v1/users/invite` | Invite user (auto-sends branded email) |
| `POST` | `/api/v1/users/invite/bulk` | Bulk invite users |
| `POST` | `/api/v1/users/invite/csv` | Bulk invite from CSV upload |

---

