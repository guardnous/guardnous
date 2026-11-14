"use client";

import React, { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import PageLayout from "@/components/PageLayout";
import {
  getKnowledgeEntries,
  getKnowledgeStats,
  createKnowledgeEntry,
  deleteKnowledgeEntry,
  seedKnowledgeBase,
} from "@/lib/api";
import {
  BookOpen,
  Search,
  Plus,
  Trash2,
  Loader2,
  Sparkles,
  X,
  FileText,
  ChevronDown,
  ChevronUp,
  Tag,
  Shield,
  AlertTriangle,
  CheckCircle2,
  Wrench,
  ExternalLink,
} from "lucide-react";

/* ════════════════════════════════════════════════════════════
   CURATED SECURITY REFERENCE DATA
   ════════════════════════════════════════════════════════════ */

type RefCategory = "Vulnerabilities" | "Best Practices" | "Compliance" | "Remediation Guides";

interface SecurityArticle {
  id: string;
  title: string;
  summary: string;
  category: RefCategory;
  severity?: "critical" | "high" | "medium" | "low" | "info";
  tags: string[];
  content: string;
  references?: string[];
}

const SECURITY_ARTICLES: SecurityArticle[] = [
  // ── OWASP Top 10 2021 ──
  {
    id: "owasp-a01",
    title: "A01:2021 — Broken Access Control",
    summary: "Access control enforces policy such that users cannot act outside of their intended permissions. Failures lead to unauthorized disclosure, modification, or destruction of data.",
    category: "Vulnerabilities",
    severity: "critical",
    tags: ["OWASP", "A01", "Access Control", "CWE-200", "CWE-284"],
    content: `**Impact:** Attackers can access unauthorized functions or data, modify other users' data, or escalate privileges.\n\n**Common Weaknesses:**\n• Violation of least-privilege or deny-by-default\n• Bypassing access checks by modifying URL, API request, or internal state\n• Permitting viewing or editing someone else's account (IDOR)\n• Missing access control for POST, PUT, DELETE\n• Elevation of privilege — acting as admin when logged in as user\n\n**Remediation:**\n1. Deny by default — except for public resources\n2. Implement access control mechanisms once and reuse throughout the app\n3. Enforce record-level ownership checks\n4. Disable web server directory listing\n5. Log access control failures and alert admins\n6. Rate-limit API and controller access\n7. Invalidate JWT tokens on the server after logout`,
    references: ["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
  },
  {
    id: "owasp-a02",
    title: "A02:2021 — Cryptographic Failures",
    summary: "Failures related to cryptography which often lead to sensitive data exposure. Formerly known as 'Sensitive Data Exposure'.",
    category: "Vulnerabilities",
    severity: "critical",
    tags: ["OWASP", "A02", "Cryptography", "CWE-259", "CWE-327"],
    content: `**Impact:** Exposure of sensitive data such as passwords, credit card numbers, health records, personal information, or business secrets.\n\n**Common Weaknesses:**\n• Data transmitted in clear text (HTTP, SMTP, FTP)\n• Old or weak cryptographic algorithms (MD5, SHA1, DES)\n• Default or weak crypto keys, lack of key rotation\n• Missing TLS enforcement; invalid certificate validation\n• Passwords stored in plain text or with reversible encryption\n\n**Remediation:**\n1. Classify data processed, stored, or transmitted and apply controls per classification\n2. Don't store sensitive data unnecessarily — discard it ASAP\n3. Encrypt all data in transit with TLS 1.2+ and enforce with HSTS\n4. Use strong, up-to-date algorithms (AES-256, RSA-2048+, Argon2id for passwords)\n5. Ensure proper key management — rotate keys regularly\n6. Disable caching for sensitive data responses`,
    references: ["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"],
  },
  {
    id: "owasp-a03",
    title: "A03:2021 — Injection",
    summary: "Injection flaws occur when hostile data is sent to an interpreter as part of a command or query. SQL, NoSQL, OS, LDAP injection remain prevalent.",
    category: "Vulnerabilities",
    severity: "critical",
    tags: ["OWASP", "A03", "Injection", "SQLi", "CWE-79", "CWE-89"],
    content: `**Impact:** Complete data loss, data corruption, host takeover, and denial of service.\n\n**Common Weaknesses:**\n• User-supplied data not validated, filtered, or sanitized\n• Dynamic queries or non-parameterized calls without context-aware escaping\n• Hostile data used in ORM search parameters to extract sensitive records\n• Hostile data directly used or concatenated in SQL, commands, or stored procedures\n\n**Remediation:**\n1. Use parameterized queries / prepared statements (preferred)\n2. Use positive server-side input validation\n3. Escape special characters for any residual dynamic queries\n4. Use LIMIT and other SQL controls to prevent mass disclosure\n5. Use ORMs — but be aware they are not immune to injection\n6. Implement WAF as an additional layer`,
    references: ["https://owasp.org/Top10/A03_2021-Injection/"],
  },
  {
    id: "owasp-a04",
    title: "A04:2021 — Insecure Design",
    summary: "A new category focusing on risks related to design and architectural flaws. Secure design requires threat modeling, secure design patterns, and reference architectures.",
    category: "Vulnerabilities",
    severity: "high",
    tags: ["OWASP", "A04", "Design", "Threat Modeling"],
    content: `**Impact:** Fundamental security weaknesses that cannot be fixed by perfect implementation — the design itself is flawed.\n\n**Common Weaknesses:**\n• Missing or ineffective threat modeling\n• No security requirements in design phase\n• Insufficient separation of tenants in multi-tenant architectures\n• Missing rate limiting on business-critical functions\n• No defense-in-depth strategy\n\n**Remediation:**\n1. Establish a secure development lifecycle with AppSec professionals\n2. Use threat modeling for critical authentication, access control, business logic, and key flows\n3. Integrate security language and controls into user stories\n4. Write unit and integration tests to validate security-critical flows\n5. Segregate tenant processing and data at all tiers\n6. Limit resource consumption by user or service`,
    references: ["https://owasp.org/Top10/A04_2021-Insecure_Design/"],
  },
  {
    id: "owasp-a05",
    title: "A05:2021 — Security Misconfiguration",
    summary: "The application might be vulnerable if it is missing appropriate security hardening or has improperly configured permissions on cloud services.",
    category: "Vulnerabilities",
    severity: "high",
    tags: ["OWASP", "A05", "Configuration", "CWE-16"],
    content: `**Impact:** Unauthorized access to system data or functionality, potentially complete system compromise.\n\n**Common Weaknesses:**\n• Missing security hardening across application stack\n• Unnecessary features enabled (ports, services, pages, accounts, privileges)\n• Default accounts and passwords unchanged\n• Error handling reveals stack traces or overly informative messages\n• Security settings in frameworks/libraries not set to secure values\n• Missing security headers or directives\n• Software out of date or vulnerable\n\n**Remediation:**\n1. Implement a repeatable hardening process across all environments\n2. Remove or do not install unused features and frameworks\n3. Review and update configurations as part of patch management\n4. Use segmented application architecture with containerization or ACLs\n5. Send security directives to clients (Security Headers)\n6. Automate configuration verification across all environments`,
    references: ["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
  },
  {
    id: "owasp-a06",
    title: "A06:2021 — Vulnerable and Outdated Components",
    summary: "Components such as libraries, frameworks, and software modules run with the same privileges as the application. Known vulnerabilities in components can be exploited.",
    category: "Vulnerabilities",
    severity: "high",
    tags: ["OWASP", "A06", "Dependencies", "SCA", "CVE"],
    content: `**Impact:** While some known vulnerabilities lead to minor impacts, some of the largest breaches have relied on exploiting known vulnerabilities in components.\n\n**Common Weaknesses:**\n• You do not know the versions of all components you use (client and server side)\n• Software is vulnerable, unsupported, or out of date\n• You do not scan for vulnerabilities regularly\n• You do not fix or upgrade underlying platform, frameworks, and dependencies in a timely fashion\n• Developers do not test compatibility of updated, upgraded, or patched libraries\n\n**Remediation:**\n1. Remove unused dependencies and unnecessary features\n2. Continuously inventory versions of components and their dependencies (SCA tools)\n3. Monitor sources like NVD for vulnerabilities and subscribe to security advisories\n4. Only obtain components from official sources over secure links\n5. Monitor for unmaintained libraries/components; use virtual patching if needed`,
    references: ["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"],
  },
  {
    id: "owasp-a07",
    title: "A07:2021 — Identification and Authentication Failures",
    summary: "Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks.",
    category: "Vulnerabilities",
    severity: "high",
    tags: ["OWASP", "A07", "Authentication", "Session", "CWE-287"],
    content: `**Impact:** Attackers can compromise passwords, keys, session tokens, or exploit implementation flaws to assume other users' identities.\n\n**Common Weaknesses:**\n• Permits brute force or credential stuffing attacks\n• Permits default, weak, or well-known passwords\n• Uses weak credential recovery (knowledge-based answers)\n• Uses plain text, encrypted, or weakly hashed passwords\n• Missing or ineffective multi-factor authentication\n• Exposes session identifier in the URL\n• Reuses session identifier after successful login\n\n**Remediation:**\n1. Implement multi-factor authentication to prevent credential stuffing and brute force\n2. Ship without default credentials, especially for admin users\n3. Implement weak-password checks against top 10,000 worst passwords\n4. Align password policies with NIST 800-63b guidelines\n5. Harden registration, credential recovery, and API pathways against account enumeration\n6. Limit or increasingly delay failed login attempts; log all failures`,
    references: ["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
  },
  {
    id: "owasp-a08",
    title: "A08:2021 — Software and Data Integrity Failures",
    summary: "Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations, including insecure CI/CD pipelines.",
    category: "Vulnerabilities",
    severity: "high",
    tags: ["OWASP", "A08", "Integrity", "CI/CD", "Supply Chain"],
    content: `**Impact:** Unauthorized access, malicious code inclusion, or complete system compromise through supply chain attacks.\n\n**Common Weaknesses:**\n• Application relies upon plugins, libraries, or modules from untrusted sources\n• Insecure CI/CD pipeline can introduce opportunity for unauthorized access or malicious code\n• Auto-update functionality downloads updates without sufficient integrity verification\n• Objects or data encoded/serialized in a way that an attacker can see and modify\n\n**Remediation:**\n1. Use digital signatures to verify software/data from expected source and not altered\n2. Ensure libraries and dependencies consume trusted repositories\n3. Use a software supply chain security tool (e.g., OWASP Dependency Check)\n4. Ensure CI/CD pipeline has proper segregation, configuration, and access control\n5. Ensure unsigned or unencrypted serialized data is not sent to untrusted clients`,
    references: ["https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"],
  },
  {
    id: "owasp-a09",
    title: "A09:2021 — Security Logging and Monitoring Failures",
    summary: "Without logging and monitoring, breaches cannot be detected. Insufficient logging, detection, monitoring, and active response occurs any time.",
    category: "Vulnerabilities",
    severity: "medium",
    tags: ["OWASP", "A09", "Logging", "Monitoring", "SIEM"],
    content: `**Impact:** Inability to detect, escalate, or respond to active breaches. Attackers can pivot, persist, and extract/tamper/destroy data.\n\n**Common Weaknesses:**\n• Auditable events not logged (logins, failed logins, high-value transactions)\n• Warnings and errors generate no, inadequate, or unclear log messages\n• Logs only stored locally\n• Alerting thresholds and response escalation processes absent or ineffective\n• Penetration testing and DAST scans do not trigger alerts\n• Application cannot detect, escalate, or alert for active attacks in real-time\n\n**Remediation:**\n1. Ensure all login, access control, and server-side input validation failures are logged with sufficient user context\n2. Ensure logs are generated in a format easily consumed by centralized log management solutions\n3. Ensure high-value transactions have an audit trail with integrity controls\n4. Establish effective monitoring and alerting so suspicious activities are detected and responded to\n5. Establish or adopt an incident response and recovery plan`,
    references: ["https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"],
  },
  {
    id: "owasp-a10",
    title: "A10:2021 — Server-Side Request Forgery (SSRF)",
    summary: "SSRF flaws occur whenever a web application fetches a remote resource without validating the user-supplied URL, allowing attackers to coerce the server to send crafted requests.",
    category: "Vulnerabilities",
    severity: "high",
    tags: ["OWASP", "A10", "SSRF", "CWE-918"],
    content: `**Impact:** Attackers can scan internal networks, access internal services (metadata APIs, databases), read local files, or pivot to RCE.\n\n**Common Weaknesses:**\n• Application fetches remote resource using user-provided URL without validation\n• Allows access to internal services through the application server\n• Cloud metadata services (169.254.169.254) accessible via SSRF\n\n**Remediation:**\n1. Sanitize and validate all client-supplied input data\n2. Enforce URL schema, port, and destination with a positive allow list\n3. Do not send raw responses to clients\n4. Disable HTTP redirections\n5. Use network-level segmentation: deny-by-default firewall rules\n6. For cloud: block access to metadata endpoints (169.254.169.254) from application tier`,
    references: ["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"],
  },
  // ── Common CWE Entries ──
  {
    id: "cwe-79",
    title: "CWE-79 — Cross-Site Scripting (XSS)",
    summary: "The application does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output used as a web page served to other users.",
    category: "Vulnerabilities",
    severity: "high",
    tags: ["CWE", "XSS", "Injection", "OWASP A03"],
    content: `**Types:**\n• **Reflected XSS** — Payload delivered via URL parameter, reflected in response\n• **Stored XSS** — Payload persisted in database, rendered to other users\n• **DOM-based XSS** — Client-side JavaScript processes untrusted data\n\n**Remediation:**\n1. Use context-aware output encoding (HTML, JavaScript, URL, CSS)\n2. Use Content Security Policy (CSP) headers to mitigate impact\n3. Use modern frameworks that auto-escape by default (React, Angular, Vue)\n4. Sanitize HTML input with libraries like DOMPurify\n5. Set HttpOnly flag on session cookies\n6. Validate input on the server side — never trust client validation alone`,
    references: ["https://cwe.mitre.org/data/definitions/79.html"],
  },
  {
    id: "cwe-89",
    title: "CWE-89 — SQL Injection",
    summary: "The application constructs SQL commands using externally-influenced input without properly neutralizing special elements, allowing attackers to modify intended SQL queries.",
    category: "Vulnerabilities",
    severity: "critical",
    tags: ["CWE", "SQLi", "Injection", "OWASP A03"],
    content: `**Impact:** Complete database compromise — read, modify, or delete any data; bypass authentication; execute OS commands in some configurations.\n\n**Attack Patterns:**\n• **Classic:** \`' OR 1=1 --\` in login fields\n• **Union-based:** \`UNION SELECT username, password FROM users\`\n• **Blind:** Boolean or time-based inference of data\n• **Second-order:** Payload stored, triggered in a different query\n\n**Remediation:**\n1. **Parameterized queries** — the #1 defense (use \`?\` or \`:param\` placeholders)\n2. Use stored procedures (with parameterized calls)\n3. Validate input against an allow list of expected values\n4. Escape all user-supplied input (last resort, not primary defense)\n5. Enforce least privilege on database accounts\n6. Use WAF rules as defense-in-depth`,
    references: ["https://cwe.mitre.org/data/definitions/89.html"],
  },
  {
    id: "cwe-22",
    title: "CWE-22 — Path Traversal",
    summary: "The application uses external input to construct a pathname for a file or directory without properly neutralizing sequences like '../' that can resolve to locations outside the intended directory.",
    category: "Vulnerabilities",
    severity: "high",
    tags: ["CWE", "Path Traversal", "Directory Traversal", "LFI"],
    content: `**Impact:** Read arbitrary files (credentials, source code, /etc/passwd), write files (webshells), or delete files.\n\n**Attack Patterns:**\n• \`../../etc/passwd\` — classic traversal\n• \`..%2f..%2f\` — URL-encoded variants\n• \`....//....//\` — double-encoding bypass\n• Null byte injection: \`../../etc/passwd%00.png\`\n\n**Remediation:**\n1. Use a path canonicalization function and verify the result starts with the expected base directory\n2. Use an allow list of permitted file names\n3. Use chroot jails or containerization to restrict filesystem access\n4. Validate input — reject any path containing \`../\` or \`..\\\\\`\n5. Run the application with minimal filesystem permissions`,
    references: ["https://cwe.mitre.org/data/definitions/22.html"],
  },
  {
    id: "cwe-352",
    title: "CWE-352 — Cross-Site Request Forgery (CSRF)",
    summary: "The web application does not verify that a request was intentionally sent by the user, allowing attackers to trick victims into performing unintended actions.",
    category: "Vulnerabilities",
    severity: "medium",
    tags: ["CWE", "CSRF", "Session", "OWASP"],
    content: `**Impact:** Attackers can force authenticated users to perform state-changing operations — transfer funds, change email/password, modify data.\n\n**Remediation:**\n1. Use anti-CSRF tokens (synchronizer token pattern)\n2. Use SameSite cookie attribute (Lax or Strict)\n3. Verify Origin and Referer headers for state-changing requests\n4. Require re-authentication for sensitive operations\n5. Use custom request headers for AJAX/API calls (not automatically sent cross-origin)`,
    references: ["https://cwe.mitre.org/data/definitions/352.html"],
  },
  {
    id: "cwe-502",
    title: "CWE-502 — Deserialization of Untrusted Data",
    summary: "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid, leading to remote code execution or object injection.",
    category: "Vulnerabilities",
    severity: "critical",
    tags: ["CWE", "Deserialization", "RCE", "OWASP A08"],
    content: `**Impact:** Remote Code Execution (RCE), denial of service, authentication bypass, or arbitrary object injection.\n\n**Affected Technologies:**\n• Java (ObjectInputStream, XMLDecoder)\n• PHP (unserialize())\n• Python (pickle, yaml.load)\n• .NET (BinaryFormatter, XmlSerializer)\n• Ruby (Marshal.load)\n\n**Remediation:**\n1. Do not accept serialized objects from untrusted sources\n2. Use simple data formats like JSON instead of native serialization\n3. Implement integrity checks (digital signatures) on serialized objects\n4. Enforce strict type constraints during deserialization\n5. Run deserialization code in low-privilege environments\n6. Monitor and alert on frequent deserialization exceptions`,
    references: ["https://cwe.mitre.org/data/definitions/502.html"],
  },
  // ── Best Practices ──
  {
    id: "bp-secrets",
    title: "Secrets Management Best Practices",
    summary: "How to properly manage API keys, credentials, tokens, and other secrets across development, CI/CD, and production environments.",
    category: "Best Practices",
    severity: "info",
    tags: ["Secrets", "Vault", "CI/CD", "DevSecOps"],
    content: `**Core Principles:**\n1. **Never hardcode secrets** in source code, configs, or container images\n2. **Use a secrets manager** — HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, or GCP Secret Manager\n3. **Rotate secrets regularly** — automate rotation where possible\n4. **Use short-lived credentials** — prefer temporary tokens over long-lived API keys\n5. **Audit access** — log who accessed which secrets and when\n\n**CI/CD Integration:**\n• Use pipeline-native secret variables (GitHub Secrets, GitLab CI variables)\n• Never echo secrets in build logs\n• Use OIDC federation to eliminate static credentials in CI/CD\n• Scan for leaked secrets with tools like Gitleaks, TruffleHog, or detect-secrets\n\n**Development:**\n• Use .env files locally — ensure .env is in .gitignore\n• Use pre-commit hooks to block secret commits\n• Provide developers with personal, rotatable API keys`,
  },
  {
    id: "bp-iac-security",
    title: "Infrastructure as Code (IaC) Security",
    summary: "Security best practices for Terraform, CloudFormation, Bicep, and other IaC frameworks to prevent misconfigurations before deployment.",
    category: "Best Practices",
    severity: "info",
    tags: ["IaC", "Terraform", "CloudFormation", "CSPM"],
    content: `**Shift-Left IaC Security:**\n1. **Scan before deploy** — integrate Checkov, tfsec, KICS, or Terrascan into CI/CD\n2. **Policy-as-Code** — use OPA/Rego or Sentinel to enforce guardrails\n3. **Module versioning** — pin module versions, review before upgrading\n4. **State file security** — encrypt state at rest, use remote backends with access control\n5. **Least privilege IAM** — IaC deployment roles should have minimal permissions\n\n**Common IaC Misconfigurations:**\n• Public S3 buckets or storage accounts\n• Security groups with 0.0.0.0/0 ingress\n• Unencrypted databases or disks\n• Missing logging/monitoring configuration\n• Overly permissive IAM policies\n• Default VPC usage instead of custom networking`,
  },
  {
    id: "bp-container-security",
    title: "Container & Kubernetes Security",
    summary: "Hardening containers and orchestration platforms against runtime attacks, supply chain threats, and misconfigurations.",
    category: "Best Practices",
    severity: "info",
    tags: ["Containers", "Kubernetes", "Docker", "CIS Benchmark"],
    content: `**Image Security:**\n1. Use minimal base images (distroless, Alpine)\n2. Scan images for vulnerabilities (Trivy, Grype, Snyk Container)\n3. Sign images with Cosign or Notary\n4. Never run as root — use non-root USER in Dockerfile\n5. Multi-stage builds to minimize attack surface\n\n**Kubernetes Hardening:**\n1. Enable RBAC with least-privilege service accounts\n2. Use Network Policies to restrict pod-to-pod communication\n3. Enable Pod Security Standards (Restricted profile)\n4. Use read-only root filesystem where possible\n5. Implement resource quotas and limit ranges\n6. Regularly audit with kube-bench (CIS Kubernetes Benchmark)\n7. Use admission controllers (OPA Gatekeeper, Kyverno) for policy enforcement`,
  },
  // ── Compliance ──
  {
    id: "comp-nist",
    title: "NIST Cybersecurity Framework (CSF) 2.0 Overview",
    summary: "The NIST CSF provides a comprehensive framework for managing and reducing cybersecurity risk, organized into six core functions.",
    category: "Compliance",
    severity: "info",
    tags: ["NIST", "CSF", "Framework", "Risk Management"],
    content: `**Six Core Functions:**\n\n1. **GOVERN (GV)** — Establish and monitor cybersecurity risk management strategy, expectations, and policy\n2. **IDENTIFY (ID)** — Understand organizational context, assets, risks, and supply chain\n3. **PROTECT (PR)** — Implement safeguards (access control, training, data security)\n4. **DETECT (DE)** — Develop and implement monitoring to identify cybersecurity events\n5. **RESPOND (RS)** — Take action regarding detected cybersecurity incidents\n6. **RECOVER (RC)** — Restore capabilities impaired by cybersecurity incidents\n\n**Implementation Tiers:**\n• Tier 1: Partial — ad hoc, reactive\n• Tier 2: Risk-Informed — approved but not organization-wide\n• Tier 3: Repeatable — formally approved, regularly updated\n• Tier 4: Adaptive — continuously improving based on lessons learned`,
    references: ["https://www.nist.gov/cyberframework"],
  },
  {
    id: "comp-cis",
    title: "CIS Controls v8 — Prioritized Security Actions",
    summary: "The CIS Critical Security Controls are a prioritized set of actions to protect against the most pervasive cyber attacks. 18 controls organized by Implementation Group.",
    category: "Compliance",
    severity: "info",
    tags: ["CIS", "Controls", "Benchmark", "Hardening"],
    content: `**Implementation Group 1 (Essential — all orgs):**\n• Control 1: Inventory and Control of Enterprise Assets\n• Control 2: Inventory and Control of Software Assets\n• Control 3: Data Protection\n• Control 4: Secure Configuration of Enterprise Assets and Software\n• Control 5: Account Management\n• Control 6: Access Control Management\n\n**Implementation Group 2 (Foundational):**\n• Control 7: Continuous Vulnerability Management\n• Control 8: Audit Log Management\n• Control 9: Email and Web Browser Protections\n• Control 10: Malware Defenses\n• Control 11: Data Recovery\n• Control 12: Network Infrastructure Management\n\n**Implementation Group 3 (Organizational):**\n• Controls 13–18: Network monitoring, security awareness, service provider management, application software security, incident response, penetration testing`,
    references: ["https://www.cisecurity.org/controls"],
  },
  {
    id: "comp-soc2",
    title: "SOC 2 Trust Service Criteria",
    summary: "SOC 2 reports evaluate an organization's information systems relevant to security, availability, processing integrity, confidentiality, and privacy.",
    category: "Compliance",
    severity: "info",
    tags: ["SOC 2", "Audit", "Trust Services", "AICPA"],
    content: `**Five Trust Service Criteria:**\n\n1. **Security (Common Criteria)** — Protection against unauthorized access\n   • CC1-CC9: Control environment, communication, risk assessment, monitoring, logical/physical access, system operations, change management\n\n2. **Availability** — System is available for operation and use as committed\n   • Monitoring, disaster recovery, incident response, capacity planning\n\n3. **Processing Integrity** — System processing is complete, valid, accurate, timely\n   • Quality assurance, data validation, error handling\n\n4. **Confidentiality** — Confidential information is protected as committed\n   • Encryption, access controls, data classification, secure disposal\n\n5. **Privacy** — Personal information is collected, used, retained, and disclosed in conformity with the entity's privacy notice\n\n**Mapping to IaC Scanning:**\n• GuardNous maps cloud misconfigurations to relevant SOC 2 criteria\n• Encryption findings → Confidentiality + Security\n• Access control findings → Security (CC6)\n• Logging findings → Security (CC7) + Availability`,
  },
  // ── Remediation Guides ──
  {
    id: "rem-s3-public",
    title: "Remediation: Public S3 Bucket / Storage Account",
    summary: "Step-by-step guide to identify and fix publicly accessible cloud storage buckets across AWS, Azure, and GCP.",
    category: "Remediation Guides",
    severity: "critical",
    tags: ["AWS", "Azure", "GCP", "Storage", "Public Access"],
    content: `**AWS S3:**\n\`\`\`bash\n# Check public access\naws s3api get-public-access-block --bucket BUCKET_NAME\n\n# Block all public access\naws s3api put-public-access-block --bucket BUCKET_NAME \\\\\n  --public-access-block-configuration \\\\\n  BlockPublicAcls=true,IgnorePublicAcls=true,\\\\\n  BlockPublicPolicy=true,RestrictPublicBuckets=true\n\`\`\`\n\n**Azure Storage:**\n\`\`\`bash\n# Disable public blob access\naz storage account update --name ACCOUNT_NAME \\\\\n  --resource-group RG_NAME \\\\\n  --allow-blob-public-access false\n\`\`\`\n\n**GCP Cloud Storage:**\n\`\`\`bash\n# Remove allUsers/allAuthenticatedUsers IAM binding\ngsutil iam ch -d allUsers gs://BUCKET_NAME\ngsutil iam ch -d allAuthenticatedUsers gs://BUCKET_NAME\n\`\`\`\n\n**Terraform Prevention:**\n\`\`\`hcl\n# AWS\nresource "aws_s3_bucket_public_access_block" "block" {\n  bucket                  = aws_s3_bucket.main.id\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}\n\`\`\``,
  },
  {
    id: "rem-open-sg",
    title: "Remediation: Overly Permissive Security Groups / NSGs",
    summary: "How to identify and restrict security groups allowing unrestricted inbound access (0.0.0.0/0) on sensitive ports.",
    category: "Remediation Guides",
    severity: "high",
    tags: ["AWS", "Azure", "Network", "Firewall", "Security Group"],
    content: `**Identify the problem:**\n• Security group allows inbound 0.0.0.0/0 on SSH (22), RDP (3389), database (3306/5432), or all ports\n\n**AWS:**\n\`\`\`bash\n# Find overly permissive rules\naws ec2 describe-security-groups --query \\\\\n  \"SecurityGroups[?IpPermissions[?IpRanges[?CidrIp=='0.0.0.0/0']]]\"\n\n# Revoke specific rule\naws ec2 revoke-security-group-ingress \\\\\n  --group-id sg-xxx \\\\\n  --protocol tcp --port 22 --cidr 0.0.0.0/0\n\`\`\`\n\n**Azure:**\n\`\`\`bash\n# List NSG rules allowing any source\naz network nsg rule list -g RG_NAME --nsg-name NSG_NAME \\\\\n  --query \"[?sourceAddressPrefix=='*']\"\n\n# Update to restrict source\naz network nsg rule update -g RG_NAME --nsg-name NSG_NAME \\\\\n  -n RULE_NAME --source-address-prefixes 10.0.0.0/8\n\`\`\`\n\n**Best Practices:**\n• Use VPN or bastion host for SSH/RDP — never expose directly\n• Restrict database ports to application subnet CIDRs only\n• Use prefix lists or managed IP groups for maintainability\n• Review security groups quarterly`,
  },
  {
    id: "rem-unencrypted-db",
    title: "Remediation: Unencrypted Database Storage",
    summary: "Enable encryption at rest for RDS, Azure SQL, Cloud SQL, and other managed database services to protect data at rest.",
    category: "Remediation Guides",
    severity: "high",
    tags: ["Encryption", "Database", "AWS", "Azure", "GCP"],
    content: `**AWS RDS:**\n\`\`\`bash\n# Check encryption status\naws rds describe-db-instances --query \\\\\n  \"DBInstances[*].{ID:DBInstanceIdentifier,Encrypted:StorageEncrypted}\"\n\n# Enable encryption (requires snapshot + restore)\naws rds create-db-snapshot --db-instance-id mydb --db-snapshot-id mydb-snap\naws rds copy-db-snapshot --source-db-snapshot-id mydb-snap \\\\\n  --target-db-snapshot-id mydb-snap-enc --kms-key-id alias/aws/rds\naws rds restore-db-instance-from-db-snapshot \\\\\n  --db-instance-id mydb-encrypted --db-snapshot-id mydb-snap-enc\n\`\`\`\n\n**Azure SQL:**\n\`\`\`bash\n# TDE is enabled by default; verify:\naz sql db tde show -g RG -s SERVER -d DATABASE\n# Enable if somehow disabled:\naz sql db tde set -g RG -s SERVER -d DATABASE --status Enabled\n\`\`\`\n\n**Terraform Prevention:**\n\`\`\`hcl\nresource "aws_db_instance" "main" {\n  storage_encrypted = true\n  kms_key_id        = aws_kms_key.rds.arn\n}\n\`\`\``,
  },
];

const REF_CATEGORIES: RefCategory[] = [
  "Vulnerabilities",
  "Best Practices",
  "Compliance",
  "Remediation Guides",
];

const REF_CATEGORY_ICONS: Record<RefCategory, React.ElementType> = {
  Vulnerabilities: AlertTriangle,
  "Best Practices": CheckCircle2,
  Compliance: Shield,
  "Remediation Guides": Wrench,
};

const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-red-500/10 text-red-500 border-red-500/20",
  high: "bg-orange-500/10 text-orange-500 border-orange-500/20",
  medium: "bg-yellow-500/10 text-yellow-600 border-yellow-500/20",
  low: "bg-blue-500/10 text-blue-500 border-blue-500/20",
  info: "bg-slate-500/10 text-slate-500 border-slate-500/20",
};

/* ════════════════════════════════════════════════════════════
   KB STORE TYPES & COLORS (existing backend-driven tab)
   ════════════════════════════════════════════════════════════ */

interface KEntry {
  id: number;
  title: string;
  content: string;
  category: string;
  entry_type: string;
  tags: string;
  priority: number;
  is_active: boolean;
  created_by: string;
  created_at: string | null;
  updated_at: string | null;
}

const CATEGORY_COLORS: Record<string, string> = {
  runbook: "bg-blue-50 text-blue-700 border-blue-200",
  playbook: "bg-purple-50 text-purple-700 border-purple-200",
  infrastructure: "bg-emerald-50 text-emerald-700 border-emerald-200",
  known_issue: "bg-amber-50 text-amber-700 border-amber-200",
  escalation: "bg-red-50 text-red-700 border-red-200",
  compliance: "bg-orange-50 text-orange-700 border-orange-200",
  architecture: "bg-cyan-50 text-cyan-700 border-cyan-200",
  custom_rule: "bg-gray-50 text-gray-700 border-gray-200",
};

/* ════════════════════════════════════════════════════════════
   MAIN PAGE — TABBED LAYOUT
   ════════════════════════════════════════════════════════════ */

type TabKey = "reference" | "store";

export default function KnowledgeBasePage() {
  const [activeTab, setActiveTab] = useState<TabKey>("reference");

  return (
    <PageLayout
      title="Knowledge Base"
      subtitle="Security reference library & org knowledge for AI-powered triage"
      icon={BookOpen}
      breadcrumbs={[{ label: "Home", href: "/dashboard" }, { label: "Knowledge Base" }]}
    >
      {/* Tab bar */}
      <div className="mb-6 flex gap-1 rounded-lg border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50 p-1 w-fit">
        {([
          { key: "reference" as TabKey, label: "Security Reference", icon: Shield },
          { key: "store" as TabKey, label: "Knowledge Store", icon: FileText },
        ]).map(({ key, label, icon: TabIcon }) => (
          <button
            key={key}
            onClick={() => setActiveTab(key)}
            className={`inline-flex items-center gap-1.5 rounded-md px-4 py-2 text-[13px] font-medium transition-colors ${
              activeTab === key
                ? "bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm"
                : "text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200"
            }`}
          >
            <TabIcon className="h-4 w-4" />
            {label}
          </button>
        ))}
      </div>

      {activeTab === "reference" ? <SecurityReferenceTab /> : <KnowledgeStoreTab />}
    </PageLayout>
  );
}

/* ════════════════════════════════════════════════════════════
   TAB 1 — SECURITY REFERENCE (curated OWASP / CWE / NIST)
   ════════════════════════════════════════════════════════════ */

function SecurityReferenceTab() {
  const [search, setSearch] = useState("");
  const [refCategory, setRefCategory] = useState<RefCategory | "">("");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const filtered = useMemo(() => {
    let arts = SECURITY_ARTICLES;
    if (refCategory) arts = arts.filter((a) => a.category === refCategory);
    if (search.trim()) {
      const q = search.toLowerCase();
      arts = arts.filter(
        (a) =>
          a.title.toLowerCase().includes(q) ||
          a.summary.toLowerCase().includes(q) ||
          a.tags.some((t) => t.toLowerCase().includes(q))
      );
    }
    return arts;
  }, [search, refCategory]);

  const countByCategory = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const cat of REF_CATEGORIES) {
      counts[cat] = SECURITY_ARTICLES.filter((a) => a.category === cat).length;
    }
    return counts;
  }, []);

  return (
    <>
      {/* Category stat cards */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 mb-4">
        {REF_CATEGORIES.map((cat) => {
          const Icon = REF_CATEGORY_ICONS[cat];
          return (
            <button
              key={cat}
              onClick={() => setRefCategory(refCategory === cat ? "" : cat)}
              className={`rounded-xl border p-4 text-left transition-colors ${
                refCategory === cat
                  ? "border-orange-400 bg-orange-50 dark:bg-orange-500/10 dark:border-orange-500/40"
                  : "border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 hover:border-gray-300 dark:hover:border-gray-600"
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-[12px] text-gray-500 dark:text-gray-400">{cat}</span>
                <Icon className={`h-4 w-4 ${refCategory === cat ? "text-orange-500" : "text-gray-300 dark:text-gray-600"}`} />
              </div>
              <p className="mt-1 text-[22px] font-semibold text-gray-900 dark:text-white">
                {countByCategory[cat]}
              </p>
            </button>
          );
        })}
      </div>

      {/* Search */}
      <div className="relative mb-4">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search OWASP, CWE, NIST, remediation guides…"
          className="w-full rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 py-2 pl-9 pr-3 text-[13px] text-gray-900 dark:text-white outline-none focus:border-orange-400 placeholder:text-gray-400"
        />
      </div>

      {/* Results count */}
      <p className="mb-3 text-[12px] text-gray-500 dark:text-gray-400">
        {filtered.length} article{filtered.length !== 1 ? "s" : ""}
        {refCategory ? ` in ${refCategory}` : ""}
        {search ? ` matching "${search}"` : ""}
      </p>

      {/* Article cards */}
      {filtered.length === 0 ? (
        <div className="rounded-xl border border-dashed border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 py-16 text-center">
          <Search className="mx-auto h-10 w-10 text-gray-300 dark:text-gray-600" />
          <p className="mt-3 text-[14px] font-medium text-gray-700 dark:text-gray-300">No articles found</p>
          <p className="mt-1 text-[13px] text-gray-500 dark:text-gray-400">
            Try a different search term or category.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map((article) => {
            const isOpen = expandedId === article.id;
            const CatIcon = REF_CATEGORY_ICONS[article.category];
            return (
              <div
                key={article.id}
                className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 overflow-hidden"
              >
                <button
                  onClick={() => setExpandedId(isOpen ? null : article.id)}
                  className="flex w-full items-start gap-3 p-4 text-left"
                >
                  <div className="mt-0.5">
                    {isOpen ? (
                      <ChevronUp className="h-4 w-4 text-gray-400" />
                    ) : (
                      <ChevronDown className="h-4 w-4 text-gray-400" />
                    )}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-[14px] font-semibold text-gray-900 dark:text-white">
                        {article.title}
                      </span>
                      {article.severity && (
                        <span
                          className={`rounded-full border px-2 py-0.5 text-[11px] font-medium capitalize ${
                            SEVERITY_BADGE[article.severity]
                          }`}
                        >
                          {article.severity}
                        </span>
                      )}
                      <span className="inline-flex items-center gap-1 rounded-full border border-gray-200 dark:border-gray-600 bg-gray-50 dark:bg-gray-700 px-2 py-0.5 text-[11px] text-gray-600 dark:text-gray-300">
                        <CatIcon className="h-3 w-3" />
                        {article.category}
                      </span>
                    </div>
                    <p className="mt-1 text-[13px] text-gray-500 dark:text-gray-400 line-clamp-2">
                      {article.summary}
                    </p>
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {article.tags.map((t) => (
                        <span
                          key={t}
                          className="text-[11px] text-orange-500/70 dark:text-orange-400/70"
                        >
                          #{t}
                        </span>
                      ))}
                    </div>
                  </div>
                </button>

                {isOpen && (
                  <div className="border-t border-gray-100 dark:border-gray-700 bg-gray-50/50 dark:bg-gray-900/30 px-4 py-4">
                    <div className="prose prose-sm dark:prose-invert max-w-none">
                      <pre className="whitespace-pre-wrap font-mono text-[12px] leading-relaxed text-gray-700 dark:text-gray-300">
                        {article.content}
                      </pre>
                    </div>
                    {article.references && article.references.length > 0 && (
                      <div className="mt-4 pt-3 border-t border-gray-200 dark:border-gray-700">
                        <p className="text-[11px] font-medium text-gray-500 dark:text-gray-400 mb-1">
                          References
                        </p>
                        {article.references.map((ref) => (
                          <a
                            key={ref}
                            href={ref}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 text-[12px] text-orange-600 dark:text-orange-400 hover:underline mr-4"
                          >
                            <ExternalLink className="h-3 w-3" />
                            {ref.replace(/^https?:\/\//, "").split("/").slice(0, 2).join("/")}
                          </a>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </>
  );
}

/* ════════════════════════════════════════════════════════════
   TAB 2 — KNOWLEDGE STORE (existing backend-driven tab)
   ════════════════════════════════════════════════════════════ */

function KnowledgeStoreTab() {
  const qc = useQueryClient();
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("");
  const [expanded, setExpanded] = useState<number | null>(null);
  const [showCreate, setShowCreate] = useState(false);

  const { data, isLoading } = useQuery({
    queryKey: ["kb-entries", search, category],
    queryFn: () =>
      getKnowledgeEntries({
        ...(search ? { search } : {}),
        ...(category ? { category } : {}),
        page_size: 100,
      }),
  });

  const { data: stats } = useQuery({
    queryKey: ["kb-stats"],
    queryFn: getKnowledgeStats,
  });

  const seedMut = useMutation({
    mutationFn: seedKnowledgeBase,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["kb-entries"] });
      qc.invalidateQueries({ queryKey: ["kb-stats"] });
    },
  });

  const delMut = useMutation({
    mutationFn: deleteKnowledgeEntry,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["kb-entries"] });
      qc.invalidateQueries({ queryKey: ["kb-stats"] });
    },
  });

  const entries: KEntry[] = data?.entries ?? [];
  const categories: string[] = data?.categories ?? [];
  const total: number = data?.total ?? 0;

  return (
    <>
      {/* Actions */}
      <div className="flex items-center gap-2 mb-4">
        {total === 0 && (
          <button
            onClick={() => seedMut.mutate()}
            disabled={seedMut.isPending}
            className="inline-flex items-center gap-1.5 rounded-lg bg-orange-500 px-3 py-2 text-[13px] font-medium text-white hover:bg-orange-600 disabled:opacity-60"
          >
            {seedMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />}
            Seed default knowledge
          </button>
        )}
        <button
          onClick={() => setShowCreate(true)}
          className="inline-flex items-center gap-1.5 rounded-lg border border-gray-200 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2 text-[13px] font-medium text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-700"
        >
          <Plus className="h-4 w-4" /> New entry
        </button>
        {(seedMut.isError || delMut.isError) && (
          <span className="text-[13px] text-red-600 dark:text-red-400">
            {[seedMut.error, delMut.error].some((e: any) => e?.response?.status === 403)
              ? "You do not have permission to change this"
              : "Request failed"}
          </span>
        )}
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 mb-4">
        <StatCard label="Total entries" value={stats?.total_entries ?? 0} icon={BookOpen} />
        <StatCard label="Categories" value={Object.keys(stats?.by_category ?? {}).length} icon={Tag} />
        <StatCard label="Runbooks" value={stats?.by_type?.runbook ?? 0} icon={FileText} />
        <StatCard label="Playbooks" value={stats?.by_type?.playbook ?? 0} icon={FileText} />
      </div>

      {/* Filters */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center mb-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search runbooks, playbooks, knowledge…"
            className="w-full rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 py-2 pl-9 pr-3 text-[13px] text-gray-900 dark:text-white outline-none focus:border-orange-400 placeholder:text-gray-400"
          />
        </div>
        <select
          value={category}
          onChange={(e) => setCategory(e.target.value)}
          className="rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 px-3 py-2 text-[13px] text-gray-900 dark:text-white outline-none focus:border-orange-400"
        >
          <option value="">All categories</option>
          {categories.map((c) => (
            <option key={c} value={c}>
              {c.replace(/_/g, " ")}
            </option>
          ))}
        </select>
      </div>

      {/* List */}
      {isLoading ? (
        <div className="flex items-center justify-center py-20 text-gray-400">
          <Loader2 className="h-6 w-6 animate-spin" />
        </div>
      ) : entries.length === 0 ? (
        <div className="rounded-xl border border-dashed border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 py-16 text-center">
          <BookOpen className="mx-auto h-10 w-10 text-gray-300 dark:text-gray-600" />
          <p className="mt-3 text-[14px] font-medium text-gray-700 dark:text-gray-300">No knowledge entries yet</p>
          <p className="mt-1 text-[13px] text-gray-500 dark:text-gray-400">
            Seed the default runbooks & playbooks, or create your own.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {entries.map((e) => {
            const open = expanded === e.id;
            return (
              <div key={e.id} className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 overflow-hidden">
                <div className="flex items-start justify-between gap-3 p-4">
                  <button
                    onClick={() => setExpanded(open ? null : e.id)}
                    className="flex flex-1 items-start gap-3 text-left"
                  >
                    <div className="mt-0.5">
                      {open ? (
                        <ChevronUp className="h-4 w-4 text-gray-400" />
                      ) : (
                        <ChevronDown className="h-4 w-4 text-gray-400" />
                      )}
                    </div>
                    <div className="flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-[14px] font-semibold text-gray-900 dark:text-white">{e.title}</span>
                        <span
                          className={`rounded-full border px-2 py-0.5 text-[11px] font-medium ${
                            CATEGORY_COLORS[e.category] ?? "bg-gray-50 text-gray-600 border-gray-200"
                          }`}
                        >
                          {e.category.replace(/_/g, " ")}
                        </span>
                        <span className="rounded-full border border-gray-200 dark:border-gray-600 bg-gray-50 dark:bg-gray-700 px-2 py-0.5 text-[11px] text-gray-600 dark:text-gray-300">
                          {e.entry_type}
                        </span>
                      </div>
                      {e.tags && (
                        <div className="mt-1 flex flex-wrap gap-1">
                          {e.tags.split(",").filter(Boolean).map((t) => (
                            <span key={t} className="text-[11px] text-gray-400">
                              #{t.trim()}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </button>
                  <button
                    onClick={() => {
                      if (confirm(`Delete "${e.title}"?`)) delMut.mutate(e.id);
                    }}
                    className="rounded-md p-1.5 text-gray-400 hover:bg-red-50 hover:text-red-600"
                    title="Delete entry"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
                {open && (
                  <div className="border-t border-gray-100 dark:border-gray-700 bg-gray-50/50 dark:bg-gray-900/30 px-4 py-3">
                    <pre className="whitespace-pre-wrap font-mono text-[12px] leading-relaxed text-gray-700 dark:text-gray-300">
                      {e.content}
                    </pre>
                    <p className="mt-3 text-[11px] text-gray-400">
                      By {e.created_by} · priority {e.priority}
                    </p>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {showCreate && (
        <CreateEntryModal
          categories={categories.length ? categories : ["runbook", "playbook", "infrastructure", "known_issue", "escalation", "compliance", "architecture", "custom_rule"]}
          entryTypes={data?.entry_types ?? ["runbook", "playbook", "pattern", "document", "sop", "checklist"]}
          onClose={() => setShowCreate(false)}
          onCreated={() => {
            setShowCreate(false);
            qc.invalidateQueries({ queryKey: ["kb-entries"] });
            qc.invalidateQueries({ queryKey: ["kb-stats"] });
          }}
        />
      )}
    </>
  );
}

/* ════════════════════════════════════════════════════════════
   SHARED COMPONENTS
   ════════════════════════════════════════════════════════════ */

function StatCard({ label, value, icon: Icon }: { label: string; value: number; icon: React.ElementType }) {
  return (
    <div className="rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 p-4">
      <div className="flex items-center justify-between">
        <span className="text-[12px] text-gray-500 dark:text-gray-400">{label}</span>
        <Icon className="h-4 w-4 text-gray-300 dark:text-gray-600" />
      </div>
      <p className="mt-1 text-[22px] font-semibold text-gray-900 dark:text-white">{value}</p>
    </div>
  );
}

function CreateEntryModal({
  categories,
  entryTypes,
  onClose,
  onCreated,
}: {
  categories: string[];
  entryTypes: string[];
  onClose: () => void;
  onCreated: () => void;
}) {
  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");
  const [category, setCategory] = useState(categories[0] ?? "runbook");
  const [entryType, setEntryType] = useState(entryTypes[0] ?? "runbook");
  const [tags, setTags] = useState("");
  const [err, setErr] = useState("");

  const mut = useMutation({
    mutationFn: () =>
      createKnowledgeEntry({ title, content, category, entry_type: entryType, tags, priority: 50 }),
    onSuccess: onCreated,
    onError: (e: any) => setErr(e?.response?.data?.detail ?? "Failed to create entry"),
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div className="w-full max-w-2xl rounded-2xl bg-white dark:bg-gray-800 shadow-xl">
        <div className="flex items-center justify-between border-b border-gray-100 dark:border-gray-700 px-5 py-4">
          <h3 className="text-[15px] font-semibold text-gray-900 dark:text-white">New knowledge entry</h3>
          <button onClick={onClose} className="rounded-md p-1 text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700">
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="space-y-3 p-5">
          {err && (
            <div className="rounded-lg bg-red-50 dark:bg-red-900/30 px-3 py-2 text-[13px] text-red-700 dark:text-red-400">{err}</div>
          )}
          <input
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Title"
            className="w-full rounded-lg border border-gray-200 dark:border-gray-600 bg-white dark:bg-gray-700 px-3 py-2 text-[13px] text-gray-900 dark:text-white outline-none focus:border-orange-400"
          />
          <div className="grid grid-cols-2 gap-3">
            <select
              value={category}
              onChange={(e) => setCategory(e.target.value)}
              className="rounded-lg border border-gray-200 dark:border-gray-600 bg-white dark:bg-gray-700 px-3 py-2 text-[13px] text-gray-900 dark:text-white outline-none focus:border-orange-400"
            >
              {categories.map((c) => (
                <option key={c} value={c}>
                  {c.replace(/_/g, " ")}
                </option>
              ))}
            </select>
            <select
              value={entryType}
              onChange={(e) => setEntryType(e.target.value)}
              className="rounded-lg border border-gray-200 dark:border-gray-600 bg-white dark:bg-gray-700 px-3 py-2 text-[13px] text-gray-900 dark:text-white outline-none focus:border-orange-400"
            >
              {entryTypes.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </div>
          <input
            value={tags}
            onChange={(e) => setTags(e.target.value)}
            placeholder="Tags (comma-separated)"
            className="w-full rounded-lg border border-gray-200 dark:border-gray-600 bg-white dark:bg-gray-700 px-3 py-2 text-[13px] text-gray-900 dark:text-white outline-none focus:border-orange-400"
          />
          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            placeholder="Content (markdown supported)…"
            rows={10}
            className="w-full rounded-lg border border-gray-200 dark:border-gray-600 bg-white dark:bg-gray-700 px-3 py-2 font-mono text-[12px] text-gray-900 dark:text-white outline-none focus:border-orange-400"
          />
        </div>
        <div className="flex justify-end gap-2 border-t border-gray-100 dark:border-gray-700 px-5 py-4">
          <button onClick={onClose} className="rounded-lg px-4 py-2 text-[13px] font-medium text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700">
            Cancel
          </button>
          <button
            onClick={() => {
              setErr("");
              if (!title.trim() || !content.trim()) {
                setErr("Title and content are required.");
                return;
              }
              mut.mutate();
            }}
            disabled={mut.isPending}
            className="inline-flex items-center gap-1.5 rounded-lg bg-orange-500 px-4 py-2 text-[13px] font-medium text-white hover:bg-orange-600 disabled:opacity-60"
          >
            {mut.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
            Create
          </button>
        </div>
      </div>
    </div>
  );
}
