import re
from app.services.scanners.base import BaseScanner, ScanResult

try:
    import hcl2
    HCL2_AVAILABLE = True
except ImportError:
    HCL2_AVAILABLE = False


class TerraformScanner(BaseScanner):
    """Terraform (.tf) file security scanner with 40 enterprise security checks."""

    def detect_cloud_provider(self, content: str) -> str:
        if "aws_" in content or '"aws"' in content:
            return "aws"
        if "google_" in content or '"google"' in content:
            return "gcp"
        if "azurerm_" in content or '"azurerm"' in content:
            return "azure"
        return "aws"

    def scan(self, content: str, file_name: str = "") -> list[ScanResult]:
        results = []
        cloud = self.detect_cloud_provider(content)
        parsed = self._parse_hcl(content)
        lines = content.split("\n")

        # Run all 40 enterprise checks
        checks = [
            self._check_public_security_group,
            self._check_unencrypted_s3,
            self._check_public_s3_bucket,
            self._check_unencrypted_rds,
            self._check_public_rds,
            self._check_overly_permissive_iam,
            self._check_wildcard_iam_actions,
            self._check_missing_logging,
            self._check_hardcoded_secrets,
            self._check_unencrypted_ebs,
            self._check_default_vpc,
            self._check_open_ssh,
            self._check_open_rdp,
            self._check_missing_tags,
            self._check_unencrypted_sqs,
            self._check_public_ecr,
            self._check_missing_ssl_rds,
            self._check_unencrypted_elasticache,
            self._check_public_lambda,
            self._check_missing_vpc_flow_logs,
            self._check_unencrypted_efs,
            self._check_missing_backup,
            self._check_insecure_tls,
            self._check_missing_monitoring,
            self._check_overly_broad_cidr,
            # Enterprise checks 26-40
            self._check_s3_block_public_access,
            self._check_s3_versioning,
            self._check_cloudtrail,
            self._check_kms_key_rotation,
            self._check_ec2_imdsv2,
            self._check_rds_deletion_protection,
            self._check_rds_multi_az,
            self._check_guardduty,
            self._check_sns_encryption,
            self._check_dynamodb_encryption,
            self._check_cloudwatch_log_encryption,
            self._check_lambda_vpc,
            self._check_secrets_manager_rotation,
            self._check_eks_encryption,
            self._check_eks_public_endpoint,
        ]

        for check in checks:
            results.extend(check(content, parsed, lines, cloud, file_name))

        return results

    def _parse_hcl(self, content: str) -> dict:
        if not HCL2_AVAILABLE:
            return {}
        try:
            import io
            return hcl2.load(io.StringIO(content))
        except Exception:
            return {}

    def _find_line(self, lines: list[str], pattern: str) -> int:
        for i, line in enumerate(lines, 1):
            if pattern in line:
                return i
        return 0

    def _find_line_regex(self, lines: list[str], pattern: str) -> int:
        compiled = re.compile(pattern, re.IGNORECASE)
        for i, line in enumerate(lines, 1):
            if compiled.search(line):
                return i
        return 0

    def _get_snippet(self, lines: list[str], line_num: int, context: int = 2) -> str:
        if line_num <= 0:
            return ""
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        return "\n".join(lines[start:end])

    # === CHECK 1: Public Security Groups (0.0.0.0/0 or ::/0) ===
    def _check_public_security_group(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        # Match cidr_blocks containing 0.0.0.0/0 (IPv4) or ::/0 (IPv6)
        pattern = r'cidr_blocks\s*=\s*\[([^\]]*"0\.0\.0\.0/0"[^\]]*)\]'
        ipv6_pattern = r'ipv6_cidr_blocks\s*=\s*\[([^\]]*"::/0"[^\]]*)\]'
        for pat, cidr_label in [(pattern, "0.0.0.0/0"), (ipv6_pattern, "::/0")]:
            for match in re.finditer(pat, content):
                line_num = content[:match.start()].count("\n") + 1
                # Check if this is in an ingress block (not egress)
                block_context_start = max(0, match.start() - 500)
                preceding = content[block_context_start:match.start()]
                # If this is inside an egress block, skip — egress to 0.0.0.0/0 is normal
                last_ingress = preceding.rfind("ingress")
                last_egress = preceding.rfind("egress")
                if last_egress > last_ingress:
                    continue
                results.append(ScanResult(
                    rule_id="SD-TF-001",
                    title=f"Security group allows ingress from {cidr_label}",
                    description=f"Security group has an ingress rule that allows traffic from any IP address ({cidr_label}). This exposes resources to the entire internet.",
                    severity="CRITICAL",
                    cloud_provider=cloud,
                    resource_type="aws_security_group",
                    file_path=file_name,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Restrict cidr_blocks to specific IP ranges. Use VPN or bastion host for access.",
                ))
        return results

    # === CHECK 2: Unencrypted S3 (no explicit KMS/CMK encryption) ===
    def _check_unencrypted_s3(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        # Since Jan 2023, S3 encrypts with SSE-S3 by default. This check now looks
        # for missing *explicit* encryption config (KMS/CMK), which is a best-practice
        # recommendation — not a critical gap.
        for match in re.finditer(r'resource\s+"aws_s3_bucket"\s+"(\w+)"', content):
            bucket_name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            # Per-bucket check: look inside the bucket block AND for a companion resource
            has_inline_enc = "server_side_encryption_configuration" in block
            # Also check for companion aws_s3_bucket_server_side_encryption_configuration resource
            companion_pat = rf'resource\s+"aws_s3_bucket_server_side_encryption_configuration"[^{{]*\{{[^}}]*{bucket_name}'
            has_companion_enc = bool(re.search(companion_pat, content, re.DOTALL))
            if not has_inline_enc and not has_companion_enc:
                line_num = content[:block_start].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-TF-002",
                    title=f"S3 bucket '{bucket_name}' uses default SSE-S3 encryption only",
                    description="S3 bucket relies on default AWS SSE-S3 encryption (AES-256). For sensitive data, consider using SSE-KMS with a customer-managed key for audit trail and key rotation.",
                    severity="MEDIUM",
                    cloud_provider="aws",
                    resource_type="aws_s3_bucket",
                    resource_name=bucket_name,
                    file_path=file_name,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Add server_side_encryption_configuration with aws:kms algorithm and a KMS key for enhanced control.",
                ))
        return results

    # === CHECK 3: Public S3 Bucket ===
    def _check_public_s3_bucket(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        pattern = r'acl\s*=\s*"(public-read|public-read-write)"'
        for match in re.finditer(pattern, content):
            acl = match.group(1)
            line_num = content[:match.start()].count("\n") + 1
            results.append(ScanResult(
                rule_id="SD-TF-003",
                title=f"S3 bucket has public ACL: {acl}",
                description=f"S3 bucket is configured with '{acl}' ACL. This allows public access to bucket contents.",
                severity="CRITICAL",
                cloud_provider="aws",
                resource_type="aws_s3_bucket",
                file_path=file_name,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="Set acl to 'private' and use bucket policies for controlled access.",
            ))
        return results

    # === CHECK 4: Unencrypted RDS ===
    def _check_unencrypted_rds(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r'resource\s+"aws_db_instance"\s+"(\w+)"', content):
            db_name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if "storage_encrypted" not in block or "storage_encrypted = false" in block or re.search(r"storage_encrypted\s*=\s*false", block):
                line_num = content[:block_start].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-TF-004",
                    title=f"RDS instance '{db_name}' storage not encrypted",
                    description="RDS instance does not have storage encryption enabled. Database data at rest should be encrypted.",
                    severity="HIGH",
                    cloud_provider="aws",
                    resource_type="aws_db_instance",
                    resource_name=db_name,
                    file_path=file_name,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Set storage_encrypted = true in the aws_db_instance resource.",
                ))
        return results

    # === CHECK 5: Public RDS ===
    def _check_public_rds(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        pattern = r'publicly_accessible\s*=\s*true'
        for match in re.finditer(pattern, content):
            line_num = content[:match.start()].count("\n") + 1
            results.append(ScanResult(
                rule_id="SD-TF-005",
                title="RDS instance is publicly accessible",
                description="RDS instance has publicly_accessible set to true. Databases should not be directly accessible from the internet.",
                severity="CRITICAL",
                cloud_provider="aws",
                resource_type="aws_db_instance",
                file_path=file_name,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="Set publicly_accessible = false and use private subnets with VPN access.",
            ))
        return results

    # === CHECK 6: Overly Permissive IAM ===
    def _check_overly_permissive_iam(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        # Match individual policy statements — look for Allow + Resource:* within
        # the same statement block (bounded by {}), not across the entire file.
        # Find all statement-like blocks with Effect: Allow
        stmt_pattern = r'\{[^{}]*"Effect"\s*:\s*"Allow"[^{}]*"Resource"\s*:\s*"\*"[^{}]*\}'
        # Also match reversed order (Resource before Effect)
        stmt_pattern2 = r'\{[^{}]*"Resource"\s*:\s*"\*"[^{}]*"Effect"\s*:\s*"Allow"[^{}]*\}'
        seen_lines = set()
        for pat in [stmt_pattern, stmt_pattern2]:
            for match in re.finditer(pat, content, re.DOTALL):
                line_num = content[:match.start()].count("\n") + 1
                if line_num not in seen_lines:
                    seen_lines.add(line_num)
                    results.append(ScanResult(
                        rule_id="SD-TF-006",
                        title="IAM policy allows access to all resources (*)",
                        description="IAM policy statement grants permissions on all resources (Resource: *). Follow least-privilege principle.",
                        severity="HIGH",
                        cloud_provider="aws",
                        resource_type="aws_iam_policy",
                        file_path=file_name,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation="Restrict Resource to specific ARNs instead of using wildcard (*).",
                    ))
        return results

    # === CHECK 7: Wildcard IAM Actions ===
    def _check_wildcard_iam_actions(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        pattern = r'"Action"\s*:\s*\[?\s*"\*"\s*\]?'
        for match in re.finditer(pattern, content):
            line_num = content[:match.start()].count("\n") + 1
            results.append(ScanResult(
                rule_id="SD-TF-007",
                title="IAM policy uses wildcard (*) actions",
                description="IAM policy grants all actions (*). This violates the principle of least privilege.",
                severity="CRITICAL",
                cloud_provider="aws",
                resource_type="aws_iam_policy",
                file_path=file_name,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="Replace wildcard actions with specific actions needed (e.g., s3:GetObject).",
            ))
        return results

    # === CHECK 8: Missing Logging ===
    def _check_missing_logging(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r'resource\s+"aws_s3_bucket"\s+"(\w+)"', content):
            bucket_name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            # Per-bucket check: inline logging block OR companion resource
            has_inline_logging = "logging" in block
            companion_pat = rf'resource\s+"aws_s3_bucket_logging"[^{{]*\{{[^}}]*{bucket_name}'
            has_companion_logging = bool(re.search(companion_pat, content, re.DOTALL))
            if not has_inline_logging and not has_companion_logging:
                line_num = content[:block_start].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-TF-008",
                    title=f"S3 bucket '{bucket_name}' missing access logging",
                    description="S3 bucket does not have access logging enabled. Enable logging for audit trail.",
                    severity="MEDIUM",
                    cloud_provider="aws",
                    resource_type="aws_s3_bucket",
                    resource_name=bucket_name,
                    file_path=file_name,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Add aws_s3_bucket_logging resource or logging block to enable access logging.",
                ))
        return results

    # === CHECK 9: Hardcoded Secrets ===
    def _check_hardcoded_secrets(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        patterns = [
            (r'(?:password|secret|api_key|access_key)\s*=\s*"(?!var\.|local\.|data\.)([^"]{8,})"', "Hardcoded secret value"),
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
            (r'(?:secret_access_key|aws_secret)\s*=\s*"([^"]+)"', "AWS Secret Access Key"),
        ]
        for pat, desc in patterns:
            for match in re.finditer(pat, content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-TF-009",
                    title=f"Potential hardcoded secret: {desc}",
                    description=f"Found potential hardcoded secret ({desc}). Secrets should be stored in a vault or environment variables.",
                    severity="CRITICAL",
                    category="secrets",
                    cloud_provider=cloud,
                    file_path=file_name,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Use AWS Secrets Manager, HashiCorp Vault, or environment variables instead of hardcoding secrets.",
                ))
        return results

    # === CHECK 10: Unencrypted EBS ===
    def _check_unencrypted_ebs(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r'resource\s+"aws_ebs_volume"\s+"(\w+)"', content):
            vol_name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if "encrypted" not in block or "encrypted = false" in block:
                line_num = content[:block_start].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-TF-010",
                    title=f"EBS volume '{vol_name}' not encrypted",
                    description="EBS volume does not have encryption enabled.",
                    severity="HIGH",
                    cloud_provider="aws",
                    resource_type="aws_ebs_volume",
                    resource_name=vol_name,
                    file_path=file_name,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Set encrypted = true in the aws_ebs_volume resource.",
                ))
        return results

    # === CHECK 11: Default VPC ===
    def _check_default_vpc(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r'resource\s+"aws_default_vpc"', content):
            line_num = content[:match.start()].count("\n") + 1
            results.append(ScanResult(
                rule_id="SD-TF-011",
                title="Default VPC is being used",
                description="Using the default VPC is not recommended. Create custom VPCs with proper network segmentation.",
                severity="MEDIUM",
                cloud_provider="aws",
                resource_type="aws_default_vpc",
                file_path=file_name,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="Create a custom VPC with proper CIDR blocks and subnets instead of using the default VPC.",
            ))
        return results

    # === CHECK 12: Open SSH (port 22) ===
    def _check_open_ssh(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        # Find ingress blocks in security group rules that combine port 22 with 0.0.0.0/0
        # Check both inline ingress blocks and aws_security_group_rule resources
        results.extend(self._check_open_port(content, lines, cloud, file_name, 22, "SSH", "SD-TF-012"))
        return results

    # === CHECK 13: Open RDP (port 3389) ===
    def _check_open_rdp(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        results.extend(self._check_open_port(content, lines, cloud, file_name, 3389, "RDP", "SD-TF-013"))
        return results

    def _check_open_port(self, content, lines, cloud, file_name, port, proto_name, rule_id) -> list[ScanResult]:
        """Check for a specific port open to the internet within the same resource/ingress block."""
        results = []
        seen_lines = set()
        # Pattern 1: aws_security_group_rule resource blocks
        for match in re.finditer(r'resource\s+"aws_security_group_rule"\s+"(\w+)"', content):
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            is_ingress = re.search(r'type\s*=\s*"ingress"', block)
            has_port = re.search(rf'(?:from_port|port)\s*=\s*{port}\b', block)
            has_open_cidr = "0.0.0.0/0" in block or "::/0" in block
            if is_ingress and has_port and has_open_cidr:
                line_num = content[:block_start].count("\n") + 1
                if line_num not in seen_lines:
                    seen_lines.add(line_num)
                    results.append(ScanResult(
                        rule_id=rule_id,
                        title=f"{proto_name} (port {port}) open to the internet",
                        description=f"Security group rule allows {proto_name} access from 0.0.0.0/0 or ::/0. {proto_name} should be restricted to known IPs.",
                        severity="HIGH",
                        cloud_provider=cloud,
                        resource_type="aws_security_group_rule",
                        file_path=file_name,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation=f"Restrict {proto_name} access to specific IPs or use a VPN/bastion host.",
                    ))
        # Pattern 2: inline ingress blocks inside aws_security_group
        for sg_match in re.finditer(r'resource\s+"aws_security_group"\s+"(\w+)"', content):
            sg_start = sg_match.start()
            sg_end = self._find_block_end(content, sg_start)
            sg_block = content[sg_start:sg_end]
            # Find ingress sub-blocks
            for ing_match in re.finditer(r'\bingress\s*\{', sg_block):
                ing_start = ing_match.start()
                ing_end = self._find_block_end(sg_block, ing_start)
                ing_block = sg_block[ing_start:ing_end]
                has_port = re.search(rf'(?:from_port|port)\s*=\s*{port}\b', ing_block)
                has_open_cidr = "0.0.0.0/0" in ing_block or "::/0" in ing_block
                if has_port and has_open_cidr:
                    abs_pos = sg_start + ing_start
                    line_num = content[:abs_pos].count("\n") + 1
                    if line_num not in seen_lines:
                        seen_lines.add(line_num)
                        results.append(ScanResult(
                            rule_id=rule_id,
                            title=f"{proto_name} (port {port}) open to the internet",
                            description=f"Security group allows {proto_name} access from 0.0.0.0/0 or ::/0. {proto_name} should be restricted to known IPs.",
                            severity="HIGH",
                            cloud_provider=cloud,
                            resource_type="aws_security_group",
                            file_path=file_name,
                            line_number=line_num,
                            code_snippet=self._get_snippet(lines, line_num),
                            remediation=f"Restrict {proto_name} access to specific IPs or use a VPN/bastion host.",
                        ))
        return results

    # === CHECK 14: Missing Tags ===
    def _check_missing_tags(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        resource_pattern = r'resource\s+"(\w+)"\s+"(\w+)"'
        taggable = {"aws_instance", "aws_s3_bucket", "aws_db_instance", "aws_vpc", "aws_subnet",
                     "aws_security_group", "aws_ebs_volume", "aws_lambda_function",
                     "google_compute_instance", "azurerm_virtual_machine"}
        for match in re.finditer(resource_pattern, content):
            resource_type = match.group(1)
            resource_name = match.group(2)
            if resource_type in taggable:
                block_start = match.start()
                block_end = self._find_block_end(content, block_start)
                block = content[block_start:block_end]
                if "tags" not in block and "labels" not in block:
                    line_num = content[:block_start].count("\n") + 1
                    results.append(ScanResult(
                        rule_id="SD-TF-014",
                        title=f"Resource '{resource_name}' missing tags",
                        description=f"Resource {resource_type}.{resource_name} does not have tags/labels. Tags are essential for cost allocation and governance.",
                        severity="LOW",
                        cloud_provider=cloud,
                        resource_type=resource_type,
                        resource_name=resource_name,
                        file_path=file_name,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation="Add tags block with at minimum: Environment, Owner, Project, and CostCenter tags.",
                    ))
        return results

    # === CHECK 15: Unencrypted SQS ===
    def _check_unencrypted_sqs(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r'resource\s+"aws_sqs_queue"\s+"(\w+)"', content):
            queue_name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if "kms_master_key_id" not in block and "sqs_managed_sse_enabled" not in block:
                line_num = content[:block_start].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-TF-015",
                    title=f"SQS queue '{queue_name}' not encrypted",
                    description="SQS queue does not have encryption enabled.",
                    severity="MEDIUM",
                    cloud_provider="aws",
                    resource_type="aws_sqs_queue",
                    resource_name=queue_name,
                    file_path=file_name,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Add kms_master_key_id or sqs_managed_sse_enabled = true.",
                ))
        return results

    # === CHECK 16: ECR Missing Image Scanning ===
    def _check_public_ecr(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r'resource\s+"aws_ecr_repository"\s+"(\w+)"', content):
            repo_name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if "image_scanning_configuration" not in block:
                line_num = content[:block_start].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-TF-016",
                    title=f"ECR repository '{repo_name}' missing image scanning on push",
                    description="ECR repository does not have image scanning on push enabled. Scanning container images helps detect known vulnerabilities.",
                    severity="MEDIUM",
                    cloud_provider="aws",
                    resource_type="aws_ecr_repository",
                    resource_name=repo_name,
                    file_path=file_name,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Add image_scanning_configuration { scan_on_push = true }.",
                ))
        return results

    # === CHECK 17: RDS Missing IAM Auth or SSL Enforcement ===
    def _check_missing_ssl_rds(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r'resource\s+"aws_db_instance"\s+"(\w+)"', content):
            db_name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            # SSL enforcement on RDS requires a parameter group with rds.force_ssl=1.
            # Also check for iam_database_authentication_enabled.
            # ca_cert_identifier alone does NOT enforce SSL — it only selects the CA cert.
            has_iam_auth = "iam_database_authentication_enabled" in block
            has_param_group = "parameter_group_name" in block
            if not has_iam_auth and not has_param_group:
                line_num = content[:block_start].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-TF-017",
                    title=f"RDS instance '{db_name}' missing IAM auth and custom parameter group",
                    description="RDS instance does not have IAM database authentication enabled and lacks a custom parameter group (needed to enforce SSL via rds.force_ssl=1). Both are security best practices.",
                    severity="MEDIUM",
                    cloud_provider="aws",
                    resource_type="aws_db_instance",
                    resource_name=db_name,
                    file_path=file_name,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Enable iam_database_authentication_enabled = true and use a parameter group with rds.force_ssl = 1.",
                ))
        return results

    # === CHECK 18: Unencrypted ElastiCache ===
    def _check_unencrypted_elasticache(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        # Check both aws_elasticache_cluster AND aws_elasticache_replication_group
        # Production ElastiCache typically uses replication groups
        for res_type in ["aws_elasticache_cluster", "aws_elasticache_replication_group"]:
            for match in re.finditer(rf'resource\s+"{res_type}"\s+"(\w+)"', content):
                cache_name = match.group(1)
                block_start = match.start()
                block_end = self._find_block_end(content, block_start)
                block = content[block_start:block_end]
                if "transit_encryption_enabled" not in block and "at_rest_encryption_enabled" not in block:
                    line_num = content[:block_start].count("\n") + 1
                    short_type = res_type.replace("aws_elasticache_", "")
                    results.append(ScanResult(
                        rule_id="SD-TF-018",
                        title=f"ElastiCache {short_type} '{cache_name}' not encrypted",
                        description=f"ElastiCache {short_type} does not have encryption at rest or in transit enabled.",
                        severity="HIGH",
                        cloud_provider="aws",
                        resource_type=res_type,
                        resource_name=cache_name,
                        file_path=file_name,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation="Set transit_encryption_enabled = true and at_rest_encryption_enabled = true.",
                    ))
        return results

    # === CHECK 19: Public Lambda ===
    def _check_public_lambda(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r'resource\s+"aws_lambda_permission"\s+"(\w+)"', content):
            perm_name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if '"*"' in block and "principal" in block:
                line_num = content[:block_start].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-TF-019",
                    title=f"Lambda permission '{perm_name}' allows wildcard principal",
                    description="Lambda function permission allows invocation from any AWS account.",
                    severity="HIGH",
                    cloud_provider="aws",
                    resource_type="aws_lambda_permission",
                    resource_name=perm_name,
                    file_path=file_name,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Restrict principal to specific AWS account IDs or service principals.",
                ))
        return results

    # === CHECK 20: Missing VPC Flow Logs ===
    def _check_missing_vpc_flow_logs(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        # Per-VPC check: each VPC should have a corresponding aws_flow_log
        # that references it via vpc_id = aws_vpc.<name>.id
        flow_log_targets = set()
        for fl_match in re.finditer(r'resource\s+"aws_flow_log"\s+"(\w+)"', content):
            fl_start = fl_match.start()
            fl_end = self._find_block_end(content, fl_start)
            fl_block = content[fl_start:fl_end]
            # Extract which VPC this flow log targets
            vpc_ref = re.search(r'vpc_id\s*=\s*aws_vpc\.(\w+)\.id', fl_block)
            if vpc_ref:
                flow_log_targets.add(vpc_ref.group(1))
            # Also handle var references or direct IDs (less precise but don't false-positive)
            if re.search(r'vpc_id\s*=\s*(?:var\.|local\.)', fl_block):
                flow_log_targets.add("__dynamic__")

        for match in re.finditer(r'resource\s+"aws_vpc"\s+"(\w+)"', content):
            vpc_name = match.group(1)
            if vpc_name not in flow_log_targets and "__dynamic__" not in flow_log_targets:
                line_num = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-TF-020",
                    title=f"VPC '{vpc_name}' missing flow logs",
                    description="VPC does not have a corresponding aws_flow_log resource. Flow logs are essential for network monitoring and forensics.",
                    severity="MEDIUM",
                    cloud_provider="aws",
                    resource_type="aws_vpc",
                    resource_name=vpc_name,
                    file_path=file_name,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Create aws_flow_log resource with vpc_id referencing this VPC.",
                ))
        return results

    # === CHECK 21: Unencrypted EFS ===
    def _check_unencrypted_efs(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r'resource\s+"aws_efs_file_system"\s+"(\w+)"', content):
            efs_name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if "encrypted" not in block or "encrypted = false" in block:
                line_num = content[:block_start].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-TF-021",
                    title=f"EFS file system '{efs_name}' not encrypted",
                    description="EFS file system does not have encryption enabled.",
                    severity="HIGH",
                    cloud_provider="aws",
                    resource_type="aws_efs_file_system",
                    resource_name=efs_name,
                    file_path=file_name,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Set encrypted = true in the aws_efs_file_system resource.",
                ))
        return results

    # === CHECK 22: Missing Backup ===
    def _check_missing_backup(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r'resource\s+"aws_db_instance"\s+"(\w+)"', content):
            db_name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if "backup_retention_period" not in block:
                line_num = content[:block_start].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-TF-022",
                    title=f"RDS instance '{db_name}' missing backup configuration",
                    description="RDS instance does not have backup_retention_period configured.",
                    severity="MEDIUM",
                    cloud_provider="aws",
                    resource_type="aws_db_instance",
                    resource_name=db_name,
                    file_path=file_name,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Add backup_retention_period = 7 (or more) to enable automated backups.",
                ))
        return results

    # === CHECK 23: Insecure TLS ===
    def _check_insecure_tls(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        pattern = r'(?:ssl_policy|minimum_tls_version)\s*=\s*"(TLS_1_0|TLS_1_1|TLSv1|TLSv1\.0|TLSv1\.1|ELBSecurityPolicy-2016-08)"'
        for match in re.finditer(pattern, content, re.IGNORECASE):
            tls_ver = match.group(1)
            line_num = content[:match.start()].count("\n") + 1
            results.append(ScanResult(
                rule_id="SD-TF-023",
                title=f"Insecure TLS version: {tls_ver}",
                description=f"Resource uses outdated TLS version {tls_ver}. Use TLS 1.2 or higher.",
                severity="HIGH",
                cloud_provider=cloud,
                file_path=file_name,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="Update to TLS 1.2 minimum (e.g., ELBSecurityPolicy-TLS-1-2-2017-01).",
            ))
        return results

    # === CHECK 24: Missing Monitoring ===
    def _check_missing_monitoring(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r'resource\s+"aws_db_instance"\s+"(\w+)"', content):
            db_name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if "monitoring_interval" not in block:
                line_num = content[:block_start].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-TF-024",
                    title=f"RDS instance '{db_name}' missing enhanced monitoring",
                    description="RDS instance does not have enhanced monitoring enabled.",
                    severity="LOW",
                    cloud_provider="aws",
                    resource_type="aws_db_instance",
                    resource_name=db_name,
                    file_path=file_name,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Add monitoring_interval = 60 and monitoring_role_arn to enable enhanced monitoring.",
                ))
        return results

    # === CHECK 25: Overly Broad CIDR ===
    def _check_overly_broad_cidr(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        pattern = r'cidr_blocks?\s*=\s*\[?\s*"(10\.0\.0\.0/8|172\.16\.0\.0/12|192\.168\.0\.0/16)"\s*\]?'
        for match in re.finditer(pattern, content):
            cidr = match.group(1)
            line_num = content[:match.start()].count("\n") + 1
            results.append(ScanResult(
                rule_id="SD-TF-025",
                title=f"Overly broad CIDR block: {cidr}",
                description=f"Using entire {cidr} range. Consider using more specific CIDR blocks for better network segmentation.",
                severity="LOW",
                cloud_provider=cloud,
                resource_type="aws_security_group",
                file_path=file_name,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="Use more specific CIDR blocks (e.g., /24 or /16 instead of /8).",
            ))
        return results

    # === CHECK 26: S3 Block Public Access ===
    def _check_s3_block_public_access(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        if "aws_s3_bucket" not in content:
            return results
        has_block_public = "aws_s3_bucket_public_access_block" in content
        for match in re.finditer(r'resource\s+"aws_s3_bucket"\s+"(\w+)"', content):
            bucket_name = match.group(1)
            if not has_block_public or bucket_name not in content[content.index("aws_s3_bucket_public_access_block"):] if has_block_public else True:
                # Check if a generic public access block exists referencing this bucket
                ref_pattern = rf'aws_s3_bucket\.{bucket_name}\.id'
                if has_block_public and re.search(ref_pattern, content):
                    continue
                ln = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-TF-026",
                    title=f"S3 bucket '{bucket_name}' missing Block Public Access",
                    description="S3 bucket does not have an aws_s3_bucket_public_access_block resource. This is the primary protection against accidental public exposure.",
                    severity="CRITICAL",
                    cloud_provider=cloud,
                    resource_type="aws_s3_bucket",
                    resource_name=bucket_name,
                    file_path=file_name,
                    line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Add aws_s3_bucket_public_access_block with block_public_acls=true, block_public_policy=true, ignore_public_acls=true, restrict_public_buckets=true.",
                ))
        return results

    # === CHECK 27: S3 Versioning ===
    def _check_s3_versioning(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        has_versioning_resource = "aws_s3_bucket_versioning" in content
        for match in re.finditer(r'resource\s+"aws_s3_bucket"\s+"(\w+)"', content):
            bucket_name = match.group(1)
            ref_pattern = rf'aws_s3_bucket\.{bucket_name}\.id'
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            inline_versioning = "versioning" in block and "Enabled" in block
            companion_versioning = has_versioning_resource and re.search(ref_pattern, content)
            if not inline_versioning and not companion_versioning:
                ln = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-TF-027",
                    title=f"S3 bucket '{bucket_name}' versioning not enabled",
                    description="S3 bucket does not have versioning enabled. Versioning protects against accidental deletion and enables object recovery.",
                    severity="MEDIUM",
                    cloud_provider=cloud,
                    resource_type="aws_s3_bucket",
                    resource_name=bucket_name,
                    file_path=file_name,
                    line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Add aws_s3_bucket_versioning resource with versioning_configuration { status = 'Enabled' }.",
                ))
        return results

    # === CHECK 28: CloudTrail ===
    def _check_cloudtrail(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        if "aws_cloudtrail" in content:
            for match in re.finditer(r'resource\s+"aws_cloudtrail"\s+"(\w+)"', content):
                block_start = match.start()
                block_end = self._find_block_end(content, block_start)
                block = content[block_start:block_end]
                if "is_multi_region_trail" not in block or "false" in block[block.index("is_multi_region_trail"):block.index("is_multi_region_trail")+50] if "is_multi_region_trail" in block else True:
                    ln = content[:match.start()].count("\n") + 1
                    results.append(ScanResult(
                        rule_id="SD-TF-028",
                        title="CloudTrail not configured as multi-region",
                        description="CloudTrail trail is not configured as multi-region. Events from other regions will not be captured.",
                        severity="HIGH",
                        cloud_provider=cloud,
                        resource_type="aws_cloudtrail",
                        file_path=file_name,
                        line_number=ln,
                        code_snippet=self._get_snippet(lines, ln),
                        remediation="Set is_multi_region_trail = true and enable_log_file_validation = true.",
                    ))
        return results

    # === CHECK 29: KMS Key Rotation ===
    def _check_kms_key_rotation(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r'resource\s+"aws_kms_key"\s+"(\w+)"', content):
            key_name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if "enable_key_rotation" not in block or re.search(r'enable_key_rotation\s*=\s*false', block):
                ln = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-TF-029",
                    title=f"KMS key '{key_name}' does not have automatic rotation enabled",
                    description="AWS KMS key does not have automatic key rotation enabled. Key rotation limits the blast radius of a compromised key.",
                    severity="HIGH",
                    cloud_provider=cloud,
                    resource_type="aws_kms_key",
                    resource_name=key_name,
                    file_path=file_name,
                    line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Set enable_key_rotation = true.",
                ))
        return results

    # === CHECK 30: EC2 IMDSv2 Enforcement ===
    def _check_ec2_imdsv2(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r'resource\s+"aws_instance"\s+"(\w+)"', content):
            instance_name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            has_imdsv2 = re.search(r'http_tokens\s*=\s*"required"', block)
            if not has_imdsv2:
                ln = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-TF-030",
                    title=f"EC2 instance '{instance_name}' not enforcing IMDSv2",
                    description="EC2 instance does not enforce Instance Metadata Service v2 (IMDSv2). IMDSv1 is vulnerable to SSRF credential theft attacks.",
                    severity="HIGH",
                    cloud_provider=cloud,
                    resource_type="aws_instance",
                    resource_name=instance_name,
                    file_path=file_name,
                    line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Add metadata_options { http_tokens = \"required\", http_endpoint = \"enabled\" }.",
                ))
        return results

    # === CHECK 31: RDS Deletion Protection ===
    def _check_rds_deletion_protection(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r'resource\s+"aws_db_instance"\s+"(\w+)"', content):
            db_name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if "deletion_protection" not in block or re.search(r'deletion_protection\s*=\s*false', block):
                ln = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-TF-031",
                    title=f"RDS instance '{db_name}' missing deletion protection",
                    description="RDS instance does not have deletion protection enabled. Accidental deletion can cause permanent data loss.",
                    severity="HIGH",
                    cloud_provider=cloud,
                    resource_type="aws_db_instance",
                    resource_name=db_name,
                    file_path=file_name,
                    line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Set deletion_protection = true.",
                ))
        return results

    # === CHECK 32: RDS Multi-AZ ===
    def _check_rds_multi_az(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r'resource\s+"aws_db_instance"\s+"(\w+)"', content):
            db_name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if "multi_az" not in block or re.search(r'multi_az\s*=\s*false', block):
                ln = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-TF-032",
                    title=f"RDS instance '{db_name}' not configured for Multi-AZ",
                    description="RDS instance is not deployed in Multi-AZ configuration. Single-AZ deployments are vulnerable to AZ-level failures.",
                    severity="MEDIUM",
                    cloud_provider=cloud,
                    resource_type="aws_db_instance",
                    resource_name=db_name,
                    file_path=file_name,
                    line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Set multi_az = true for production databases.",
                ))
        return results

    # === CHECK 33: GuardDuty Detector ===
    def _check_guardduty(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        if "aws_guardduty_detector" in content:
            for match in re.finditer(r'resource\s+"aws_guardduty_detector"\s+"(\w+)"', content):
                block_start = match.start()
                block_end = self._find_block_end(content, block_start)
                block = content[block_start:block_end]
                if re.search(r'enable\s*=\s*false', block):
                    ln = content[:match.start()].count("\n") + 1
                    results.append(ScanResult(
                        rule_id="SD-TF-033",
                        title="GuardDuty detector is disabled",
                        description="GuardDuty detector is explicitly disabled. GuardDuty provides intelligent threat detection for AWS accounts.",
                        severity="HIGH",
                        cloud_provider=cloud,
                        resource_type="aws_guardduty_detector",
                        file_path=file_name,
                        line_number=ln,
                        code_snippet=self._get_snippet(lines, ln),
                        remediation="Set enable = true on the GuardDuty detector.",
                    ))
        return results

    # === CHECK 34: SNS Topic Encryption ===
    def _check_sns_encryption(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r'resource\s+"aws_sns_topic"\s+"(\w+)"', content):
            topic_name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if "kms_master_key_id" not in block:
                ln = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-TF-034",
                    title=f"SNS topic '{topic_name}' not encrypted with KMS",
                    description="SNS topic does not have server-side encryption configured. Messages in transit and at rest should be encrypted.",
                    severity="MEDIUM",
                    cloud_provider=cloud,
                    resource_type="aws_sns_topic",
                    resource_name=topic_name,
                    file_path=file_name,
                    line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Set kms_master_key_id to an AWS KMS key ARN.",
                ))
        return results

    # === CHECK 35: DynamoDB Encryption ===
    def _check_dynamodb_encryption(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r'resource\s+"aws_dynamodb_table"\s+"(\w+)"', content):
            table_name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if "server_side_encryption" not in block:
                ln = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-TF-035",
                    title=f"DynamoDB table '{table_name}' using default encryption",
                    description="DynamoDB table does not configure customer-managed KMS encryption. Default AWS-owned keys provide less control over key management.",
                    severity="MEDIUM",
                    cloud_provider=cloud,
                    resource_type="aws_dynamodb_table",
                    resource_name=table_name,
                    file_path=file_name,
                    line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Add server_side_encryption { enabled = true, kms_key_arn = aws_kms_key.example.arn }.",
                ))
        return results

    # === CHECK 36: CloudWatch Log Group Encryption ===
    def _check_cloudwatch_log_encryption(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r'resource\s+"aws_cloudwatch_log_group"\s+"(\w+)"', content):
            lg_name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if "kms_key_id" not in block:
                ln = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-TF-036",
                    title=f"CloudWatch log group '{lg_name}' not encrypted with KMS",
                    description="CloudWatch log group does not have KMS encryption. Logs may contain sensitive data and should be encrypted with a customer-managed key.",
                    severity="MEDIUM",
                    cloud_provider=cloud,
                    resource_type="aws_cloudwatch_log_group",
                    resource_name=lg_name,
                    file_path=file_name,
                    line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Set kms_key_id to a KMS key ARN.",
                ))
        return results

    # === CHECK 37: Lambda VPC Configuration ===
    def _check_lambda_vpc(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r'resource\s+"aws_lambda_function"\s+"(\w+)"', content):
            fn_name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if "vpc_config" not in block:
                ln = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-TF-037",
                    title=f"Lambda function '{fn_name}' not deployed in VPC",
                    description="Lambda function is not configured with VPC settings. Functions accessing private resources should run inside a VPC for network isolation.",
                    severity="LOW",
                    cloud_provider=cloud,
                    resource_type="aws_lambda_function",
                    resource_name=fn_name,
                    file_path=file_name,
                    line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Add vpc_config block with subnet_ids and security_group_ids.",
                ))
        return results

    # === CHECK 38: Secrets Manager Rotation ===
    def _check_secrets_manager_rotation(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r'resource\s+"aws_secretsmanager_secret"\s+"(\w+)"', content):
            secret_name = match.group(1)
            ref_pattern = rf'aws_secretsmanager_secret\.{secret_name}'
            has_rotation = any(ref_pattern in content[r.start():] for r in re.finditer(r'resource\s+"aws_secretsmanager_secret_rotation"', content))
            if not has_rotation:
                ln = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-TF-038",
                    title=f"Secrets Manager secret '{secret_name}' has no automatic rotation",
                    description="Secret does not have automatic rotation configured. Stale secrets increase the risk of credential compromise.",
                    severity="MEDIUM",
                    cloud_provider=cloud,
                    resource_type="aws_secretsmanager_secret",
                    resource_name=secret_name,
                    file_path=file_name,
                    line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Add aws_secretsmanager_secret_rotation resource with rotation_lambda_arn and rotation_rules.",
                ))
        return results

    # === CHECK 39: EKS Cluster Encryption ===
    def _check_eks_encryption(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r'resource\s+"aws_eks_cluster"\s+"(\w+)"', content):
            cluster_name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if "encryption_config" not in block:
                ln = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-TF-039",
                    title=f"EKS cluster '{cluster_name}' missing envelope encryption for secrets",
                    description="EKS cluster does not have encryption_config for Kubernetes secrets. Secrets stored in etcd should be encrypted at rest with a KMS key.",
                    severity="HIGH",
                    cloud_provider=cloud,
                    resource_type="aws_eks_cluster",
                    resource_name=cluster_name,
                    file_path=file_name,
                    line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Add encryption_config { provider { key_arn = aws_kms_key.eks.arn } resources = [\"secrets\"] }.",
                ))
        return results

    # === CHECK 40: EKS Public Endpoint ===
    def _check_eks_public_endpoint(self, content, parsed, lines, cloud, file_name) -> list[ScanResult]:
        results = []
        for match in re.finditer(r'resource\s+"aws_eks_cluster"\s+"(\w+)"', content):
            cluster_name = match.group(1)
            block_start = match.start()
            block_end = self._find_block_end(content, block_start)
            block = content[block_start:block_end]
            if re.search(r'endpoint_public_access\s*=\s*true', block):
                ln = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-TF-040",
                    title=f"EKS cluster '{cluster_name}' has public API endpoint enabled",
                    description="EKS cluster API server is accessible from the internet. This exposes the Kubernetes API to potential attacks.",
                    severity="HIGH",
                    cloud_provider=cloud,
                    resource_type="aws_eks_cluster",
                    resource_name=cluster_name,
                    file_path=file_name,
                    line_number=ln,
                    code_snippet=self._get_snippet(lines, ln),
                    remediation="Set endpoint_public_access = false and endpoint_private_access = true in vpc_config.",
                ))
        return results

    def _find_block_end(self, content: str, start: int) -> int:
        """Find the end of a Terraform block starting at given position."""
        depth = 0
        i = start
        while i < len(content):
            if content[i] == "{":
                depth += 1
            elif content[i] == "}":
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        return len(content)
