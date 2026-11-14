import re
import yaml
import json
from app.services.scanners.base import BaseScanner, ScanResult


class _CFLoader(yaml.SafeLoader):
    """YAML loader that handles CloudFormation intrinsic functions."""
    pass


# Register all CF intrinsic function tags
for tag in ["!Ref", "!Sub", "!GetAtt", "!Join", "!Select", "!Split",
            "!FindInMap", "!GetAZs", "!ImportValue", "!Condition",
            "!If", "!Not", "!And", "!Or", "!Equals", "!Base64",
            "!Cidr", "!Transform"]:
    _CFLoader.add_constructor(tag, lambda loader, node: loader.construct_scalar(node)
                              if isinstance(node, yaml.ScalarNode)
                              else loader.construct_sequence(node)
                              if isinstance(node, yaml.SequenceNode)
                              else loader.construct_mapping(node))


class CloudFormationScanner(BaseScanner):
    """CloudFormation (YAML/JSON) security scanner with 40 enterprise checks."""

    def detect_cloud_provider(self, content: str) -> str:
        return "aws"

    def scan(self, content: str, file_name: str = "") -> list[ScanResult]:
        results = []
        template = self._parse_template(content)
        if not template or not isinstance(template, dict):
            return results

        resources = template.get("Resources", {})
        if not resources or not isinstance(resources, dict):
            return results

        lines = content.split("\n")

        for resource_name, resource_def in resources.items():
            resource_type = resource_def.get("Type", "")
            properties = resource_def.get("Properties", {})
            line_num = self._find_resource_line(lines, resource_name)

            checks = [
                (self._check_public_sg, "AWS::EC2::SecurityGroup"),
                (self._check_unencrypted_s3, "AWS::S3::Bucket"),
                (self._check_public_s3, "AWS::S3::Bucket"),
                (self._check_unencrypted_rds, "AWS::RDS::DBInstance"),
                (self._check_public_rds, "AWS::RDS::DBInstance"),
                (self._check_wildcard_iam, "AWS::IAM::Policy"),
                (self._check_wildcard_iam, "AWS::IAM::Role"),
                (self._check_missing_s3_logging, "AWS::S3::Bucket"),
                (self._check_unencrypted_ebs, "AWS::EC2::Volume"),
                (self._check_open_ssh_sg, "AWS::EC2::SecurityGroup"),
                (self._check_open_rdp_sg, "AWS::EC2::SecurityGroup"),
                (self._check_missing_tags, None),
                (self._check_unencrypted_sqs, "AWS::SQS::Queue"),
                (self._check_missing_ssl_rds, "AWS::RDS::DBInstance"),
                (self._check_unencrypted_elasticache, "AWS::ElastiCache::CacheCluster"),
                (self._check_missing_backup_rds, "AWS::RDS::DBInstance"),
                (self._check_insecure_tls, "AWS::ElasticLoadBalancingV2::Listener"),
                (self._check_missing_monitoring_rds, "AWS::RDS::DBInstance"),
                (self._check_public_subnet, "AWS::EC2::Subnet"),
                (self._check_unencrypted_sns, "AWS::SNS::Topic"),
                (self._check_missing_cloudtrail, None),
                (self._check_unencrypted_dynamodb, "AWS::DynamoDB::Table"),
                (self._check_missing_waf, "AWS::ElasticLoadBalancingV2::LoadBalancer"),
                (self._check_unrestricted_api_gw, "AWS::ApiGateway::Method"),
                (self._check_missing_vpc_endpoint, None),
                # Enterprise checks 26-40
                (self._check_s3_block_public_access, "AWS::S3::Bucket"),
                (self._check_s3_versioning, "AWS::S3::Bucket"),
                (self._check_kms_rotation, "AWS::KMS::Key"),
                (self._check_ec2_imdsv2, "AWS::EC2::LaunchTemplate"),
                (self._check_rds_deletion_protection, "AWS::RDS::DBInstance"),
                (self._check_rds_multi_az, "AWS::RDS::DBInstance"),
                (self._check_guardduty_detector, None),
                (self._check_lambda_vpc, "AWS::Lambda::Function"),
                (self._check_cloudwatch_log_encryption, "AWS::Logs::LogGroup"),
                (self._check_secretsmanager_rotation, "AWS::SecretsManager::Secret"),
                (self._check_ecs_privileged, "AWS::ECS::TaskDefinition"),
                (self._check_eks_logging, "AWS::EKS::Cluster"),
                (self._check_eks_public_endpoint, "AWS::EKS::Cluster"),
                (self._check_s3_lifecycle, "AWS::S3::Bucket"),
                (self._check_config_recorder, None),
            ]

            for check_fn, target_type in checks:
                if target_type is None or resource_type == target_type:
                    results.extend(check_fn(
                        resource_name, resource_type, properties, template, lines, line_num, file_name
                    ))

        # Global checks
        results.extend(self._check_hardcoded_secrets_global(content, lines, file_name))

        return results

    def _parse_template(self, content: str) -> dict:
        try:
            result = yaml.load(content, Loader=_CFLoader)
            return result if isinstance(result, dict) else {}
        except yaml.YAMLError:
            try:
                result = json.loads(content)
                return result if isinstance(result, dict) else {}
            except (json.JSONDecodeError, TypeError):
                return {}

    def _find_resource_line(self, lines: list[str], resource_name: str) -> int:
        for i, line in enumerate(lines, 1):
            if resource_name in line:
                return i
        return 0

    def _get_snippet(self, lines: list[str], line_num: int, context: int = 3) -> str:
        if line_num <= 0:
            return ""
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        return "\n".join(lines[start:end])

    # CHECK 1: Public Security Group
    def _check_public_sg(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        results = []
        for ingress in props.get("SecurityGroupIngress", []):
            cidr = ingress.get("CidrIp", "")
            if cidr == "0.0.0.0/0":
                results.append(ScanResult(
                    rule_id="SD-CF-001",
                    title=f"Security group '{name}' allows ingress from 0.0.0.0/0",
                    description="Security group allows traffic from any IP address.",
                    severity="CRITICAL",
                    cloud_provider="aws",
                    resource_type=rtype,
                    resource_name=name,
                    file_path=file_name,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Restrict CidrIp to specific IP ranges.",
                ))
        return results

    # CHECK 2: Unencrypted S3
    def _check_unencrypted_s3(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        encryption = props.get("BucketEncryption")
        if not encryption:
            return [ScanResult(
                rule_id="SD-CF-002",
                title=f"S3 bucket '{name}' missing encryption",
                description="S3 bucket does not have BucketEncryption configured.",
                severity="HIGH",
                cloud_provider="aws",
                resource_type=rtype,
                resource_name=name,
                file_path=file_name,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="Add BucketEncryption with ServerSideEncryptionConfiguration.",
            )]
        return []

    # CHECK 3: Public S3
    def _check_public_s3(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        access = props.get("AccessControl", "")
        if access in ("PublicRead", "PublicReadWrite"):
            return [ScanResult(
                rule_id="SD-CF-003",
                title=f"S3 bucket '{name}' has public access: {access}",
                description=f"S3 bucket configured with '{access}' access control.",
                severity="CRITICAL",
                cloud_provider="aws",
                resource_type=rtype,
                resource_name=name,
                file_path=file_name,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="Set AccessControl to 'Private'.",
            )]
        return []

    # CHECK 4: Unencrypted RDS
    def _check_unencrypted_rds(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        if not props.get("StorageEncrypted", False):
            return [ScanResult(
                rule_id="SD-CF-004",
                title=f"RDS instance '{name}' storage not encrypted",
                description="RDS instance does not have StorageEncrypted enabled.",
                severity="HIGH",
                cloud_provider="aws",
                resource_type=rtype,
                resource_name=name,
                file_path=file_name,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="Set StorageEncrypted to true.",
            )]
        return []

    # CHECK 5: Public RDS
    def _check_public_rds(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        if props.get("PubliclyAccessible", False):
            return [ScanResult(
                rule_id="SD-CF-005",
                title=f"RDS instance '{name}' is publicly accessible",
                description="RDS instance has PubliclyAccessible set to true.",
                severity="CRITICAL",
                cloud_provider="aws",
                resource_type=rtype,
                resource_name=name,
                file_path=file_name,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="Set PubliclyAccessible to false.",
            )]
        return []

    # CHECK 6-7: Wildcard IAM
    def _check_wildcard_iam(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        results = []
        policies = props.get("Policies", props.get("PolicyDocument", {}))
        if isinstance(policies, list):
            for policy in policies:
                doc = policy.get("PolicyDocument", {})
                self._check_policy_doc(doc, name, rtype, results, lines, line_num, file_name)
        elif isinstance(policies, dict):
            self._check_policy_doc(policies, name, rtype, results, lines, line_num, file_name)
        return results

    def _check_policy_doc(self, doc, name, rtype, results, lines, line_num, file_name):
        for stmt in doc.get("Statement", []):
            if stmt.get("Effect") == "Allow":
                actions = stmt.get("Action", [])
                resources = stmt.get("Resource", [])
                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]
                if "*" in actions:
                    results.append(ScanResult(
                        rule_id="SD-CF-007",
                        title=f"IAM '{name}' uses wildcard actions",
                        description="IAM policy allows all actions (*).",
                        severity="CRITICAL",
                        cloud_provider="aws",
                        resource_type=rtype,
                        resource_name=name,
                        file_path=file_name,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation="Replace * with specific actions.",
                    ))
                if "*" in resources:
                    results.append(ScanResult(
                        rule_id="SD-CF-006",
                        title=f"IAM '{name}' allows access to all resources",
                        description="IAM policy grants permissions on all resources (*).",
                        severity="HIGH",
                        cloud_provider="aws",
                        resource_type=rtype,
                        resource_name=name,
                        file_path=file_name,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation="Restrict Resource to specific ARNs.",
                    ))

    # CHECK 8: Missing S3 Logging
    def _check_missing_s3_logging(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        if not props.get("LoggingConfiguration"):
            return [ScanResult(
                rule_id="SD-CF-008",
                title=f"S3 bucket '{name}' missing access logging",
                description="S3 bucket does not have LoggingConfiguration.",
                severity="MEDIUM",
                cloud_provider="aws",
                resource_type=rtype,
                resource_name=name,
                file_path=file_name,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="Add LoggingConfiguration with DestinationBucketName.",
            )]
        return []

    # CHECK 9: Unencrypted EBS
    def _check_unencrypted_ebs(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        if not props.get("Encrypted", False):
            return [ScanResult(
                rule_id="SD-CF-010",
                title=f"EBS volume '{name}' not encrypted",
                description="EBS volume does not have Encrypted set to true.",
                severity="HIGH",
                cloud_provider="aws",
                resource_type=rtype,
                resource_name=name,
                file_path=file_name,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="Set Encrypted to true.",
            )]
        return []

    # CHECK 10: Open SSH
    def _check_open_ssh_sg(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        results = []
        for ingress in props.get("SecurityGroupIngress", []):
            if ingress.get("FromPort") == 22 and ingress.get("CidrIp") == "0.0.0.0/0":
                results.append(ScanResult(
                    rule_id="SD-CF-012",
                    title=f"Security group '{name}' allows SSH from 0.0.0.0/0",
                    description="SSH port 22 is open to the internet.",
                    severity="HIGH",
                    cloud_provider="aws",
                    resource_type=rtype,
                    resource_name=name,
                    file_path=file_name,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Restrict SSH access to specific IPs.",
                ))
        return results

    # CHECK 11: Open RDP
    def _check_open_rdp_sg(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        results = []
        for ingress in props.get("SecurityGroupIngress", []):
            if ingress.get("FromPort") == 3389 and ingress.get("CidrIp") == "0.0.0.0/0":
                results.append(ScanResult(
                    rule_id="SD-CF-013",
                    title=f"Security group '{name}' allows RDP from 0.0.0.0/0",
                    description="RDP port 3389 is open to the internet.",
                    severity="HIGH",
                    cloud_provider="aws",
                    resource_type=rtype,
                    resource_name=name,
                    file_path=file_name,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Restrict RDP access to specific IPs.",
                ))
        return results

    # CHECK 12: Missing Tags
    def _check_missing_tags(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        taggable = {"AWS::EC2::Instance", "AWS::S3::Bucket", "AWS::RDS::DBInstance",
                     "AWS::EC2::VPC", "AWS::EC2::SecurityGroup"}
        if rtype in taggable and not props.get("Tags"):
            return [ScanResult(
                rule_id="SD-CF-014",
                title=f"Resource '{name}' missing tags",
                description=f"{rtype} does not have Tags configured.",
                severity="LOW",
                cloud_provider="aws",
                resource_type=rtype,
                resource_name=name,
                file_path=file_name,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="Add Tags with Environment, Owner, and Project.",
            )]
        return []

    # CHECK 13: Unencrypted SQS
    def _check_unencrypted_sqs(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        if not props.get("KmsMasterKeyId") and not props.get("SqsManagedSseEnabled"):
            return [ScanResult(
                rule_id="SD-CF-015",
                title=f"SQS queue '{name}' not encrypted",
                description="SQS queue does not have encryption configured.",
                severity="MEDIUM",
                cloud_provider="aws",
                resource_type=rtype,
                resource_name=name,
                file_path=file_name,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="Add KmsMasterKeyId or SqsManagedSseEnabled.",
            )]
        return []

    # CHECK 14: Missing SSL for RDS
    def _check_missing_ssl_rds(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        if not props.get("CACertificateIdentifier"):
            return [ScanResult(
                rule_id="SD-CF-017",
                title=f"RDS '{name}' may not enforce SSL",
                description="RDS instance does not specify CACertificateIdentifier.",
                severity="MEDIUM",
                cloud_provider="aws",
                resource_type=rtype,
                resource_name=name,
                file_path=file_name,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="Add CACertificateIdentifier property.",
            )]
        return []

    # CHECK 15: Unencrypted ElastiCache
    def _check_unencrypted_elasticache(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        if not props.get("TransitEncryptionEnabled") and not props.get("AtRestEncryptionEnabled"):
            return [ScanResult(
                rule_id="SD-CF-018",
                title=f"ElastiCache '{name}' not encrypted",
                description="ElastiCache cluster missing encryption settings.",
                severity="HIGH",
                cloud_provider="aws",
                resource_type=rtype,
                resource_name=name,
                file_path=file_name,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="Enable TransitEncryptionEnabled and AtRestEncryptionEnabled.",
            )]
        return []

    # CHECK 16: Missing Backup
    def _check_missing_backup_rds(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        if not props.get("BackupRetentionPeriod"):
            return [ScanResult(
                rule_id="SD-CF-022",
                title=f"RDS '{name}' missing backup configuration",
                description="RDS instance does not have BackupRetentionPeriod set.",
                severity="MEDIUM",
                cloud_provider="aws",
                resource_type=rtype,
                resource_name=name,
                file_path=file_name,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="Set BackupRetentionPeriod to 7 or more.",
            )]
        return []

    # CHECK 17: Insecure TLS
    def _check_insecure_tls(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        ssl_policy = props.get("SslPolicy", "")
        if ssl_policy and ("2016" in ssl_policy or "TLS-1-0" in ssl_policy or "TLS-1-1" in ssl_policy):
            return [ScanResult(
                rule_id="SD-CF-023",
                title=f"Listener '{name}' uses insecure TLS: {ssl_policy}",
                description="Load balancer listener uses outdated SSL policy.",
                severity="HIGH",
                cloud_provider="aws",
                resource_type=rtype,
                resource_name=name,
                file_path=file_name,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="Use ELBSecurityPolicy-TLS-1-2-2017-01 or newer.",
            )]
        return []

    # CHECK 18: Missing RDS Monitoring
    def _check_missing_monitoring_rds(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        if not props.get("MonitoringInterval"):
            return [ScanResult(
                rule_id="SD-CF-024",
                title=f"RDS '{name}' missing enhanced monitoring",
                description="RDS instance does not have MonitoringInterval set.",
                severity="LOW",
                cloud_provider="aws",
                resource_type=rtype,
                resource_name=name,
                file_path=file_name,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="Set MonitoringInterval to 60.",
            )]
        return []

    # CHECK 19: Public Subnet
    def _check_public_subnet(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        if props.get("MapPublicIpOnLaunch", False):
            return [ScanResult(
                rule_id="SD-CF-019",
                title=f"Subnet '{name}' auto-assigns public IPs",
                description="Subnet has MapPublicIpOnLaunch enabled.",
                severity="MEDIUM",
                cloud_provider="aws",
                resource_type=rtype,
                resource_name=name,
                file_path=file_name,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="Set MapPublicIpOnLaunch to false for private subnets.",
            )]
        return []

    # CHECK 20: Unencrypted SNS
    def _check_unencrypted_sns(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        if not props.get("KmsMasterKeyId"):
            return [ScanResult(
                rule_id="SD-CF-020",
                title=f"SNS topic '{name}' not encrypted",
                description="SNS topic does not have KMS encryption.",
                severity="MEDIUM",
                cloud_provider="aws",
                resource_type=rtype,
                resource_name=name,
                file_path=file_name,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="Add KmsMasterKeyId property.",
            )]
        return []

    # CHECK 21: Missing CloudTrail (template-level check)
    def _check_missing_cloudtrail(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        resources = template.get("Resources", {})
        has_trail = any(r.get("Type") == "AWS::CloudTrail::Trail" for r in resources.values())
        # This is a template-level check — fire once per template (on the first resource),
        # not only on EC2 instances. Templates with compute, databases, or IAM resources
        # should have CloudTrail for audit logging.
        audit_worthy_types = [
            "AWS::EC2::Instance", "AWS::RDS::DBInstance", "AWS::Lambda::Function",
            "AWS::IAM::Role", "AWS::IAM::User", "AWS::S3::Bucket",
            "AWS::ECS::Service", "AWS::EKS::Cluster",
        ]
        if not has_trail and rtype in audit_worthy_types:
            return [ScanResult(
                rule_id="SD-CF-021",
                title="Template missing CloudTrail configuration",
                description="No CloudTrail trail found in template containing audit-worthy resources. CloudTrail provides audit logging for API activity.",
                severity="LOW",
                cloud_provider="aws",
                file_path=file_name,
                line_number=line_num,
                code_snippet="",
                remediation="Add AWS::CloudTrail::Trail resource or ensure CloudTrail is configured at the organization/account level.",
            )]
        return []

    # CHECK 22: Unencrypted DynamoDB
    def _check_unencrypted_dynamodb(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        sse = props.get("SSESpecification", {})
        if not sse.get("SSEEnabled", False):
            return [ScanResult(
                rule_id="SD-CF-025",
                title=f"DynamoDB table '{name}' not using CMK encryption",
                description="DynamoDB table does not have SSESpecification enabled.",
                severity="MEDIUM",
                cloud_provider="aws",
                resource_type=rtype,
                resource_name=name,
                file_path=file_name,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="Add SSESpecification with SSEEnabled: true.",
            )]
        return []

    # CHECK 23: Missing WAF
    def _check_missing_waf(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        resources = template.get("Resources", {})
        has_waf = any("WAF" in r.get("Type", "") for r in resources.values())
        if not has_waf:
            return [ScanResult(
                rule_id="SD-CF-026",
                title=f"Load balancer '{name}' has no WAF association",
                description="ALB does not have a WAF Web ACL associated.",
                severity="MEDIUM",
                cloud_provider="aws",
                resource_type=rtype,
                resource_name=name,
                file_path=file_name,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="Associate an AWS::WAFv2::WebACL with the load balancer.",
            )]
        return []

    # CHECK 24: Unrestricted API Gateway
    def _check_unrestricted_api_gw(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        if props.get("AuthorizationType") == "NONE":
            return [ScanResult(
                rule_id="SD-CF-027",
                title=f"API Gateway method '{name}' has no authorization",
                description="API Gateway method has AuthorizationType set to NONE.",
                severity="HIGH",
                cloud_provider="aws",
                resource_type=rtype,
                resource_name=name,
                file_path=file_name,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="Set AuthorizationType to AWS_IAM, COGNITO_USER_POOLS, or CUSTOM.",
            )]
        return []

    # CHECK 25: Missing VPC Endpoint (global check)
    def _check_missing_vpc_endpoint(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        resources = template.get("Resources", {})
        has_vpc = any(r.get("Type") == "AWS::EC2::VPC" for r in resources.values())
        has_endpoint = any(r.get("Type") == "AWS::EC2::VPCEndpoint" for r in resources.values())
        if has_vpc and not has_endpoint and rtype == "AWS::EC2::VPC":
            return [ScanResult(
                rule_id="SD-CF-028",
                title="VPC missing VPC Endpoints for AWS services",
                description="VPC does not use VPC Endpoints, so traffic to AWS services traverses the internet.",
                severity="LOW",
                cloud_provider="aws",
                resource_type="AWS::EC2::VPC",
                resource_name=name,
                file_path=file_name,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="Add AWS::EC2::VPCEndpoint for S3, DynamoDB, and other frequently used services.",
            )]
        return []

    # === CHECK 26: S3 Block Public Access ===
    def _check_s3_block_public_access(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        if rtype != "AWS::S3::Bucket":
            return []
        pac = props.get("PublicAccessBlockConfiguration", {})
        if not pac or not all(pac.get(k, False) for k in ["BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"]):
            return [ScanResult(
                rule_id="SD-CF-029", title=f"S3 bucket '{name}' missing full public access block",
                description="S3 bucket does not have all four public access block settings enabled. Misconfigured ACLs or policies could expose data.",
                severity="HIGH", cloud_provider="aws", resource_type=rtype, resource_name=name,
                file_path=file_name, line_number=line_num, code_snippet=self._get_snippet(lines, line_num),
                remediation="Add PublicAccessBlockConfiguration with all four settings set to true.",
            )]
        return []

    # === CHECK 27: S3 Versioning ===
    def _check_s3_versioning(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        if rtype != "AWS::S3::Bucket":
            return []
        vc = props.get("VersioningConfiguration", {})
        if not vc or vc.get("Status") != "Enabled":
            return [ScanResult(
                rule_id="SD-CF-030", title=f"S3 bucket '{name}' versioning not enabled",
                description="S3 bucket versioning is not enabled. Data loss from accidental deletion or overwrite cannot be recovered.",
                severity="MEDIUM", cloud_provider="aws", resource_type=rtype, resource_name=name,
                file_path=file_name, line_number=line_num, code_snippet=self._get_snippet(lines, line_num),
                remediation="Add VersioningConfiguration with Status: Enabled.",
            )]
        return []

    # === CHECK 28: KMS Key Rotation ===
    def _check_kms_rotation(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        if rtype != "AWS::KMS::Key":
            return []
        if not props.get("EnableKeyRotation", False):
            return [ScanResult(
                rule_id="SD-CF-031", title=f"KMS key '{name}' automatic rotation not enabled",
                description="KMS key does not have automatic key rotation enabled. Long-lived encryption keys increase the blast radius of key compromise.",
                severity="MEDIUM", cloud_provider="aws", resource_type=rtype, resource_name=name,
                file_path=file_name, line_number=line_num, code_snippet=self._get_snippet(lines, line_num),
                remediation="Set EnableKeyRotation: true.",
            )]
        return []

    # === CHECK 29: EC2 IMDSv2 ===
    def _check_ec2_imdsv2(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        if rtype != "AWS::EC2::LaunchTemplate":
            return []
        lt_data = props.get("LaunchTemplateData", {})
        mo = lt_data.get("MetadataOptions", {})
        if mo.get("HttpTokens") != "required":
            return [ScanResult(
                rule_id="SD-CF-032", title=f"Launch template '{name}' does not enforce IMDSv2",
                description="EC2 launch template does not require IMDSv2. IMDSv1 is vulnerable to SSRF-based credential theft.",
                severity="HIGH", cloud_provider="aws", resource_type=rtype, resource_name=name,
                file_path=file_name, line_number=line_num, code_snippet=self._get_snippet(lines, line_num),
                remediation="Set MetadataOptions.HttpTokens: required to enforce IMDSv2.",
            )]
        return []

    # === CHECK 30: RDS Deletion Protection ===
    def _check_rds_deletion_protection(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        if rtype != "AWS::RDS::DBInstance":
            return []
        if not props.get("DeletionProtection", False):
            return [ScanResult(
                rule_id="SD-CF-033", title=f"RDS instance '{name}' missing deletion protection",
                description="RDS instance does not have deletion protection enabled. The database can be accidentally deleted.",
                severity="HIGH", cloud_provider="aws", resource_type=rtype, resource_name=name,
                file_path=file_name, line_number=line_num, code_snippet=self._get_snippet(lines, line_num),
                remediation="Set DeletionProtection: true.",
            )]
        return []

    # === CHECK 31: RDS Multi-AZ ===
    def _check_rds_multi_az(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        if rtype != "AWS::RDS::DBInstance":
            return []
        if not props.get("MultiAZ", False):
            return [ScanResult(
                rule_id="SD-CF-034", title=f"RDS instance '{name}' not multi-AZ",
                description="RDS instance is not configured for Multi-AZ deployment. A single AZ failure will cause downtime.",
                severity="MEDIUM", cloud_provider="aws", resource_type=rtype, resource_name=name,
                file_path=file_name, line_number=line_num, code_snippet=self._get_snippet(lines, line_num),
                remediation="Set MultiAZ: true for production databases.",
            )]
        return []

    # === CHECK 32: GuardDuty Detector ===
    def _check_guardduty_detector(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        resources = template.get("Resources", {})
        has_gd = any(r.get("Type") == "AWS::GuardDuty::Detector" for r in resources.values() if isinstance(r, dict))
        if not has_gd and rtype == list(resources.keys())[0] if resources else False:
            return [ScanResult(
                rule_id="SD-CF-035", title="No GuardDuty detector in template",
                description="Template does not include a GuardDuty detector. Threat detection and continuous security monitoring are absent.",
                severity="MEDIUM", cloud_provider="aws", resource_type="AWS::GuardDuty::Detector",
                resource_name="N/A", file_path=file_name, line_number=1,
                code_snippet=self._get_snippet(lines, 1),
                remediation="Add AWS::GuardDuty::Detector with Enable: true.",
            )]
        return []

    # === CHECK 33: Lambda VPC ===
    def _check_lambda_vpc(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        if rtype != "AWS::Lambda::Function":
            return []
        vpc_config = props.get("VpcConfig", {})
        if not vpc_config or not vpc_config.get("SubnetIds"):
            return [ScanResult(
                rule_id="SD-CF-036", title=f"Lambda function '{name}' not in VPC",
                description="Lambda function is not deployed in a VPC. It cannot access VPC-only resources and has less network control.",
                severity="LOW", cloud_provider="aws", resource_type=rtype, resource_name=name,
                file_path=file_name, line_number=line_num, code_snippet=self._get_snippet(lines, line_num),
                remediation="Add VpcConfig with SubnetIds and SecurityGroupIds.",
            )]
        return []

    # === CHECK 34: CloudWatch Log Encryption ===
    def _check_cloudwatch_log_encryption(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        if rtype != "AWS::Logs::LogGroup":
            return []
        if not props.get("KmsKeyId"):
            return [ScanResult(
                rule_id="SD-CF-037", title=f"CloudWatch log group '{name}' not encrypted with CMK",
                description="CloudWatch Logs group uses default encryption. Sensitive log data is not protected by a customer-managed key.",
                severity="MEDIUM", cloud_provider="aws", resource_type=rtype, resource_name=name,
                file_path=file_name, line_number=line_num, code_snippet=self._get_snippet(lines, line_num),
                remediation="Set KmsKeyId to a KMS key ARN.",
            )]
        return []

    # === CHECK 35: Secrets Manager Rotation ===
    def _check_secretsmanager_rotation(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        if rtype != "AWS::SecretsManager::Secret":
            return []
        resources = template.get("Resources", {})
        has_schedule = any(
            r.get("Type") == "AWS::SecretsManager::RotationSchedule"
            and str(r.get("Properties", {}).get("SecretId", "")) in (name, f"!Ref {name}")
            for r in resources.values() if isinstance(r, dict)
        )
        if not has_schedule:
            return [ScanResult(
                rule_id="SD-CF-038", title=f"Secret '{name}' has no rotation schedule",
                description="Secrets Manager secret has no rotation schedule configured. Long-lived secrets are a security risk.",
                severity="MEDIUM", cloud_provider="aws", resource_type=rtype, resource_name=name,
                file_path=file_name, line_number=line_num, code_snippet=self._get_snippet(lines, line_num),
                remediation="Add AWS::SecretsManager::RotationSchedule referencing this secret.",
            )]
        return []

    # === CHECK 36: ECS Privileged Containers ===
    def _check_ecs_privileged(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        if rtype != "AWS::ECS::TaskDefinition":
            return []
        results = []
        for cd in props.get("ContainerDefinitions", []):
            if isinstance(cd, dict) and cd.get("Privileged", False):
                cname = cd.get("Name", "unknown")
                results.append(ScanResult(
                    rule_id="SD-CF-039", title=f"ECS container '{cname}' in task '{name}' runs privileged",
                    description="ECS container runs in privileged mode granting full access to the host OS. Container escape attacks become trivial.",
                    severity="CRITICAL", cloud_provider="aws", resource_type=rtype, resource_name=name,
                    file_path=file_name, line_number=line_num, code_snippet=self._get_snippet(lines, line_num),
                    remediation="Set Privileged: false and use specific Linux capabilities instead.",
                ))
        return results

    # === CHECK 37: EKS Logging ===
    def _check_eks_logging(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        if rtype != "AWS::EKS::Cluster":
            return []
        logging = props.get("Logging", {})
        cluster_logging = logging.get("ClusterLogging", {})
        enabled_types = cluster_logging.get("EnabledTypes", [])
        if not enabled_types:
            return [ScanResult(
                rule_id="SD-CF-040", title=f"EKS cluster '{name}' control plane logging disabled",
                description="EKS cluster does not have control plane logging enabled. API server, audit, and authenticator logs are not captured.",
                severity="MEDIUM", cloud_provider="aws", resource_type=rtype, resource_name=name,
                file_path=file_name, line_number=line_num, code_snippet=self._get_snippet(lines, line_num),
                remediation="Enable Logging.ClusterLogging.EnabledTypes for api, audit, authenticator, controllerManager, scheduler.",
            )]
        return []

    # === CHECK 38: EKS Public Endpoint ===
    def _check_eks_public_endpoint(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        if rtype != "AWS::EKS::Cluster":
            return []
        rc = props.get("ResourcesVpcConfig", {})
        if rc.get("EndpointPublicAccess", True) is True:
            return [ScanResult(
                rule_id="SD-CF-041", title=f"EKS cluster '{name}' has public API endpoint",
                description="EKS cluster API server is publicly accessible. The Kubernetes API surface is exposed to the internet.",
                severity="HIGH", cloud_provider="aws", resource_type=rtype, resource_name=name,
                file_path=file_name, line_number=line_num, code_snippet=self._get_snippet(lines, line_num),
                remediation="Set EndpointPublicAccess: false and use EndpointPrivateAccess: true with VPN/Direct Connect.",
            )]
        return []

    # === CHECK 39: S3 Lifecycle Policy ===
    def _check_s3_lifecycle(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        if rtype != "AWS::S3::Bucket":
            return []
        lc = props.get("LifecycleConfiguration", {})
        if not lc or not lc.get("Rules"):
            return [ScanResult(
                rule_id="SD-CF-042", title=f"S3 bucket '{name}' has no lifecycle policy",
                description="S3 bucket has no lifecycle rules. Old objects accumulate indefinitely, increasing storage costs and attack surface.",
                severity="LOW", cloud_provider="aws", resource_type=rtype, resource_name=name,
                file_path=file_name, line_number=line_num, code_snippet=self._get_snippet(lines, line_num),
                remediation="Add LifecycleConfiguration with rules for transition and expiration.",
            )]
        return []

    # === CHECK 40: AWS Config Recorder ===
    def _check_config_recorder(self, name, rtype, props, template, lines, line_num, file_name) -> list[ScanResult]:
        resources = template.get("Resources", {})
        has_config = any(r.get("Type") == "AWS::Config::ConfigurationRecorder" for r in resources.values() if isinstance(r, dict))
        if not has_config and rtype == list(resources.keys())[0] if resources else False:
            return [ScanResult(
                rule_id="SD-CF-043", title="No AWS Config recorder in template",
                description="Template does not include an AWS Config recorder. Resource configuration changes are not being tracked for compliance.",
                severity="LOW", cloud_provider="aws", resource_type="AWS::Config::ConfigurationRecorder",
                resource_name="N/A", file_path=file_name, line_number=1,
                code_snippet=self._get_snippet(lines, 1),
                remediation="Add AWS::Config::ConfigurationRecorder with recording enabled for all resource types.",
            )]
        return []

    # Hardcoded secrets check (applied globally to content)
    def _check_hardcoded_secrets_global(self, content, lines, file_name) -> list[ScanResult]:
        results = []
        patterns = [
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
            (r'(?:password|secret|api_key)\s*[:=]\s*["\']([^"\']{8,})["\']', "Hardcoded secret"),
            (r'(?:Password|Secret)\s*:\s*([^\s\n!][^\n]{7,})', "Hardcoded YAML value"),
        ]
        for pat, desc in patterns:
            for match in re.finditer(pat, content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                results.append(ScanResult(
                    rule_id="SD-CF-009",
                    title=f"Potential hardcoded secret: {desc}",
                    description=f"Found potential {desc} in CloudFormation template.",
                    severity="CRITICAL",
                    category="secrets",
                    cloud_provider="aws",
                    file_path=file_name,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Use AWS Secrets Manager or SSM Parameter Store.",
                ))
        return results
