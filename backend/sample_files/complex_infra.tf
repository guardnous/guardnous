provider "aws" {
  region = "us-east-1"
}

# === NETWORKING ===
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_default_vpc" "default" {}

resource "aws_security_group" "web_tier" {
  name        = "web-tier-sg"
  description = "Public-facing web tier"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "db_tier" {
  name        = "db-tier-sg"
  description = "Database tier"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# === STORAGE ===
resource "aws_s3_bucket" "application_assets" {
  bucket = "corp-app-assets-prod"
  acl    = "public-read-write"
}

resource "aws_s3_bucket" "customer_data" {
  bucket = "corp-customer-data"
  acl    = "public-read"
}

resource "aws_s3_bucket" "audit_logs" {
  bucket = "corp-audit-logs"
  acl    = "private"
  # No versioning, no encryption, no logging
}

resource "aws_ebs_volume" "app_data" {
  availability_zone = "us-east-1a"
  size              = 500
  # No encryption
}

resource "aws_ebs_volume" "db_backup" {
  availability_zone = "us-east-1b"
  size              = 1000
  # No encryption
}

resource "aws_efs_file_system" "shared_data" {
  creation_token = "shared-nfs"
  # No encryption at rest
}

# === DATABASES ===
resource "aws_db_instance" "production" {
  identifier           = "prod-mysql"
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.r6g.xlarge"
  allocated_storage    = 500
  username             = "admin"
  password             = "Pr0duct10n_P@ssw0rd!"
  publicly_accessible  = true
  skip_final_snapshot  = true
  storage_encrypted    = false
  multi_az             = false
  backup_retention_period = 0
}

resource "aws_db_instance" "analytics" {
  identifier           = "analytics-postgres"
  engine               = "postgres"
  instance_class       = "db.r6g.large"
  username             = "analytics_admin"
  password             = "An@lyt1cs_Secr3t"
  publicly_accessible  = true
  storage_encrypted    = false
}

resource "aws_elasticache_cluster" "sessions" {
  cluster_id      = "prod-sessions"
  engine          = "redis"
  node_type       = "cache.r6g.large"
  num_cache_nodes = 1
  # No encryption in transit, no auth
}

resource "aws_elasticache_cluster" "cache" {
  cluster_id      = "prod-cache"
  engine          = "redis"
  node_type       = "cache.m6g.large"
  num_cache_nodes = 3
  # No encryption
}

# === MESSAGING ===
resource "aws_sqs_queue" "orders" {
  name = "production-orders"
  # No encryption, no DLQ
}

resource "aws_sqs_queue" "notifications" {
  name = "production-notifications"
  # No encryption
}

resource "aws_sns_topic" "alerts" {
  name = "system-alerts"
  # No encryption
}

# === COMPUTE ===
resource "aws_ecr_repository" "api_service" {
  name                 = "api-service"
  image_tag_mutability = "MUTABLE"
  # No image scanning
}

resource "aws_ecr_repository" "worker_service" {
  name                 = "worker-service"
  image_tag_mutability = "MUTABLE"
}

# === IAM ===
resource "aws_iam_policy" "god_mode" {
  name = "god-mode-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*"
      }
    ]
  })
}

resource "aws_iam_policy" "s3_wildcard" {
  name = "s3-wildcard"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect": "Allow",
        "Action": "s3:*",
        "Resource": "*"
      }
    ]
  })
}

resource "aws_iam_role" "lambda_exec" {
  name = "lambda-exec-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

# === SECRETS / HARDCODED CREDENTIALS ===
variable "aws_access_key" {
  default = "AKIAIOSFODNN7EXAMPLE"
}

variable "aws_secret_key" {
  default = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

variable "database_url" {
  default = "postgresql://admin:SuperSecret123!@prod-db.internal:5432/production"
}

variable "stripe_key" {
  default = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
}

variable "github_token" {
  default = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
}

# === LOGGING (MISSING) ===
resource "aws_cloudwatch_log_group" "app" {
  name              = "/app/production"
  retention_in_days = 7
  # Short retention, no encryption
}

resource "aws_cloudtrail" "audit" {
  name           = "audit-trail"
  s3_bucket_name = aws_s3_bucket.audit_logs.id
  # No log file validation, no encryption
}
