provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Web security group"

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
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  acl    = "public-read"
}

resource "aws_db_instance" "main" {
  identifier     = "main-db"
  engine         = "mysql"
  instance_class = "db.t3.micro"
  username       = "admin"
  password       = "SuperSecret123!"
  publicly_accessible = true
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size             = 100
}

resource "aws_default_vpc" "default" {
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_sqs_queue" "messages" {
  name = "my-queue"
}

resource "aws_ecr_repository" "app" {
  name = "my-app"
}

resource "aws_elasticache_cluster" "cache" {
  cluster_id      = "my-cache"
  engine          = "redis"
  node_type       = "cache.t3.micro"
  num_cache_nodes = 1
}

resource "aws_efs_file_system" "data" {
  creation_token = "my-efs"
}

resource "aws_iam_policy" "admin" {
  name = "admin-policy"
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

variable "secret_key" {
  default = "AKIAIOSFODNN7EXAMPLE"
}
