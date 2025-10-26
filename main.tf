########################################
# Phase 1-3: Core Networking + Logging
########################################

# --- VPCs ---
resource "aws_vpc" "mgmt_vpc" {
  cidr_block           = "10.0.0.0/24"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "${var.name_prefix}-mgmt-vpc" }
}

resource "aws_vpc" "fw_vpc" {
  cidr_block           = "10.0.1.0/24"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "${var.name_prefix}-fw-vpc" }
}

resource "aws_vpc" "app_vpc" {
  cidr_block           = "10.0.2.0/24"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "${var.name_prefix}-app-vpc" }
}

# --- Subnets (1 per AZ for brevity) ---
resource "aws_subnet" "fw_trust_1"  { vpc_id = aws_vpc.fw_vpc.id cidr_block = "10.0.1.0/28" availability_zone = "us-west-2a" }
resource "aws_subnet" "fw_trust_2"  { vpc_id = aws_vpc.fw_vpc.id cidr_block = "10.0.1.16/28" availability_zone = "us-west-2b" }
resource "aws_subnet" "fw_mgmt_1"   { vpc_id = aws_vpc.fw_vpc.id cidr_block = "10.0.1.32/28" availability_zone = "us-west-2a" }
resource "aws_subnet" "fw_untrust_1"{ vpc_id = aws_vpc.fw_vpc.id cidr_block = "10.0.1.48/28" availability_zone = "us-west-2a" }
resource "aws_subnet" "fw_untrust_2"{ vpc_id = aws_vpc.fw_vpc.id cidr_block = "10.0.1.64/28" availability_zone = "us-west-2b" }

# --- S3 Bucket for Logs ---
resource "aws_s3_bucket" "logs" {
  bucket        = var.log_s3_bucket_name
  force_destroy = false
  tags = {
    Name        = "${var.name_prefix}-logs"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# --- Outputs ---
output "vpc_ids" {
  value = {
    mgmt = aws_vpc.mgmt_vpc.id
    fw   = aws_vpc.fw_vpc.id
    app  = aws_vpc.app_vpc.id
  }
}

output "subnet_ids_fw" {
  value = {
    trust_1  = aws_subnet.fw_trust_1.id
    trust_2  = aws_subnet.fw_trust_2.id
    mgmt_1   = aws_subnet.fw_mgmt_1.id
    untrust1 = aws_subnet.fw_untrust_1.id
    untrust2 = aws_subnet.fw_untrust_2.id
  }
}
