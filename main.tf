########################################
# CloudGenius – AWS TGW + GWLB + Palo Alto VM-Series
# Phases 1–5  (Production-ready, Terraform Cloud compatible)
########################################

terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

########################################
# Provider
########################################
provider "aws" {
  region = var.region
}

########################################
# Variables
########################################
variable "region" {
  type    = string
  default = "us-west-2"
}

variable "project_name" {
  type        = string
  description = "Project identifier"
}

variable "environment" {
  type        = string
  description = "Environment name (sandbox/dev/prod)"
}

variable "name_prefix" {
  type        = string
  description = "Prefix for consistent naming"
}

variable "admin_cidr" {
  description = "Public IP CIDR allowed for SSH/GUI access"
  type        = string
}

variable "fw_ami_id" {
  description = "AMI ID for Palo Alto VM-Series"
  type        = string
}

variable "fw_instance_type" {
  description = "Firewall instance type"
  type        = string
  default     = "c5.xlarge"
}

variable "fw_key_name" {
  description = "SSH key pair name"
  type        = string
}

variable "fw_enable_flow_logs" {
  type    = bool
  default = true
}

variable "bootstrap_s3_bucket" {
  description = "S3 bucket for bootstrap files"
  type        = string
}

variable "bootstrap_s3_prefix" {
  type    = string
  default = "bootstrap"
}

variable "log_s3_bucket_name" {
  description = "S3 bucket for logs"
  type        = string
}

variable "enable_s3_bootstrap" {
  type    = bool
  default = true
}

variable "tgw_id" {
  type    = string
  default = ""
}

variable "fw_bootstrap_user_data" {
  description = "Optional base64 user data string for firewall bootstrapping"
  type        = string
  default     = null
}

variable "fw_desired_capacity" {
  description = "Number of firewall instances per AZ"
  type        = number
  default     = 1
}

########################################
# Phase 1–3: VPCs + Subnets + SGs
########################################
resource "aws_vpc" "mgmt_vpc" {
  cidr_block           = "10.0.0.0/24"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "${var.name_prefix}-mgmt-vpc"
  }
}

resource "aws_vpc" "fw_vpc" {
  cidr_block           = "10.0.1.0/24"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "${var.name_prefix}-fw-vpc"
  }
}

resource "aws_vpc" "app_vpc" {
  cidr_block           = "10.0.2.0/24"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "${var.name_prefix}-app-vpc"
  }
}

# Subnets (Firewall VPC)
resource "aws_subnet" "fw_mgmt_1" {
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.0.1.0/28"
  availability_zone = "us-west-2a"
}

resource "aws_subnet" "fw_trust_1" {
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.0.1.16/28"
  availability_zone = "us-west-2a"
}

resource "aws_subnet" "fw_trust_2" {
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.0.1.32/28"
  availability_zone = "us-west-2b"
}

resource "aws_subnet" "fw_untrust_1" {
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.0.1.48/28"
  availability_zone = "us-west-2a"
}

resource "aws_subnet" "fw_untrust_2" {
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.0.1.64/28"
  availability_zone = "us-west-2b"
}

########################################
# Security Groups
########################################
resource "aws_security_group" "fw_mgmt_sg" {
  name        = "${var.name_prefix}-fw-mgmt-sg"
  description = "Mgmt access via HTTPS/SSH"
  vpc_id      = aws_vpc.fw_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.name_prefix}-fw-mgmt-sg"
  }
}

########################################
# Phase 4: IAM + Palo Alto VM-Series
########################################
# IAM Role for SSM
resource "aws_iam_role" "fw_ssm_role" {
  name               = "${var.name_prefix}-fw-ssm-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "ec2.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "fw_ssm_attach" {
  role       = aws_iam_role.fw_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "fw_ssm_profile" {
  name = "${var.name_prefix}-fw-ssm-profile"
  role = aws_iam_role.fw_ssm_role.name
}

# Local mappings
locals {
  fw_pairs = [
    { mgmt = aws_subnet.fw_mgmt_1.id, untrust = aws_subnet.fw_untrust_1.id, trust = aws_subnet.fw_trust_1.id },
    { mgmt = aws_subnet.fw_mgmt_1.id, untrust = aws_subnet.fw_untrust_2.id, trust = aws_subnet.fw_trust_2.id }
  ]

  fw_user_data = var.enable_s3_bootstrap ? "vmseries-bootstrap-aws-s3bucket=${var.bootstrap_s3_bucket}" : ""
}

# ENIs
resource "aws_network_interface" "fw_mgmt" {
  count           = length(local.fw_pairs)
  subnet_id       = local.fw_pairs[count.index].mgmt
  security_groups = [aws_security_group.fw_mgmt_sg.id]
  tags = {
    Name = "${var.name_prefix}-fw-mgmt-${count.index}"
  }
}

resource "aws_network_interface" "fw_untrust" {
  count             = length(local.fw_pairs)
  subnet_id         = local.fw_pairs[count.index].untrust
  source_dest_check = false
  tags = {
    Name = "${var.name_prefix}-fw-untrust-${count.index}"
  }
}

resource "aws_eip" "fw_eip" {
  count             = length(local.fw_pairs)
  domain            = "vpc"
  network_interface = aws_network_interface.fw_untrust[count.index].id
  tags = {
    Name = "${var.name_prefix}-fw-eip-${count.index}"
  }
}

resource "aws_network_interface" "fw_trust" {
  count             = length(local.fw_pairs)
  subnet_id         = local.fw_pairs[count.index].trust
  source_dest_check = false
  tags = {
    Name = "${var.name_prefix}-fw-trust-${count.index}"
  }
}

# Firewall Instances
resource "aws_instance" "fw_vm" {
  count                  = length(local.fw_pairs)
  ami                    = var.fw_ami_id
  instance_type          = var.fw_instance_type
  key_name               = var.fw_key_name
  subnet_id              = local.fw_pairs[count.index].mgmt
  vpc_security_group_ids = [aws_security_group.fw_mgmt_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.fw_ssm_profile.name
  user_data_base64       = base64encode(local.fw_user_data)

  tags = {
    Name        = "${var.name_prefix}-fw-${count.index}"
    Project     = var.project_name
    Environment = var.environment
  }
}

# Attach dataplane ENIs
resource "aws_network_interface_attachment" "fw_untrust_attach" {
  count                = length(local.fw_pairs)
  instance_id          = aws_instance.fw_vm[count.index].id
  network_interface_id = aws_network_interface.fw_untrust[count.index].id
  device_index         = 1
}

resource "aws_network_interface_attachment" "fw_trust_attach" {
  count                = length(local.fw_pairs)
  instance_id          = aws_instance.fw_vm[count.index].id
  network_interface_id = aws_network_interface.fw_trust[count.index].id
  device_index         = 2
}

########################################
# Phase 5: Logging + Monitoring
########################################
resource "aws_s3_bucket" "logs" {
  bucket         = var.log_s3_bucket_name
  force_destroy  = true
  tags = {
    Name = "${var.name_prefix}-logs"
  }
}

resource "aws_flow_log" "fw_vpc_logs" {
  count                = var.fw_enable_flow_logs ? 1 : 0
  log_destination      = aws_s3_bucket.logs.arn
  log_destination_type = "s3"
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.fw_vpc.id
  tags = {
    Name = "${var.name_prefix}-fw-flowlogs"
  }
}

########################################
# Outputs
########################################
output "firewall_public_ips" {
  value = aws_eip.fw_eip[*].public_ip
}

output "firewall_private_ips" {
  value = aws_instance.fw_vm[*].private_ip
}

output "fw_vpc_id" {
  value = aws_vpc.fw_vpc.id
}
