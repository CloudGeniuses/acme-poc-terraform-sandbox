########################################
# AWS Centralized Inspection – Complete Terraform (Phases 1–6)
########################################

terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

########################################
# VARIABLES (aligned with workspace)
########################################

variable "admin_cidr" {
  type        = string
  description = "IP range allowed to access mgmt (HTTPS/SSH)."
  default     = "0.0.0.0/0"
}

variable "bootstrap_s3_bucket" {
  type        = string
  description = "Bootstrap S3 bucket."
  default     = ""
}

variable "bootstrap_s3_prefix" {
  type        = string
  description = "Bootstrap S3 prefix."
  default     = ""
}

variable "enable_s3_bootstrap" {
  type        = bool
  default     = false
}

variable "environment" {
  type        = string
  description = "Environment indicator (sandbox/dev/prod)."
  default     = "sandbox"
}

variable "fw_ami_id" {
  type        = string
  description = "Palo Alto PAYG AMI ID for your region (us-west-2)."
  default     = ""
}

variable "fw_bootstrap_user_data" {
  type        = string
  default     = null
}

variable "fw_desired_capacity" {
  type        = number
  default     = 1
}

variable "fw_enable_flow_logs" {
  type        = bool
  default     = true
}

variable "fw_instance_type" {
  type        = string
  default     = "c5.xlarge"
}

variable "fw_key_name" {
  type        = string
  default     = ""
}

variable "log_s3_bucket_name" {
  type        = string
  description = "Existing S3 bucket for flow logs."
  default     = null
}

variable "name_prefix" {
  type        = string
  default     = "acme-sandbox"
}

variable "project_name" {
  type        = string
  default     = "acme-sandbox"
}

variable "tgw_id" {
  type        = string
  default     = ""
}

variable "region" {
  type    = string
  default = "us-west-2"
}

########################################
# PROVIDER (default tags)
########################################

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      Name        = var.name_prefix
    }
  }
}

########################################
# LOCALS
########################################

locals {
  effective_ami = var.fw_ami_id
  az1           = "${var.region}a"
  az2           = "${var.region}b"

  computed_user_data = (
    var.fw_bootstrap_user_data != null
    ? var.fw_bootstrap_user_data
    : (
        var.enable_s3_bootstrap && var.bootstrap_s3_bucket != ""
        ? <<-EOT
          vmseries-bootstrap-aws-s3bucket=${var.bootstrap_s3_bucket}
          vmseries-bootstrap-aws-s3prefix=${var.bootstrap_s3_prefix}
          EOT
        : null
      )
  )
}

########################################
# PHASE 1 & 2: NETWORK + VPCs
########################################

resource "aws_vpc" "fw_vpc" {
  cidr_block           = "10.20.0.0/24"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.name_prefix}-fw-vpc" }
}

resource "aws_internet_gateway" "fw_igw" {
  vpc_id = aws_vpc.fw_vpc.id
  tags   = { Name = "${var.name_prefix}-fw-igw" }
}

resource "aws_subnet" "fw_mgmt" {
  vpc_id                  = aws_vpc.fw_vpc.id
  cidr_block              = "10.20.0.0/28"
  availability_zone       = local.az1
  map_public_ip_on_launch = true
  tags                    = { Name = "${var.name_prefix}-fw-mgmt" }
}

resource "aws_subnet" "fw_untrust" {
  vpc_id                  = aws_vpc.fw_vpc.id
  cidr_block              = "10.20.0.32/28"
  availability_zone       = local.az1
  map_public_ip_on_launch = true
  tags                    = { Name = "${var.name_prefix}-fw-untrust" }
}

resource "aws_subnet" "fw_trust" {
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.20.0.64/28"
  availability_zone = local.az1
  tags              = { Name = "${var.name_prefix}-fw-trust" }
}

########################################
# SECURITY GROUPS
########################################

resource "aws_security_group" "fw_mgmt_sg" {
  name   = "${var.name_prefix}-fw-mgmt-sg"
  vpc_id = aws_vpc.fw_vpc.id

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
}

resource "aws_security_group" "fw_trust_sg" {
  name   = "${var.name_prefix}-fw-trust-sg"
  vpc_id = aws_vpc.fw_vpc.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

########################################
# IAM ROLE FOR SSM & BOOTSTRAP
########################################

data "aws_iam_policy_document" "assume_ec2" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "fw_role" {
  name               = "${var.name_prefix}-fw-role"
  assume_role_policy = data.aws_iam_policy_document.assume_ec2.json
}

resource "aws_iam_role_policy_attachment" "fw_ssm_attach" {
  role       = aws_iam_role.fw_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "fw_profile" {
  name = "${var.name_prefix}-fw-profile"
  role = aws_iam_role.fw_role.name
}

########################################
# FIREWALL INSTANCE
########################################

resource "aws_network_interface" "fw_mgmt" {
  subnet_id       = aws_subnet.fw_mgmt.id
  security_groups = [aws_security_group.fw_mgmt_sg.id]
  tags            = { Name = "${var.name_prefix}-fw-mgmt-eni" }
}

resource "aws_network_interface" "fw_untrust" {
  subnet_id         = aws_subnet.fw_untrust.id
  security_groups   = [aws_security_group.fw_trust_sg.id]
  source_dest_check = false
  tags              = { Name = "${var.name_prefix}-fw-untrust-eni" }
}

resource "aws_network_interface" "fw_trust" {
  subnet_id         = aws_subnet.fw_trust.id
  security_groups   = [aws_security_group.fw_trust_sg.id]
  source_dest_check = false
  tags              = { Name = "${var.name_prefix}-fw-trust-eni" }
}

resource "aws_eip" "fw_eip" {
  domain            = "vpc"
  network_interface = aws_network_interface.fw_untrust.id
  tags              = { Name = "${var.name_prefix}-fw-eip" }
}

resource "aws_instance" "fw_vm" {
  ami                  = var.fw_ami_id
  instance_type        = var.fw_instance_type
  key_name             = var.fw_key_name
  iam_instance_profile = aws_iam_instance_profile.fw_profile.name
  user_data            = local.computed_user_data

  network_interface {
    device_index         = 0
    network_interface_id = aws_network_interface.fw_mgmt.id
  }

  tags = { Name = "${var.name_prefix}-fw-vm" }
}

resource "aws_network_interface_attachment" "fw_untrust_attach" {
  instance_id          = aws_instance.fw_vm.id
  network_interface_id = aws_network_interface.fw_untrust.id
  device_index         = 1
}

resource "aws_network_interface_attachment" "fw_trust_attach" {
  instance_id          = aws_instance.fw_vm.id
  network_interface_id = aws_network_interface.fw_trust.id
  device_index         = 2
}

########################################
# FLOW LOGS (optional)
########################################

resource "random_id" "suffix" {
  byte_length = 3
}

resource "aws_s3_bucket" "logs" {
  count         = var.fw_enable_flow_logs ? 1 : 0
  bucket        = coalesce(var.log_s3_bucket_name, "${var.name_prefix}-logs-${random_id.suffix.hex}")
  force_destroy = true
  tags          = { Name = "${var.name_prefix}-flow-logs" }
}

resource "aws_flow_log" "fw_vpc_logs" {
  count                = var.fw_enable_flow_logs ? 1 : 0
  log_destination      = aws_s3_bucket.logs[0].arn
  log_destination_type = "s3"
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.fw_vpc.id
  tags                 = { Name = "${var.name_prefix}-flowlog" }
}

########################################
# OUTPUTS
########################################

output "fw_public_ip" {
  value = aws_eip.fw_eip.public_ip
}

output "fw_private_ip" {
  value = aws_instance.fw_vm.private_ip
}

output "fw_vpc_id" {
  value = aws_vpc.fw_vpc.id
}
