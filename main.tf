########################################
# AWS Centralized Inspection – Phases 1–6
# Aligned to TF Cloud workspace variables
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
# VARIABLES (match your workspace)
########################################

variable "region" {
  type    = string
  default = "us-west-2"
}

variable "admin_cidr" {
  type    = string
  default = "0.0.0.0/0"
}

variable "bootstrap_s3_bucket" {
  type    = string
  default = ""
}

variable "bootstrap_s3_prefix" {
  type    = string
  default = ""
}

variable "enable_s3_bootstrap" {
  type    = bool
  default = false
}

variable "environment" {
  type    = string
  default = "sandbox"
}

variable "name_prefix" {
  type    = string
  default = "acme-sandbox"
}

variable "project_name" {
  type    = string
  default = "acme-sandbox"
}

# Prefer fw_ami_id; pan_ami_id kept for compatibility
variable "fw_ami_id" {
  type        = string
  default     = ""
  description = "Palo Alto VM-Series AMI (BYOL/PAYG) for your region"
}

variable "pan_ami_id" {
  type        = string
  default     = ""
  description = "Legacy alias; used only if fw_ami_id not provided"
}

variable "fw_instance_type" {
  type    = string
  default = "c5.xlarge"
}

variable "fw_key_name" {
  type        = string
  default     = ""
  description = "EC2 key pair for SSH (optional)"
}

variable "fw_bootstrap_user_data" {
  type    = string
  default = null
}

variable "fw_desired_capacity" {
  type    = number
  default = 1
}

variable "fw_enable_flow_logs" {
  type    = bool
  default = true
}

variable "log_s3_bucket_name" {
  type    = string
  default = null
}

variable "tgw_id" {
  type        = string
  default     = ""
  description = "Optional: existing TGW ID (unused in this POC file)"
}

########################################
# PROVIDER
########################################

provider "aws" {
  region = var.region
}

########################################
# LOCALS
########################################

# Choose AMI: fw_ami_id then pan_ami_id
# Enforced again with lifecycle precondition on the instance.
locals {
  effective_ami = length(var.fw_ami_id) > 0 ? var.fw_ami_id : var.pan_ami_id

  # Build user_data from explicit value or S3 bootstrap toggle
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

  # Light “sanitization” without regex: only replace spaces/underscores, lowercase.
  # (If user leaves it empty, we create a unique bucket below.)
  sanitized_logs_bucket = (
    var.log_s3_bucket_name != null && var.log_s3_bucket_name != ""
    ? lower(replace(replace(var.log_s3_bucket_name, " ", "-"), "_", "-"))
    : null
  )
}

########################################
# NETWORK – FW VPC (Mgmt/Untrust/Trust)
########################################

resource "aws_vpc" "fw_vpc" {
  cidr_block           = "10.20.0.0/24"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name        = "${var.name_prefix}-fw-vpc"
    Environment = var.environment
    Project     = var.project_name
  }
}

resource "aws_internet_gateway" "fw_igw" {
  vpc_id = aws_vpc.fw_vpc.id
  tags = {
    Name = "${var.name_prefix}-fw-igw"
  }
}

resource "aws_subnet" "fw_mgmt_1" {
  vpc_id                  = aws_vpc.fw_vpc.id
  cidr_block              = "10.20.0.0/28"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.name_prefix}-fw-mgmt-1"
  }
}

resource "aws_subnet" "fw_untrust_1" {
  vpc_id                  = aws_vpc.fw_vpc.id
  cidr_block              = "10.20.0.32/28"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.name_prefix}-fw-untrust-1"
  }
}

resource "aws_subnet" "fw_trust_1" {
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.20.0.64/28"
  availability_zone = "${var.region}a"

  tags = {
    Name = "${var.name_prefix}-fw-trust-1"
  }
}

# Route tables
resource "aws_route_table" "mgmt_rt" {
  vpc_id = aws_vpc.fw_vpc.id

  tags = {
    Name = "${var.name_prefix}-fw-mgmt-rt"
  }
}

resource "aws_route" "mgmt_default" {
  route_table_id         = aws_route_table.mgmt_rt.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.fw_igw.id
}

resource "aws_route_table_association" "mgmt_assoc" {
  route_table_id = aws_route_table.mgmt_rt.id
  subnet_id      = aws_subnet.fw_mgmt_1.id
}

resource "aws_route_table" "untrust_rt" {
  vpc_id = aws_vpc.fw_vpc.id

  tags = {
    Name = "${var.name_prefix}-fw-untrust-rt"
  }
}

resource "aws_route" "untrust_default" {
  route_table_id         = aws_route_table.untrust_rt.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.fw_igw.id
}

resource "aws_route_table_association" "untrust_assoc" {
  route_table_id = aws_route_table.untrust_rt.id
  subnet_id      = aws_subnet.fw_untrust_1.id
}

resource "aws_route_table" "trust_rt" {
  vpc_id = aws_vpc.fw_vpc.id

  tags = {
    Name = "${var.name_prefix}-fw-trust-rt"
  }
}

resource "aws_route_table_association" "trust_assoc" {
  route_table_id = aws_route_table.trust_rt.id
  subnet_id      = aws_subnet.fw_trust_1.id
}

########################################
# SECURITY GROUPS
########################################

resource "aws_security_group" "fw_mgmt_sg" {
  vpc_id = aws_vpc.fw_vpc.id
  name   = "${var.name_prefix}-fw-mgmt-sg"

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

resource "aws_security_group" "fw_untrust_sg" {
  vpc_id = aws_vpc.fw_vpc.id
  name   = "${var.name_prefix}-fw-untrust-sg"

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.name_prefix}-fw-untrust-sg"
  }
}

resource "aws_security_group" "fw_trust_sg" {
  vpc_id = aws_vpc.fw_vpc.id
  name   = "${var.name_prefix}-fw-trust-sg"

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

  tags = {
    Name = "${var.name_prefix}-fw-trust-sg"
  }
}

########################################
# IAM ROLE + PROFILE (SSM + optional S3 read)
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

resource "aws_iam_role" "fw_ssm_role" {
  name               = "${var.name_prefix}-fw-ssm-role"
  assume_role_policy = data.aws_iam_policy_document.assume_ec2.json
}

resource "aws_iam_role_policy_attachment" "fw_ssm_attach" {
  role       = aws_iam_role.fw_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Optional S3 read for bootstrap
data "aws_iam_policy_document" "s3_read" {
  count = var.enable_s3_bootstrap && var.bootstrap_s3_bucket != "" ? 1 : 0

  statement {
    actions = [
      "s3:GetObject",
      "s3:ListBucket"
    ]

    resources = [
      "arn:aws:s3:::${var.bootstrap_s3_bucket}",
      "arn:aws:s3:::${var.bootstrap_s3_bucket}/${var.bootstrap_s3_prefix}*"
    ]
  }
}

resource "aws_iam_policy" "s3_read_policy" {
  count  = var.enable_s3_bootstrap && var.bootstrap_s3_bucket != "" ? 1 : 0
  name   = "${var.name_prefix}-fw-s3-bootstrap-read"
  policy = data.aws_iam_policy_document.s3_read[0].json
}

resource "aws_iam_role_policy_attachment" "attach_s3_read" {
  count      = var.enable_s3_bootstrap && var.bootstrap_s3_bucket != "" ? 1 : 0
  role       = aws_iam_role.fw_ssm_role.name
  policy_arn = aws_iam_policy.s3_read_policy[0].arn
}

resource "aws_iam_instance_profile" "fw_ssm_profile" {
  name = "${var.name_prefix}-fw-ssm-profile"
  role = aws_iam_role.fw_ssm_role.name
}

########################################
# FIREWALL INTERFACES & INSTANCE
########################################

resource "aws_network_interface" "fw_mgmt" {
  subnet_id       = aws_subnet.fw_mgmt_1.id
  security_groups = [aws_security_group.fw_mgmt_sg.id]

  tags = {
    Name = "${var.name_prefix}-fw-mgmt"
  }
}

resource "aws_network_interface" "fw_untrust" {
  subnet_id         = aws_subnet.fw_untrust_1.id
  security_groups   = [aws_security_group.fw_untrust_sg.id]
  source_dest_check = false

  tags = {
    Name = "${var.name_prefix}-fw-untrust"
  }
}

resource "aws_network_interface" "fw_trust" {
  subnet_id         = aws_subnet.fw_trust_1.id
  security_groups   = [aws_security_group.fw_trust_sg.id]
  source_dest_check = false

  tags = {
    Name = "${var.name_prefix}-fw-trust"
  }
}

# EIP on Untrust
resource "aws_eip" "fw_eip" {
  domain            = "vpc"
  network_interface = aws_network_interface.fw_untrust.id

  tags = {
    Name = "${var.name_prefix}-fw-eip"
  }
}

resource "aws_instance" "fw_vm" {
  ami                  = local.effective_ami
  instance_type        = var.fw_instance_type
  key_name             = var.fw_key_name != "" ? var.fw_key_name : null
  iam_instance_profile = aws_iam_instance_profile.fw_ssm_profile.name
  user_data            = local.computed_user_data

  # PAN best practice: mgmt must be device_index 0
  network_interface {
    device_index         = 0
    network_interface_id = aws_network_interface.fw_mgmt.id
  }

  lifecycle {
    precondition {
      condition     = length(local.effective_ami) > 0
      error_message = "Set fw_ami_id (preferred) or pan_ami_id to a valid AMI ID."
    }
  }

  tags = {
    Name = "${var.name_prefix}-fw-vm"
  }
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
# FLOW LOGS + S3 (conditional, no regex)
########################################

resource "random_id" "suffix" {
  byte_length = 3
}

resource "aws_s3_bucket" "logs" {
  count         = var.fw_enable_flow_logs ? 1 : 0
  bucket        = coalesce(local.sanitized_logs_bucket, "${var.name_prefix}-flowlogs-${random_id.suffix.hex}")
  force_destroy = true

  tags = {
    Name = "${var.name_prefix}-flowlogs"
  }
}

resource "aws_flow_log" "fw_vpc_logs" {
  count                = var.fw_enable_flow_logs ? 1 : 0
  log_destination      = aws_s3_bucket.logs[0].arn
  log_destination_type = "s3"
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.fw_vpc.id

  tags = {
    Name = "${var.name_prefix}-fw-flowlog"
  }
}

########################################
# TRANSIT GATEWAY – Central Inspection (POC)
########################################

resource "aws_ec2_transit_gateway" "inspection_tgw" {
  description                     = "Central Inspection TGW"
  amazon_side_asn                 = 64512
  default_route_table_association = "disable"
  default_route_table_propagation = "disable"

  tags = {
    Name        = "${var.name_prefix}-inspection-tgw"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_ec2_transit_gateway_route_table" "inspection_rt" {
  transit_gateway_id = aws_ec2_transit_gateway.inspection_tgw.id

  tags = {
    Name = "${var.name_prefix}-inspection-rt"
  }
}

resource "aws_ec2_transit_gateway_route_table" "egress_rt" {
  transit_gateway_id = aws_ec2_transit_gateway.inspection_tgw.id

  tags = {
    Name = "${var.name_prefix}-egress-rt"
  }
}

# Attach FW VPC (Trust subnet) with Appliance Mode
resource "aws_ec2_transit_gateway_vpc_attachment" "fw_attach" {
  vpc_id                 = aws_vpc.fw_vpc.id
  subnet_ids             = [aws_subnet.fw_trust_1.id]
  transit_gateway_id     = aws_ec2_transit_gateway.inspection_tgw.id
  appliance_mode_support = "enable"

  tags = {
    Name = "${var.name_prefix}-fw-attach"
  }
}

# Example App VPC and attachment
resource "aws_vpc" "app_vpc" {
  cidr_block = "10.30.0.0/24"

  tags = {
    Name = "${var.name_prefix}-app-vpc"
  }
}

resource "aws_subnet" "app_private_1" {
  vpc_id            = aws_vpc.app_vpc.id
  cidr_block        = "10.30.0.0/28"
  availability_zone = "${var.region}a"

  tags = {
    Name = "${var.name_prefix}-app-private-1"
  }
}

resource "aws_route_table" "app_rt" {
  vpc_id = aws_vpc.app_vpc.id

  tags = {
    Name = "${var.name_prefix}-app-rt"
  }
}

resource "aws_route_table_association" "app_assoc_rt" {
  route_table_id = aws_route_table.app_rt.id
  subnet_id      = aws_subnet.app_private_1.id
}

resource "aws_ec2_transit_gateway_vpc_attachment" "app_attach" {
  vpc_id             = aws_vpc.app_vpc.id
  subnet_ids         = [aws_subnet.app_private_1.id]
  transit_gateway_id = aws_ec2_transit_gateway.inspection_tgw.id

  tags = {
    Name = "${var.name_prefix}-app-attach"
  }
}

# TGW associations & routes
resource "aws_ec2_transit_gateway_route_table_association" "app_assoc" {
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.inspection_rt.id
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.app_attach.id
}

resource "aws_ec2_transit_gateway_route_table_association" "fw_assoc" {
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.egress_rt.id
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.fw_attach.id
}

resource "aws_ec2_transit_gateway_route" "app_to_fw" {
  destination_cidr_block         = "0.0.0.0/0"
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.fw_attach.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.inspection_rt.id
}

resource "aws_ec2_transit_gateway_route" "fw_to_app" {
  destination_cidr_block         = "10.0.0.0/8"
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.app_attach.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.egress_rt.id
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

output "tgw_id" {
  value = aws_ec2_transit_gateway.inspection_tgw.id
}

output "tgw_route_tables" {
  value = {
    inspection = aws_ec2_transit_gateway_route_table.inspection_rt.id
    egress     = aws_ec2_transit_gateway_route_table.egress_rt.id
  }
}

output "flow_logs_bucket_name" {
  value       = var.fw_enable_flow_logs ? aws_s3_bucket.logs[0].bucket : null
  description = "S3 bucket used for VPC Flow Logs (if enabled)"
}
