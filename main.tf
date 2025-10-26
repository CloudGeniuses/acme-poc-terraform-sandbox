########################################
# AWS Centralized Inspection – Phases 1–6 + HA/Monitoring/IAM/Cost/Tags
########################################

terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    aws {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

########################################
# VARIABLES (ALL MULTI-LINE)
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

# AMI selection (fw_ami_id preferred)
variable "fw_ami_id" {
  type    = string
  default = ""
}

variable "pan_ami_id" {
  type    = string
  default = ""
}

variable "fw_instance_type" {
  type    = string
  default = "c5.xlarge"
}

variable "fw_key_name" {
  type    = string
  default = ""
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
  description = "Reserved for future external TGW"
}

# HA + second AZ
variable "enable_ha" {
  type    = bool
  default = true
}

variable "az_primary" {
  type    = string
  default = "a"
}

variable "az_secondary" {
  type    = string
  default = "b"
}

# Monitoring / Alerts
variable "alarm_email" {
  type    = string
  default = ""
}

# Tagging / Governance
variable "owner" {
  type    = string
  default = "network-team"
}

variable "cost_center" {
  type    = string
  default = "net-ops"
}

# Optional S3 VPCE enforcement for logs and bootstrap
variable "enable_s3_vpc_endpoint" {
  type    = bool
  default = false
}

########################################
# PROVIDER (default tags)
########################################

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Name        = var.name_prefix
      Project     = var.project_name
      Environment = var.environment
      Owner       = var.owner
      CostCenter  = var.cost_center
    }
  }
}

########################################
# LOCALS
########################################

locals {
  effective_ami = length(var.fw_ami_id) > 0 ? var.fw_ami_id : var.pan_ami_id

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

  # sanitize optional bucket name (simple replacements only)
  sanitized_logs_bucket = (
    var.log_s3_bucket_name != null && var.log_s3_bucket_name != ""
    ? lower(replace(replace(var.log_s3_bucket_name, " ", "-"), "_", "-"))
    : null
  )

  az1 = "${var.region}${var.az_primary}"
  az2 = "${var.region}${var.az_secondary}"
}

########################################
# NETWORK – FW VPC (Mgmt/Untrust/Trust) x2 AZ when HA
########################################

resource "aws_vpc" "fw_vpc" {
  cidr_block           = "10.20.0.0/24"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.name_prefix}-fw-vpc"
  }
}

resource "aws_internet_gateway" "fw_igw" {
  vpc_id = aws_vpc.fw_vpc.id

  tags = {
    Name = "${var.name_prefix}-fw-igw"
  }
}

# Primary AZ subnets
resource "aws_subnet" "fw_mgmt_az1" {
  vpc_id                  = aws_vpc.fw_vpc.id
  cidr_block              = "10.20.0.0/28"
  availability_zone       = local.az1
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.name_prefix}-fw-mgmt-${var.az_primary}"
  }
}

resource "aws_subnet" "fw_untrust_az1" {
  vpc_id                  = aws_vpc.fw_vpc.id
  cidr_block              = "10.20.0.32/28"
  availability_zone       = local.az1
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.name_prefix}-fw-untrust-${var.az_primary}"
  }
}

resource "aws_subnet" "fw_trust_az1" {
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.20.0.64/28"
  availability_zone = local.az1

  tags = {
    Name = "${var.name_prefix}-fw-trust-${var.az_primary}"
  }
}

# Secondary AZ subnets (only if HA)
resource "aws_subnet" "fw_mgmt_az2" {
  count                    = var.enable_ha ? 1 : 0
  vpc_id                   = aws_vpc.fw_vpc.id
  cidr_block               = "10.20.0.80/28"
  availability_zone        = local.az2
  map_public_ip_on_launch  = true

  tags = {
    Name = "${var.name_prefix}-fw-mgmt-${var.az_secondary}"
  }
}

resource "aws_subnet" "fw_untrust_az2" {
  count                   = var.enable_ha ? 1 : 0
  vpc_id                  = aws_vpc.fw_vpc.id
  cidr_block              = "10.20.0.96/28"
  availability_zone       = local.az2
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.name_prefix}-fw-untrust-${var.az_secondary}"
  }
}

resource "aws_subnet" "fw_trust_az2" {
  count             = var.enable_ha ? 1 : 0
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.20.0.112/28"
  availability_zone = local.az2

  tags = {
    Name = "${var.name_prefix}-fw-trust-${var.az_secondary}"
  }
}

# Route tables
resource "aws_route_table" "mgmt_rt" {
  vpc_id = aws_vpc.fw_vpc.id

  tags = {
    Name = "${var.name_prefix}-fw-mgmt-rt"
  }
}

resource "aws_route" "mgmt_def" {
  route_table_id         = aws_route_table.mgmt_rt.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.fw_igw.id
}

resource "aws_route_table_association" "mgmt_assoc_az1" {
  route_table_id = aws_route_table.mgmt_rt.id
  subnet_id      = aws_subnet.fw_mgmt_az1.id
}

resource "aws_route_table_association" "mgmt_assoc_az2" {
  count          = var.enable_ha ? 1 : 0
  route_table_id = aws_route_table.mgmt_rt.id
  subnet_id      = aws_subnet.fw_mgmt_az2[0].id
}

resource "aws_route_table" "untrust_rt" {
  vpc_id = aws_vpc.fw_vpc.id

  tags = {
    Name = "${var.name_prefix}-fw-untrust-rt"
  }
}

resource "aws_route" "untrust_def" {
  route_table_id         = aws_route_table.untrust_rt.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.fw_igw.id
}

resource "aws_route_table_association" "untrust_assoc_az1" {
  route_table_id = aws_route_table.untrust_rt.id
  subnet_id      = aws_subnet.fw_untrust_az1.id
}

resource "aws_route_table_association" "untrust_assoc_az2" {
  count          = var.enable_ha ? 1 : 0
  route_table_id = aws_route_table.untrust_rt.id
  subnet_id      = aws_subnet.fw_untrust_az2[0].id
}

resource "aws_route_table" "trust_rt" {
  vpc_id = aws_vpc.fw_vpc.id

  tags = {
    Name = "${var.name_prefix}-fw-trust-rt"
  }
}

resource "aws_route_table_association" "trust_assoc_az1" {
  route_table_id = aws_route_table.trust_rt.id
  subnet_id      = aws_subnet.fw_trust_az1.id
}

resource "aws_route_table_association" "trust_assoc_az2" {
  count          = var.enable_ha ? 1 : 0
  route_table_id = aws_route_table.trust_rt.id
  subnet_id      = aws_subnet.fw_trust_az2[0].id
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

# Optional S3 read for bootstrap (least privilege)
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
# FIREWALL INSTANCES & ENIs (HA aware)
########################################

# FW #1 (AZ1)
resource "aws_network_interface" "fw1_mgmt" {
  subnet_id       = aws_subnet.fw_mgmt_az1.id
  security_groups = [aws_security_group.fw_mgmt_sg.id]

  tags = {
    Name = "${var.name_prefix}-fw1-mgmt"
  }
}

resource "aws_network_interface" "fw1_untrust" {
  subnet_id         = aws_subnet.fw_untrust_az1.id
  security_groups   = [aws_security_group.fw_untrust_sg.id]
  source_dest_check = false

  tags = {
    Name = "${var.name_prefix}-fw1-untrust"
  }
}

resource "aws_network_interface" "fw1_trust" {
  subnet_id         = aws_subnet.fw_trust_az1.id
  security_groups   = [aws_security_group.fw_trust_sg.id]
  source_dest_check = false

  tags = {
    Name = "${var.name_prefix}-fw1-trust"
  }
}

resource "aws_eip" "fw1_eip" {
  domain            = "vpc"
  network_interface = aws_network_interface.fw1_untrust.id

  tags = {
    Name = "${var.name_prefix}-fw1-eip"
  }
}

resource "aws_instance" "fw1_vm" {
  ami                  = local.effective_ami
  instance_type        = var.fw_instance_type
  key_name             = var.fw_key_name != "" ? var.fw_key_name : null
  iam_instance_profile = aws_iam_instance_profile.fw_ssm_profile.name
  user_data            = local.computed_user_data

  network_interface {
    device_index         = 0
    network_interface_id = aws_network_interface.fw1_mgmt.id
  }

  lifecycle {
    precondition {
      condition     = length(local.effective_ami) > 0
      error_message = "Set fw_ami_id (preferred) or pan_ami_id to a valid AMI ID."
    }
  }

  tags = {
    Name = "${var.name_prefix}-fw1-vm"
  }
}

resource "aws_network_interface_attachment" "fw1_untrust_attach" {
  instance_id          = aws_instance.fw1_vm.id
  network_interface_id = aws_network_interface.fw1_untrust.id
  device_index         = 1
}

resource "aws_network_interface_attachment" "fw1_trust_attach" {
  instance_id          = aws_instance.fw1_vm.id
  network_interface_id = aws_network_interface.fw1_trust.id
  device_index         = 2
}

# FW #2 (AZ2) — only if HA
resource "aws_network_interface" "fw2_mgmt" {
  count           = var.enable_ha ? 1 : 0
  subnet_id       = aws_subnet.fw_mgmt_az2[0].id
  security_groups = [aws_security_group.fw_mgmt_sg.id]

  tags = {
    Name = "${var.name_prefix}-fw2-mgmt"
  }
}

resource "aws_network_interface" "fw2_untrust" {
  count             = var.enable_ha ? 1 : 0
  subnet_id         = aws_subnet.fw_untrust_az2[0].id
  security_groups   = [aws_security_group.fw_untrust_sg.id]
  source_dest_check = false

  tags = {
    Name = "${var.name_prefix}-fw2-untrust"
  }
}

resource "aws_network_interface" "fw2_trust" {
  count             = var.enable_ha ? 1 : 0
  subnet_id         = aws_subnet.fw_trust_az2[0].id
  security_groups   = [aws_security_group.fw_trust_sg.id]
  source_dest_check = false

  tags = {
    Name = "${var.name_prefix}-fw2-trust"
  }
}

resource "aws_eip" "fw2_eip" {
  count             = var.enable_ha ? 1 : 0
  domain            = "vpc"
  network_interface = aws_network_interface.fw2_untrust[0].id

  tags = {
    Name = "${var.name_prefix}-fw2-eip"
  }
}

resource "aws_instance" "fw2_vm" {
  count                = var.enable_ha ? 1 : 0
  ami                  = local.effective_ami
  instance_type        = var.fw_instance_type
  key_name             = var.fw_key_name != "" ? var.fw_key_name : null
  iam_instance_profile = aws_iam_instance_profile.fw_ssm_profile.name
  user_data            = local.computed_user_data

  network_interface {
    device_index         = 0
    network_interface_id = aws_network_interface.fw2_mgmt[0].id
  }

  tags = {
    Name = "${var.name_prefix}-fw2-vm"
  }
}

resource "aws_network_interface_attachment" "fw2_untrust_attach" {
  count                = var.enable_ha ? 1 : 0
  instance_id          = aws_instance.fw2_vm[0].id
  network_interface_id = aws_network_interface.fw2_untrust[0].id
  device_index         = 1
}

resource "aws_network_interface_attachment" "fw2_trust_attach" {
  count                = var.enable_ha ? 1 : 0
  instance_id          = aws_instance.fw2_vm[0].id
  network_interface_id = aws_network_interface.fw2_trust[0].id
  device_index         = 2
}

########################################
# FLOW LOGS + S3 (policy + lifecycle)
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

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "logs_bucket_policy" {
  count = var.fw_enable_flow_logs ? 1 : 0

  statement {
    sid    = "AllowVPCFlowLogsDelivery"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    actions = [
      "s3:PutObject",
      "s3:GetBucketLocation",
      "s3:ListBucketMultipartUploads",
      "s3:AbortMultipartUpload",
      "s3:ListBucket"
    ]

    resources = [
      aws_s3_bucket.logs[0].arn,
      "${aws_s3_bucket.logs[0].arn}/*"
    ]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  dynamic "statement" {
    for_each = var.enable_s3_vpc_endpoint ? [1] : []
    content {
      sid    = "DenyNonVPCE"
      effect = "Deny"

      principals {
        type        = "*"
        identifiers = ["*"]
      }

      actions = ["s3:*"]

      resources = [
        aws_s3_bucket.logs[0].arn,
        "${aws_s3_bucket.logs[0].arn}/*"
      ]

      condition {
        test     = "StringNotEquals"
        variable = "aws:SourceVpce"
        values   = [aws_vpc_endpoint.s3[0].id]
      }
    }
  }
}

resource "aws_s3_bucket_policy" "logs_policy" {
  count  = var.fw_enable_flow_logs ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  policy = data.aws_iam_policy_document.logs_bucket_policy[0].json
}

resource "aws_s3_bucket_lifecycle_configuration" "logs_lifecycle" {
  count  = var.fw_enable_flow_logs ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  rule {
    id     = "expire-logs"
    status = "Enabled"

    filter {}

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

# VPC Flow Logs
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
# (Optional) S3 Gateway Endpoint for FW VPC
########################################

resource "aws_vpc_endpoint" "s3" {
  count             = var.enable_s3_vpc_endpoint ? 1 : 0
  vpc_id            = aws_vpc.fw_vpc.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [
    aws_route_table.mgmt_rt.id,
    aws_route_table.untrust_rt.id,
    aws_route_table.trust_rt.id
  ]

  tags = {
    Name = "${var.name_prefix}-s3-endpoint"
  }
}

########################################
# TRANSIT GATEWAY – Central Inspection
########################################

resource "aws_ec2_transit_gateway" "inspection_tgw" {
  description                     = "Central Inspection TGW"
  amazon_side_asn                 = 64512
  default_route_table_association = "disable"
  default_route_table_propagation = "disable"

  tags = {
    Name = "${var.name_prefix}-inspection-tgw"
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

# Attach FW VPC (Trust subnets) with appliance mode for HA
resource "aws_ec2_transit_gateway_vpc_attachment" "fw_attach" {
  vpc_id                 = aws_vpc.fw_vpc.id
  subnet_ids             = var.enable_ha ? [aws_subnet.fw_trust_az1.id, aws_subnet.fw_trust_az2[0].id] : [aws_subnet.fw_trust_az1.id]
  transit_gateway_id     = aws_ec2_transit_gateway.inspection_tgw.id
  appliance_mode_support = "enable"

  tags = {
    Name = "${var.name_prefix}-fw-attach"
  }
}

# Example App VPC (single-AZ spoke)
resource "aws_vpc" "app_vpc" {
  cidr_block = "10.30.0.0/24"

  tags = {
    Name = "${var.name_prefix}-app-vpc"
  }
}

resource "aws_subnet" "app_private_1" {
  vpc_id            = aws_vpc.app_vpc.id
  cidr_block        = "10.30.0.0/28"
  availability_zone = local.az1

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

# VPC route-table fixes so traffic hits TGW
resource "aws_route" "app_rt_to_tgw" {
  route_table_id         = aws_route_table.app_rt.id
  destination_cidr_block = "0.0.0.0/0"
  transit_gateway_id     = aws_ec2_transit_gateway.inspection_tgw.id
}

resource "aws_route" "trust_rt_to_tgw" {
  route_table_id         = aws_route_table.trust_rt.id
  destination_cidr_block = "10.0.0.0/8"
  transit_gateway_id     = aws_ec2_transit_gateway.inspection_tgw.id
}

########################################
# MONITORING – SNS, Health checks (EIP), Alarms, Dashboard
########################################

resource "aws_sns_topic" "ops_alerts" {
  name = "${var.name_prefix}-ops-alerts"

  tags = {
    Name = "${var.name_prefix}-ops-alerts"
  }
}

resource "aws_sns_topic_subscription" "ops_email" {
  count     = var.alarm_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.ops_alerts.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

# Route53 Health checks against EIPs (use ip_address)
resource "aws_route53_health_check" "fw1_https" {
  ip_address        = aws_eip.fw1_eip.public_ip
  type              = "HTTPS"
  port              = 443
  resource_path     = "/"
  request_interval  = 30
  failure_threshold = 3
  reference_name    = "${var.name_prefix}-fw1-https"
}

resource "aws_route53_health_check" "fw2_https" {
  count             = var.enable_ha ? 1 : 0
  ip_address        = aws_eip.fw2_eip[0].public_ip
  type              = "HTTPS"
  port              = 443
  resource_path     = "/"
  request_interval  = 30
  failure_threshold = 3
  reference_name    = "${var.name_prefix}-fw2-https"
}

# Alarms – CPU, Status, and EIP health
resource "aws_cloudwatch_metric_alarm" "fw1_cpu_high" {
  alarm_name          = "${var.name_prefix}-fw1-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 80
  alarm_actions       = [aws_sns_topic.ops_alerts.arn]

  dimensions = {
    InstanceId = aws_instance.fw1_vm.id
  }
}

resource "aws_cloudwatch_metric_alarm" "fw1_status_failed" {
  alarm_name          = "${var.name_prefix}-fw1-status-check-failed"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "StatusCheckFailed"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  alarm_actions       = [aws_sns_topic.ops_alerts.arn]

  dimensions = {
    InstanceId = aws_instance.fw1_vm.id
  }
}

resource "aws_cloudwatch_metric_alarm" "fw1_eip_unhealthy" {
  alarm_name          = "${var.name_prefix}-fw1-eip-https-unhealthy"
  namespace           = "AWS/Route53"
  metric_name         = "HealthCheckStatus"

  dimensions = {
    HealthCheckId = aws_route53_health_check.fw1_https.id
  }

  statistic           = "Minimum"
  period              = 60
  evaluation_periods  = 3
  comparison_operator = "LessThanThreshold"
  threshold           = 1
  alarm_actions       = [aws_sns_topic.ops_alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "fw2_cpu_high" {
  count               = var.enable_ha ? 1 : 0
  alarm_name          = "${var.name_prefix}-fw2-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 80
  alarm_actions       = [aws_sns_topic.ops_alerts.arn]

  dimensions = {
    InstanceId = aws_instance.fw2_vm[0].id
  }
}

resource "aws_cloudwatch_metric_alarm" "fw2_status_failed" {
  count               = var.enable_ha ? 1 : 0
  alarm_name          = "${var.name_prefix}-fw2-status-check-failed"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "StatusCheckFailed"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  alarm_actions       = [aws_sns_topic.ops_alerts.arn]

  dimensions = {
    InstanceId = aws_instance.fw2_vm[0].id
  }
}

resource "aws_cloudwatch_metric_alarm" "fw2_eip_unhealthy" {
  count               = var.enable_ha ? 1 : 0
  alarm_name          = "${var.name_prefix}-fw2-eip-https-unhealthy"
  namespace           = "AWS/Route53"
  metric_name         = "HealthCheckStatus"

  dimensions = {
    HealthCheckId = aws_route53_health_check.fw2_https[0].id
  }

  statistic           = "Minimum"
  period              = 60
  evaluation_periods  = 3
  comparison_operator = "LessThanThreshold"
  threshold           = 1
  alarm_actions       = [aws_sns_topic.ops_alerts.arn]
}

# CloudWatch Dashboard (no ${} inside jsonencode)
resource "aws_cloudwatch_dashboard" "inspection_dashboard" {
  dashboard_name = "${var.name_prefix}-inspection"

  dashboard_body = jsonencode({
    widgets = [
      {
        "type" : "metric",
        "x" : 0,
        "y" : 0,
        "width" : 12,
        "height" : 6,
        "properties" : {
          "metrics" : [
            [ "AWS/EC2", "CPUUtilization", "InstanceId", aws_instance.fw1_vm.id ]
          ],
          "view" : "timeSeries",
          "stacked" : false,
          "region" : var.region,
          "title" : "Firewall CPU Utilization"
        }
      },
      {
        "type" : "metric",
        "x" : 0,
        "y" : 7,
        "width" : 12,
        "height" : 6,
        "properties" : {
          "metrics" : [
            [ "AWS/EC2", "StatusCheckFailed", "InstanceId", aws_instance.fw1_vm.id ]
          ],
          "view" : "timeSeries",
          "stacked" : false,
          "region" : var.region,
          "title" : "EC2 Status Checks"
        }
      }
    ]
  })
}

########################################
# OUTPUTS
########################################

output "fw1_public_ip" {
  value = aws_eip.fw1_eip.public_ip
}

output "fw1_private_ip" {
  value = aws_instance.fw1_vm.private_ip
}

output "fw2_public_ip" {
  value = var.enable_ha ? aws_eip.fw2_eip[0].public_ip : null
}

output "fw2_private_ip" {
  value = var.enable_ha ? aws_instance.fw2_vm[0].private_ip : null
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
  value = var.fw_enable_flow_logs ? aws_s3_bucket.logs[0].bucket : null
}

output "fw1_gui_url" {
  value = "https://${aws_eip.fw1_eip.public_ip}"
}

output "fw2_gui_url" {
  value = var.enable_ha ? "https://${aws_eip.fw2_eip[0].public_ip}" : null
}
