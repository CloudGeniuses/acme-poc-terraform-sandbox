########################################
# AWS Centralized Inspection – HA + GWLB + Audit
# VM-Series with S3 Bootstrap (admin/Admin2025!)
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
# VARIABLES
########################################

variable "region" {
  type    = string
  default = "us-west-2"
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

variable "az_primary" {
  type    = string
  default = "a"
}

variable "az_secondary" {
  type    = string
  default = "b"
}

variable "enable_ha" {
  type    = bool
  default = true
}

variable "admin_cidr" {
  type        = string
  description = "CIDR allowed to originate to mgmt (SSH/HTTPS). Use a narrow office/VPN CIDR."
  default     = "0.0.0.0/0"
}

variable "fw_ami_id" {
  type        = string
  description = "Palo Alto VM-Series AMI ID in the region (REQUIRED)"
  default     = ""
}

variable "fw_instance_type" {
  type    = string
  default = "c5.xlarge"
}

variable "fw_key_name" {
  type        = string
  description = "Optional EC2 keypair (not needed for SSM access)"
  default     = ""
}

variable "fw_enable_flow_logs" {
  type    = bool
  default = true
}

variable "alarm_email" {
  type    = string
  default = ""
}

variable "use_gwlb" {
  type        = bool
  description = "If true, steer traffic via GWLB/GWLBe. If false, use TGW inspection path."
  default     = true
}

variable "enable_s3_vpc_endpoint" {
  type    = bool
  default = false
}

# Day-0 credentials (intended for lab; stored in bootstrap.xml)
variable "admin_username" {
  type    = string
  default = "admin"
}

variable "admin_password" {
  type      = string
  default   = "Admin2025!"
  sensitive = true
}

########################################
# PROVIDER + DEFAULT TAGS
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
# RANDOM / IDENTITY
########################################

resource "random_id" "suffix" {
  byte_length = 3
}

data "aws_caller_identity" "me" {}
data "aws_caller_identity" "me_account" {}

########################################
# LOCALS
########################################

locals {
  az1 = "${var.region}${var.az_primary}"
  az2 = "${var.region}${var.az_secondary}"

  trail_bucket_name = "${var.name_prefix}-cloudtrail-${random_id.suffix.hex}"
  logs_bucket_name  = "${var.name_prefix}-flowlogs-${random_id.suffix.hex}"

  # Deterministic bootstrap bucket (unique per run via suffix)
  bootstrap_bucket_name = "${var.name_prefix}-bootstrap-${var.region}-${random_id.suffix.hex}"

  # Palo bootstrap prefix layout: <prefix>/config/bootstrap.xml
  bootstrap_prefix = "bootstrap"

  # Always pass user_data for bootstrap
  user_data = <<-EOT
    vmseries-bootstrap-aws-s3bucket=${local.bootstrap_bucket_name}
    vmseries-bootstrap-aws-s3prefix=${local.bootstrap_prefix}
  EOT
}

########################################
# KMS (DEFAULT ENCRYPTION COVERAGE)
########################################

data "aws_iam_policy_document" "kms_key_policy" {
  statement {
    sid     = "AllowRootFullAccess"
    effect  = "Allow"
    actions = ["kms:*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.me_account.account_id}:root"]
    }

    resources = ["*"]
  }

  statement {
    sid     = "AllowCloudTrailUseOfKMS"
    effect  = "Allow"
    actions = ["kms:GenerateDataKey*", "kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    resources = ["*"]

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:aws:cloudtrail:*:${data.aws_caller_identity.me_account.account_id}:trail/*"]
    }
  }

  statement {
    sid     = "AllowConfigDeliveryViaS3"
    effect  = "Allow"
    actions = ["kms:GenerateDataKey*", "kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.me_account.account_id]
    }

    condition {
      test     = "StringLike"
      variable = "kms:ViaService"
      values   = ["s3.${var.region}.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "default" {
  description             = "${var.name_prefix} default encryption key"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.kms_key_policy.json
  tags                    = { Name = "${var.name_prefix}-default-kms" }
}

resource "aws_kms_alias" "default" {
  name          = "alias/${var.name_prefix}-default"
  target_key_id = aws_kms_key.default.key_id
}

resource "aws_ebs_encryption_by_default" "on" {
  enabled = true
}

resource "aws_ebs_default_kms_key" "ebs" {
  key_arn = aws_kms_key.default.arn
}

########################################
# BOOTSTRAP S3 (Bucket + Policy + bootstrap.xml)
########################################

resource "aws_s3_bucket" "bootstrap" {
  bucket        = local.bootstrap_bucket_name
  force_destroy = true

  tags = {
    Name = "${var.name_prefix}-bootstrap"
  }
}

resource "aws_s3_bucket_public_access_block" "bootstrap" {
  bucket                  = aws_s3_bucket.bootstrap.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bootstrap" {
  bucket = aws_s3_bucket.bootstrap.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.default.arn
    }
  }
}

data "aws_iam_policy_document" "bootstrap_tls_only" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    resources = [
      aws_s3_bucket.bootstrap.arn,
      "${aws_s3_bucket.bootstrap.arn}/*"
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "bootstrap" {
  bucket = aws_s3_bucket.bootstrap.id
  policy = data.aws_iam_policy_document.bootstrap_tls_only.json
}

# Upload bootstrap.xml with admin creds
resource "aws_s3_object" "bootstrap_xml" {
  bucket       = aws_s3_bucket.bootstrap.id
  key          = "${local.bootstrap_prefix}/config/bootstrap.xml"
  content_type = "application/xml"

  content = <<-XML
    <config version="11.0.0" urldb="paloaltonetworks">
      <mgt-config>
        <users>
          <entry name="${var.admin_username}">
            <password>${var.admin_password}</password>
            <permissions>
              <role-based>
                <superuser>yes</superuser>
              </role-based>
            </permissions>
          </entry>
        </users>
      </mgt-config>
    </config>
  XML

  depends_on = [
    aws_s3_bucket.bootstrap,
    aws_s3_bucket_public_access_block.bootstrap,
    aws_s3_bucket_server_side_encryption_configuration.bootstrap,
    aws_s3_bucket_policy.bootstrap
  ]
}

########################################
# FW VPC (PRIVATE MGMT, UNTRUST, TRUST) – 2 AZs
########################################

resource "aws_vpc" "fw_vpc" {
  cidr_block           = "10.20.0.0/24"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${var.name_prefix}-fw-vpc" }
}

resource "aws_internet_gateway" "fw_igw" {
  vpc_id = aws_vpc.fw_vpc.id
  tags   = { Name = "${var.name_prefix}-fw-igw" }
}

resource "aws_subnet" "fw_mgmt_az1" {
  vpc_id                  = aws_vpc.fw_vpc.id
  cidr_block              = "10.20.0.0/28"
  availability_zone       = local.az1
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.name_prefix}-fw-mgmt-${var.az_primary}" }
}

resource "aws_subnet" "fw_mgmt_az2" {
  count                   = var.enable_ha ? 1 : 0
  vpc_id                  = aws_vpc.fw_vpc.id
  cidr_block              = "10.20.0.16/28"
  availability_zone       = local.az2
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.name_prefix}-fw-mgmt-${var.az_secondary}" }
}

resource "aws_subnet" "fw_untrust_az1" {
  vpc_id                  = aws_vpc.fw_vpc.id
  cidr_block              = "10.20.0.32/28"
  availability_zone       = local.az1
  map_public_ip_on_launch = true
  tags                    = { Name = "${var.name_prefix}-fw-untrust-${var.az_primary}" }
}

resource "aws_subnet" "fw_untrust_az2" {
  count                   = var.enable_ha ? 1 : 0
  vpc_id                  = aws_vpc.fw_vpc.id
  cidr_block              = "10.20.0.48/28"
  availability_zone       = local.az2
  map_public_ip_on_launch = true
  tags                    = { Name = "${var.name_prefix}-fw-untrust-${var.az_secondary}" }
}

resource "aws_subnet" "fw_trust_az1" {
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.20.0.64/28"
  availability_zone = local.az1
  tags              = { Name = "${var.name_prefix}-fw-trust-${var.az_primary}" }
}

resource "aws_subnet" "fw_trust_az2" {
  count             = var.enable_ha ? 1 : 0
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.20.0.80/28"
  availability_zone = local.az2
  tags              = { Name = "${var.name_prefix}-fw-trust-${var.az_secondary}" }
}

resource "aws_route_table" "mgmt_rt" {
  vpc_id = aws_vpc.fw_vpc.id
  tags   = { Name = "${var.name_prefix}-fw-mgmt-rt" }
}

resource "aws_route_table" "untrust_rt" {
  vpc_id = aws_vpc.fw_vpc.id
  tags   = { Name = "${var.name_prefix}-fw-untrust-rt" }
}

resource "aws_route" "untrust_default" {
  route_table_id         = aws_route_table.untrust_rt.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.fw_igw.id
}

resource "aws_route_table" "trust_rt" {
  vpc_id = aws_vpc.fw_vpc.id
  tags   = { Name = "${var.name_prefix}-fw-trust-rt" }
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

resource "aws_route_table_association" "untrust_assoc_1" {
  route_table_id = aws_route_table.untrust_rt.id
  subnet_id      = aws_subnet.fw_untrust_az1.id
}

resource "aws_route_table_association" "untrust_assoc_2" {
  count          = var.enable_ha ? 1 : 0
  route_table_id = aws_route_table.untrust_rt.id
  subnet_id      = aws_subnet.fw_untrust_az2[0].id
}

resource "aws_route_table_association" "trust_assoc_1" {
  route_table_id = aws_route_table.trust_rt.id
  subnet_id      = aws_subnet.fw_trust_az1.id
}

resource "aws_route_table_association" "trust_assoc_2" {
  count          = var.enable_ha ? 1 : 0
  route_table_id = aws_route_table.trust_rt.id
  subnet_id      = aws_subnet.fw_trust_az2[0].id
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

resource "aws_security_group" "fw_untrust_sg" {
  name   = "${var.name_prefix}-fw-untrust-sg"
  vpc_id = aws_vpc.fw_vpc.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "vpce_sg" {
  name   = "${var.name_prefix}-vpce-ssm-sg"
  vpc_id = aws_vpc.fw_vpc.id

  ingress {
    description = "HTTPS from mgmt subnets"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [
      aws_subnet.fw_mgmt_az1.cidr_block,
      var.enable_ha ? aws_subnet.fw_mgmt_az2[0].cidr_block : "127.0.0.1/32"
    ]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle {
    ignore_changes = [ingress]
  }
}

########################################
# VPC ENDPOINTS FOR SSM (PRIVATE MGMT ACCESS)
########################################

resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = aws_vpc.fw_vpc.id
  service_name        = "com.amazonaws.${var.region}.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.enable_ha ? [aws_subnet.fw_mgmt_az1.id, aws_subnet.fw_mgmt_az2[0].id] : [aws_subnet.fw_mgmt_az1.id]
  security_group_ids  = [aws_security_group.vpce_sg.id]
  private_dns_enabled = true
  tags                = { Name = "${var.name_prefix}-vpce-ssm" }
}

resource "aws_vpc_endpoint" "ec2messages" {
  vpc_id              = aws_vpc.fw_vpc.id
  service_name        = "com.amazonaws.${var.region}.ec2messages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.enable_ha ? [aws_subnet.fw_mgmt_az1.id, aws_subnet.fw_mgmt_az2[0].id] : [aws_subnet.fw_mgmt_az1.id]
  security_group_ids  = [aws_security_group.vpce_sg.id]
  private_dns_enabled = true
  tags                = { Name = "${var.name_prefix}-vpce-ec2messages" }
}

resource "aws_vpc_endpoint" "ssmmessages" {
  vpc_id              = aws_vpc.fw_vpc.id
  service_name        = "com.amazonaws.${var.region}.ssmmessages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.enable_ha ? [aws_subnet.fw_mgmt_az1.id, aws_subnet.fw_mgmt_az2[0].id] : [aws_subnet.fw_mgmt_az1.id]
  security_group_ids  = [aws_security_group.vpce_sg.id]
  private_dns_enabled = true
  tags                = { Name = "${var.name_prefix}-vpce-ssmmessages" }
}

resource "aws_vpc_endpoint" "s3" {
  count             = var.enable_s3_vpc_endpoint ? 1 : 0
  vpc_id            = aws_vpc.fw_vpc.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.mgmt_rt.id, aws_route_table.untrust_rt.id, aws_route_table.trust_rt.id]
  tags              = { Name = "${var.name_prefix}-s3-endpoint" }
}

########################################
# IAM (SSM + Bootstrap S3 Read)
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

data "aws_iam_policy_document" "s3_read" {
  statement {
    actions   = ["s3:ListBucket"]
    resources = ["arn:aws:s3:::${local.bootstrap_bucket_name}"]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["${local.bootstrap_prefix}*"]
    }
  }

  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::${local.bootstrap_bucket_name}/${local.bootstrap_prefix}*"]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["true"]
    }
  }
}

resource "aws_iam_policy" "s3_read_policy" {
  name   = "${var.name_prefix}-fw-s3-bootstrap-read"
  policy = data.aws_iam_policy_document.s3_read.json
}

resource "aws_iam_role_policy_attachment" "attach_s3_read" {
  role       = aws_iam_role.fw_role.name
  policy_arn = aws_iam_policy.s3_read_policy.arn
}

resource "aws_iam_instance_profile" "fw_profile" {
  name = "${var.name_prefix}-fw-profile"
  role = aws_iam_role.fw_role.name
}

########################################
# FIREWALLS (2× HA) – Depends on bootstrap.xml
########################################

resource "aws_network_interface" "fw1_mgmt" {
  subnet_id         = aws_subnet.fw_mgmt_az1.id
  security_groups   = [aws_security_group.fw_mgmt_sg.id]
  source_dest_check = false
  tags              = { Name = "${var.name_prefix}-fw1-mgmt" }
}

resource "aws_network_interface" "fw1_untrust" {
  subnet_id         = aws_subnet.fw_untrust_az1.id
  security_groups   = [aws_security_group.fw_untrust_sg.id]
  source_dest_check = false
  tags              = { Name = "${var.name_prefix}-fw1-untrust" }
}

resource "aws_network_interface" "fw1_trust" {
  subnet_id         = aws_subnet.fw_trust_az1.id
  security_groups   = [aws_security_group.fw_trust_sg.id]
  source_dest_check = false
  tags              = { Name = "${var.name_prefix}-fw1-trust" }
}

resource "aws_eip" "fw1_eip" {
  domain            = "vpc"
  network_interface = aws_network_interface.fw1_untrust.id
  tags              = { Name = "${var.name_prefix}-fw1-eip" }
}

resource "aws_instance" "fw1_vm" {
  ami                  = var.fw_ami_id
  instance_type        = var.fw_instance_type
  key_name             = var.fw_key_name
  iam_instance_profile = aws_iam_instance_profile.fw_profile.name
  user_data            = local.user_data

  root_block_device {
    encrypted   = true
    kms_key_id  = aws_kms_key.default.arn
    volume_size = 60
  }

  network_interface {
    device_index         = 0
    network_interface_id = aws_network_interface.fw1_mgmt.id
  }

  tags = { Name = "${var.name_prefix}-fw1-vm" }

  depends_on = [aws_s3_object.bootstrap_xml]
}

resource "aws_network_interface_attachment" "fw1_attach_untrust" {
  instance_id          = aws_instance.fw1_vm.id
  network_interface_id = aws_network_interface.fw1_untrust.id
  device_index         = 1
}

resource "aws_network_interface_attachment" "fw1_attach_trust" {
  instance_id          = aws_instance.fw1_vm.id
  network_interface_id = aws_network_interface.fw1_trust.id
  device_index         = 2
}

resource "aws_network_interface" "fw2_mgmt" {
  count             = var.enable_ha ? 1 : 0
  subnet_id         = aws_subnet.fw_mgmt_az2[0].id
  security_groups   = [aws_security_group.fw_mgmt_sg.id]
  source_dest_check = false
  tags              = { Name = "${var.name_prefix}-fw2-mgmt" }
}

resource "aws_network_interface" "fw2_untrust" {
  count             = var.enable_ha ? 1 : 0
  subnet_id         = aws_subnet.fw_untrust_az2[0].id
  security_groups   = [aws_security_group.fw_untrust_sg.id]
  source_dest_check = false
  tags              = { Name = "${var.name_prefix}-fw2-untrust" }
}

resource "aws_network_interface" "fw2_trust" {
  count             = var.enable_ha ? 1 : 0
  subnet_id         = aws_subnet.fw_trust_az2[0].id
  security_groups   = [aws_security_group.fw_trust_sg.id]
  source_dest_check = false
  tags              = { Name = "${var.name_prefix}-fw2-trust" }
}

resource "aws_eip" "fw2_eip" {
  count             = var.enable_ha ? 1 : 0
  domain            = "vpc"
  network_interface = aws_network_interface.fw2_untrust[0].id
  tags              = { Name = "${var.name_prefix}-fw2-eip" }
}

resource "aws_instance" "fw2_vm" {
  count                = var.enable_ha ? 1 : 0
  ami                  = var.fw_ami_id
  instance_type        = var.fw_instance_type
  key_name             = var.fw_key_name
  iam_instance_profile = aws_iam_instance_profile.fw_profile.name
  user_data            = local.user_data

  root_block_device {
    encrypted   = true
    kms_key_id  = aws_kms_key.default.arn
    volume_size = 60
  }

  network_interface {
    device_index         = 0
    network_interface_id = aws_network_interface.fw2_mgmt[0].id
  }

  tags = { Name = "${var.name_prefix}-fw2-vm" }

  depends_on = [aws_s3_object.bootstrap_xml]
}

resource "aws_network_interface_attachment" "fw2_attach_untrust" {
  count                = var.enable_ha ? 1 : 0
  instance_id          = aws_instance.fw2_vm[0].id
  network_interface_id = aws_network_interface.fw2_untrust[0].id
  device_index         = 1
}

resource "aws_network_interface_attachment" "fw2_attach_trust" {
  count                = var.enable_ha ? 1 : 0
  instance_id          = aws_instance.fw2_vm[0].id
  network_interface_id = aws_network_interface.fw2_trust[0].id
  device_index         = 2
}

########################################
# GATEWAY LOAD BALANCER (GWLB) – INLINE INSPECTION
########################################

resource "aws_lb_target_group" "gwlb_tg" {
  name        = "${var.name_prefix}-gwlb-tg"
  port        = 6081
  protocol    = "GENEVE"
  vpc_id      = aws_vpc.fw_vpc.id
  target_type = "ip"

  health_check {
    protocol = "TCP"
    port     = "80"
  }

  tags = { Name = "${var.name_prefix}-gwlb-tg" }
}

resource "aws_lb_target_group_attachment" "gwlb_tg_fw1" {
  target_group_arn = aws_lb_target_group.gwlb_tg.arn
  target_id        = aws_network_interface.fw1_untrust.private_ip
}

resource "aws_lb_target_group_attachment" "gwlb_tg_fw2" {
  count            = var.enable_ha ? 1 : 0
  target_group_arn = aws_lb_target_group.gwlb_tg.arn
  target_id        = aws_network_interface.fw2_untrust[0].private_ip
}

resource "aws_lb" "gwlb" {
  name               = "${var.name_prefix}-gwlb"
  load_balancer_type = "gateway"
  subnets            = var.enable_ha ? [aws_subnet.fw_untrust_az1.id, aws_subnet.fw_untrust_az2[0].id] : [aws_subnet.fw_untrust_az1.id]
  tags               = { Name = "${var.name_prefix}-gwlb" }
}

resource "aws_vpc_endpoint_service" "gwlb_svc" {
  acceptance_required        = false
  gateway_load_balancer_arns = [aws_lb.gwlb.arn]
  tags                       = { Name = "${var.name_prefix}-gwlb-svc" }
}

########################################
# APP VPC + TGW (Inspection Path)
########################################

resource "aws_ec2_transit_gateway" "inspection_tgw" {
  description                     = "Central Inspection TGW"
  amazon_side_asn                 = 64512
  default_route_table_association = "disable"
  default_route_table_propagation = "disable"
  tags                            = { Name = "${var.name_prefix}-inspection-tgw" }
}

resource "aws_ec2_transit_gateway_route_table" "inspection_rt" {
  transit_gateway_id = aws_ec2_transit_gateway.inspection_tgw.id
  tags               = { Name = "${var.name_prefix}-inspection-rt" }
}

resource "aws_ec2_transit_gateway_route_table" "egress_rt" {
  transit_gateway_id = aws_ec2_transit_gateway.inspection_tgw.id
  tags               = { Name = "${var.name_prefix}-egress-rt" }
}

resource "aws_vpc" "app_vpc" {
  cidr_block           = "10.30.0.0/24"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${var.name_prefix}-app-vpc" }
}

resource "aws_subnet" "app_private_1" {
  vpc_id            = aws_vpc.app_vpc.id
  cidr_block        = "10.30.0.0/28"
  availability_zone = local.az1
  tags              = { Name = "${var.name_prefix}-app-private-1" }
}

resource "aws_route_table" "app_rt" {
  vpc_id = aws_vpc.app_vpc.id
  tags   = { Name = "${var.name_prefix}-app-rt" }
}

resource "aws_route_table_association" "app_assoc_rt" {
  route_table_id = aws_route_table.app_rt.id
  subnet_id      = aws_subnet.app_private_1.id
}

resource "aws_ec2_transit_gateway_vpc_attachment" "fw_attach" {
  vpc_id                 = aws_vpc.fw_vpc.id
  subnet_ids             = var.enable_ha ? [aws_subnet.fw_trust_az1.id, aws_subnet.fw_trust_az2[0].id] : [aws_subnet.fw_trust_az1.id]
  transit_gateway_id     = aws_ec2_transit_gateway.inspection_tgw.id
  appliance_mode_support = "enable"
  tags                   = { Name = "${var.name_prefix}-fw-attach" }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "app_attach" {
  vpc_id             = aws_vpc.app_vpc.id
  subnet_ids         = [aws_subnet.app_private_1.id]
  transit_gateway_id = aws_ec2_transit_gateway.inspection_tgw.id
  tags               = { Name = "${var.name_prefix}-app-attach" }
}

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
# GWLBe IN APP VPC + ROUTING (Primary path; TGW fallback)
########################################

resource "aws_vpc_endpoint" "gwlbe_app" {
  count             = var.use_gwlb ? 1 : 0
  vpc_id            = aws_vpc.app_vpc.id
  service_name      = aws_vpc_endpoint_service.gwlb_svc.service_name
  vpc_endpoint_type = "GatewayLoadBalancer"
  subnet_ids        = [aws_subnet.app_private_1.id]
  tags              = { Name = "${var.name_prefix}-gwlbe-app" }
}

resource "aws_route" "app_rt_default_to_gwlbe" {
  count                  = var.use_gwlb ? 1 : 0
  route_table_id         = aws_route_table.app_rt.id
  destination_cidr_block = "0.0.0.0/0"
  vpc_endpoint_id        = aws_vpc_endpoint.gwlbe_app[0].id
}

resource "aws_route" "app_rt_default_to_tgw" {
  count                  = var.use_gwlb ? 0 : 1
  route_table_id         = aws_route_table.app_rt.id
  destination_cidr_block = "0.0.0.0/0"
  transit_gateway_id     = aws_ec2_transit_gateway.inspection_tgw.id
}

resource "aws_route" "trust_rt_to_tgw" {
  count                  = var.use_gwlb ? 0 : 1
  route_table_id         = aws_route_table.trust_rt.id
  destination_cidr_block = "10.0.0.0/8"
  transit_gateway_id     = aws_ec2_transit_gateway.inspection_tgw.id
}

########################################
# S3 – FLOW LOGS & CLOUDTRAIL (KMS, TLS-only, Versioning)
########################################

resource "aws_s3_bucket" "logs" {
  count         = var.fw_enable_flow_logs ? 1 : 0
  bucket        = local.logs_bucket_name
  force_destroy = true
  tags          = { Name = "${var.name_prefix}-flowlogs" }
}

resource "aws_s3_bucket_versioning" "logs" {
  count  = length(aws_s3_bucket.logs) > 0 ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  count  = length(aws_s3_bucket.logs) > 0 ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.default.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  count                   = length(aws_s3_bucket.logs) > 0 ? 1 : 0
  bucket                  = aws_s3_bucket.logs[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "logs_tls_only" {
  count = length(aws_s3_bucket.logs) > 0 ? 1 : 0

  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    resources = [
      aws_s3_bucket.logs[0].arn,
      "${aws_s3_bucket.logs[0].arn}/*"
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "logs" {
  count  = length(data.aws_iam_policy_document.logs_tls_only) > 0 ? 1 : 0
  bucket = aws_s3_bucket.logs[0].id
  policy = data.aws_iam_policy_document.logs_tls_only[0].json
}

resource "aws_flow_log" "fw_vpc_logs" {
  count                = length(aws_s3_bucket.logs) > 0 ? 1 : 0
  log_destination_type = "s3"
  log_destination      = aws_s3_bucket.logs[0].arn
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.fw_vpc.id
  tags                 = { Name = "${var.name_prefix}-fw-flowlog" }
}

resource "aws_s3_bucket" "trail" {
  bucket        = local.trail_bucket_name
  force_destroy = true
  tags          = { Name = "${var.name_prefix}-cloudtrail" }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.default.arn
    }
  }
}

data "aws_iam_policy_document" "trail_bucket_policy" {
  statement {
    sid     = "AWSCloudTrailAclCheck"
    effect  = "Allow"
    actions = ["s3:GetBucketAcl"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    resources = [aws_s3_bucket.trail.arn]
  }

  statement {
    sid     = "AWSCloudTrailWrite"
    effect  = "Allow"
    actions = ["s3:PutObject"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${data.aws_caller_identity.me_account.account_id}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid     = "AWSConfigAclCheck"
    effect  = "Allow"
    actions = ["s3:GetBucketAcl"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    resources = [aws_s3_bucket.trail.arn]
  }

  statement {
    sid     = "AWSConfigWrite"
    effect  = "Allow"
    actions = ["s3:PutObject"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    resources = ["${aws_s3_bucket.trail.arn}/config/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    resources = [
      aws_s3_bucket.trail.arn,
      "${aws_s3_bucket.trail.arn}/*"
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail_bucket_policy.json
}

resource "aws_cloudtrail" "orgtrail" {
  name                          = "${var.name_prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  kms_key_id                    = aws_kms_key.default.arn
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
}

########################################
# MONITORING – SNS, Health Checks, Alarms
########################################

resource "aws_sns_topic" "ops_alerts" {
  name              = "${var.name_prefix}-ops-alerts"
  kms_master_key_id = aws_kms_key.default.arn
  tags              = { Name = "${var.name_prefix}-ops-alerts" }
}

data "aws_iam_policy_document" "sns_topic_policy" {
  statement {
    effect  = "Allow"
    actions = ["SNS:Publish"]

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }

    resources = [aws_sns_topic.ops_alerts.arn]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.me_account.account_id]
    }
  }
}

resource "aws_sns_topic_policy" "ops" {
  arn    = aws_sns_topic.ops_alerts.arn
  policy = data.aws_iam_policy_document.sns_topic_policy.json
}

resource "aws_sns_topic_subscription" "ops_email" {
  count     = var.alarm_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.ops_alerts.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

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
  statistic           = "Minimum"
  period              = 60
  evaluation_periods  = 3
  comparison_operator = "LessThanThreshold"
  threshold           = 1
  alarm_actions       = [aws_sns_topic.ops_alerts.arn]

  dimensions = {
    HealthCheckId = aws_route53_health_check.fw1_https.id
  }
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
  statistic           = "Minimum"
  period              = 60
  evaluation_periods  = 3
  comparison_operator = "LessThanThreshold"
  threshold           = 1
  alarm_actions       = [aws_sns_topic.ops_alerts.arn]

  dimensions = {
    HealthCheckId = aws_route53_health_check.fw2_https[0].id
  }
}

########################################
# AWS Config & Security Hub
########################################

resource "aws_iam_role" "config_role" {
  name = "${var.name_prefix}-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { "Service" = "config.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
}

data "aws_iam_policy_document" "config_role_inline" {
  statement {
    effect = "Allow"
    actions = [
      "config:*",
      "ec2:Describe*",
      "iam:List*",
      "iam:Get*",
      "kms:DescribeKey",
      "kms:ListAliases"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "config_inline" {
  name   = "${var.name_prefix}-config-inline"
  role   = aws_iam_role.config_role.id
  policy = data.aws_iam_policy_document.config_role_inline.json
}

resource "aws_config_configuration_recorder" "rec" {
  name     = "default"
  role_arn = aws_iam_role.config_role.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "chan" {
  name           = "default"
  s3_bucket_name = aws_s3_bucket.trail.id
  s3_key_prefix  = "config"
  s3_kms_key_arn = aws_kms_key.default.arn

  depends_on = [
    aws_config_configuration_recorder.rec,
    aws_s3_bucket_policy.trail
  ]
}

resource "aws_config_configuration_recorder_status" "rec_status" {
  name       = aws_config_configuration_recorder.rec.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.chan]
}

resource "aws_securityhub_account" "hub" {}

resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:aws:securityhub:${var.region}::standards/cis-aws-foundations-benchmark/v/1.4.0"
  depends_on    = [aws_securityhub_account.hub]
}

########################################
# SSM Bastion for PAN Mgmt (private-only)
########################################

data "aws_ami" "amazon_linux2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

resource "aws_iam_role" "ssm_bastion_role" {
  name = "${var.name_prefix}-ssm-bastion-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "ec2.amazonaws.com" },
      Action   = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm_core_attach" {
  role       = aws_iam_role.ssm_bastion_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ssm_bastion_profile" {
  name = "${var.name_prefix}-ssm-bastion-profile"
  role = aws_iam_role.ssm_bastion_role.name
}

resource "aws_security_group" "ssm_bastion_sg" {
  name   = "${var.name_prefix}-ssm-bastion-sg"
  vpc_id = aws_vpc.fw_vpc.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name_prefix}-ssm-bastion-sg" }
}

resource "aws_instance" "ssm_bastion" {
  ami                         = data.aws_ami.amazon_linux2.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.fw_mgmt_az1.id
  iam_instance_profile        = aws_iam_instance_profile.ssm_bastion_profile.name
  vpc_security_group_ids      = [aws_security_group.ssm_bastion_sg.id]
  associate_public_ip_address = false

  tags = { Name = "${var.name_prefix}-ssm-bastion" }
}

# Allow Bastion -> PAN mgmt over HTTPS/SSH
resource "aws_security_group_rule" "bastion_to_fw_mgmt_https" {
  description              = "Allow bastion to access Palo mgmt over HTTPS (443)"
  type                     = "ingress"
  protocol                 = "tcp"
  from_port                = 443
  to_port                  = 443
  security_group_id        = aws_security_group.fw_mgmt_sg.id
  source_security_group_id = aws_security_group.ssm_bastion_sg.id
}

resource "aws_security_group_rule" "bastion_to_fw_mgmt_ssh" {
  description              = "Allow bastion to access Palo mgmt over SSH (22)"
  type                     = "ingress"
  protocol                 = "tcp"
  from_port                = 22
  to_port                  = 22
  security_group_id        = aws_security_group.fw_mgmt_sg.id
  source_security_group_id = aws_security_group.ssm_bastion_sg.id
}

########################################
# Helpful locals/outputs for SSM Port-Forward
########################################

locals {
  pan_fw1_mgmt_ip = aws_network_interface.fw1_mgmt.private_ip
}

output "ssm_bastion_instance_id" {
  value       = aws_instance.ssm_bastion.id
  description = "SSM-enabled bastion instance ID"
}

output "pan_fw1_mgmt_ip" {
  value       = local.pan_fw1_mgmt_ip
  description = "Private mgmt IP of PAN fw1"
}

output "ssm_port_forward_cmd_https" {
  description = "Run this to open PAN GUI at https://localhost:8443"
  value       = "aws ssm start-session --target ${aws_instance.ssm_bastion.id} --document-name AWS-StartPortForwardingSessionToRemoteHost --parameters 'host=[${local.pan_fw1_mgmt_ip}],portNumber=[443],localPortNumber=[8443]'"
}

output "ssm_port_forward_cmd_ssh" {
  description = "Run this then: ssh admin@localhost -p 2222"
  value       = "aws ssm start-session --target ${aws_instance.ssm_bastion.id} --document-name AWS-StartPortForwardingSessionToRemoteHost --parameters 'host=[${local.pan_fw1_mgmt_ip}],portNumber=[22],localPortNumber=[2222]'"
}

########################################
# Other Useful Outputs
########################################

output "fw1_public_ip" {
  value = aws_eip.fw1_eip.public_ip
}

output "fw2_public_ip" {
  value = var.enable_ha ? aws_eip.fw2_eip[0].public_ip : null
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
