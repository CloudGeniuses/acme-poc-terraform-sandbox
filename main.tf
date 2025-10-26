########################################
# AWS Centralized Inspection – Phases 1-6
# (Production-ready, Terraform Cloud compatible)
########################################

provider "aws" {
  region = var.region
}

########################################
# VARIABLES
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
  description = "Public IP CIDR allowed for mgmt SSH/GUI"
  type        = string
}

# Optional compatibility variables (to silence tfvars warnings)
variable "log_s3_bucket_name"    { default = null }
variable "enable_s3_bootstrap"   { default = false }
variable "fw_bootstrap_user_data"{ default = null }
variable "fw_desired_capacity"   { default = 1 }

########################################
# PHASE 2 – CORE NETWORKING (3 VPCs)
########################################
resource "aws_vpc" "mgmt_vpc" {
  cidr_block = "10.10.0.0/24"
  tags = {
    Name        = "${var.name_prefix}-mgmt-vpc"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_vpc" "fw_vpc" {
  cidr_block = "10.20.0.0/24"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name        = "${var.name_prefix}-fw-vpc"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_vpc" "app_vpc" {
  cidr_block = "10.30.0.0/24"
  tags = {
    Name        = "${var.name_prefix}-app-vpc"
    Project     = var.project_name
    Environment = var.environment
  }
}

########################################
# SUBNETS (FW VPC)
########################################
resource "aws_subnet" "fw_mgmt_1" {
  vpc_id                  = aws_vpc.fw_vpc.id
  cidr_block              = "10.20.0.0/28"
  availability_zone       = "us-west-2a"
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.name_prefix}-fw-mgmt-1"
  }
}

resource "aws_subnet" "fw_mgmt_2" {
  vpc_id                  = aws_vpc.fw_vpc.id
  cidr_block              = "10.20.0.16/28"
  availability_zone       = "us-west-2b"
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.name_prefix}-fw-mgmt-2"
  }
}

resource "aws_subnet" "fw_untrust_1" {
  vpc_id                  = aws_vpc.fw_vpc.id
  cidr_block              = "10.20.0.32/28"
  availability_zone       = "us-west-2a"
  map_public_ip_on_launch = false
  tags = {
    Name = "${var.name_prefix}-fw-untrust-1"
  }
}

resource "aws_subnet" "fw_untrust_2" {
  vpc_id                  = aws_vpc.fw_vpc.id
  cidr_block              = "10.20.0.48/28"
  availability_zone       = "us-west-2b"
  map_public_ip_on_launch = false
  tags = {
    Name = "${var.name_prefix}-fw-untrust-2"
  }
}

resource "aws_subnet" "fw_trust_1" {
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.20.0.64/28"
  availability_zone = "us-west-2a"
  tags = {
    Name = "${var.name_prefix}-fw-trust-1"
  }
}

resource "aws_subnet" "fw_trust_2" {
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.20.0.80/28"
  availability_zone = "us-west-2b"
  tags = {
    Name = "${var.name_prefix}-fw-trust-2"
  }
}

########################################
# SECURITY GROUPS – FW VPC
########################################
resource "aws_security_group" "fw_mgmt_sg" {
  name        = "${var.name_prefix}-fw-mgmt-sg"
  description = "Mgmt access to VM-Series"
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
    Name        = "${var.name_prefix}-fw-mgmt-sg"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_security_group" "fw_untrust_sg" {
  name        = "${var.name_prefix}-fw-untrust-sg"
  description = "Untrust dataplane ENI"
  vpc_id      = aws_vpc.fw_vpc.id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name        = "${var.name_prefix}-fw-untrust-sg"
  }
}

resource "aws_security_group" "fw_trust_sg" {
  name        = "${var.name_prefix}-fw-trust-sg"
  description = "Trust dataplane ENI"
  vpc_id      = aws_vpc.fw_vpc.id
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
# IAM ROLE + PROFILE (SSM Access)
########################################
resource "aws_iam_role" "fw_ssm_role" {
  name = "${var.name_prefix}-fw-ssm-role"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = {
    Name = "${var.name_prefix}-fw-ssm-role"
  }
}

resource "aws_iam_role_policy_attachment" "fw_ssm_attach" {
  role       = aws_iam_role.fw_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "fw_ssm_profile" {
  name = "${var.name_prefix}-fw-ssm-profile"
  role = aws_iam_role.fw_ssm_role.name
}

########################################
# NETWORK INTERFACES + EIPs + INSTANCES
########################################
locals {
  fw_pairs = [
    { mgmt = aws_subnet.fw_mgmt_1.id,  untrust = aws_subnet.fw_untrust_1.id, trust = aws_subnet.fw_trust_1.id },
    { mgmt = aws_subnet.fw_mgmt_2.id,  untrust = aws_subnet.fw_untrust_2.id, trust = aws_subnet.fw_trust_2.id }
  ]
}

resource "aws_network_interface" "fw_mgmt" {
  count           = length(local.fw_pairs)
  subnet_id       = local.fw_pairs[count.index].mgmt
  security_groups = [aws_security_group.fw_mgmt_sg.id]
  tags = { Name = "${var.name_prefix}-fw-mgmt-${count.index}" }
}

resource "aws_network_interface" "fw_untrust" {
  count             = length(local.fw_pairs)
  subnet_id         = local.fw_pairs[count.index].untrust
  security_groups   = [aws_security_group.fw_untrust_sg.id]
  source_dest_check = false
  tags = { Name = "${var.name_prefix}-fw-untrust-${count.index}" }
}

resource "aws_network_interface" "fw_trust" {
  count             = length(local.fw_pairs)
  subnet_id         = local.fw_pairs[count.index].trust
  security_groups   = [aws_security_group.fw_trust_sg.id]
  source_dest_check = false
  tags = { Name = "${var.name_prefix}-fw-trust-${count.index}" }
}

resource "aws_eip" "fw_eip" {
  count             = length(local.fw_pairs)
  domain            = "vpc"
  network_interface = aws_network_interface.fw_untrust[count.index].id
  tags = { Name = "${var.name_prefix}-fw-eip-${count.index}" }
}

resource "aws_instance" "fw_vm" {
  count                = length(local.fw_pairs)
  ami                  = var.pan_ami_id
  instance_type        = var.pan_instance_type
  key_name             = var.pan_key_name
  iam_instance_profile = aws_iam_instance_profile.fw_ssm_profile.name
  network_interface {
    device_index         = 0
    network_interface_id = aws_network_interface.fw_mgmt[count.index].id
  }
  tags = {
    Name = "${var.name_prefix}-fw-vm-${count.index}"
  }
}

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
# FLOW LOGS + S3
########################################
resource "aws_s3_bucket" "logs" {
  bucket = "${var.name_prefix}-flowlogs-${random_id.suffix.hex}"
  force_destroy = true
}

resource "random_id" "suffix" {
  byte_length = 3
}

resource "aws_flow_log" "fw_vpc_logs" {
  count                 = 1
  log_destination       = aws_s3_bucket.logs.arn
  log_destination_type  = "s3"
  traffic_type          = "ALL"
  vpc_id                = aws_vpc.fw_vpc.id
}

########################################
# (Optional) TGW ROUTE ASSOCIATIONS
########################################
resource "aws_ec2_transit_gateway_route_table_association" "app_assoc" {
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.inspection_rt.id
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.app_attach.id
}

resource "aws_ec2_transit_gateway_route_table_association" "fw_assoc" {
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.egress_rt.id
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.fw_attach.id
}

########################################
# OUTPUTS
########################################
output "fw_vpc_id"          { value = aws_vpc.fw_vpc.id }
output "firewall_public_ips"{ value = aws_eip.fw_eip[*].public_ip }
output "firewall_private_ips"{ value = aws_instance.fw_vm[*].private_ip }
