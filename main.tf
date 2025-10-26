########################################
# CloudGenius – AWS TGW + Palo Alto Inspection
# Terraform 1.13.x  |  Region: us-west-2
########################################

terraform {
  required_version = ">= 1.3.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

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
  default     = "cg-poc"
}

variable "environment" {
  type        = string
  description = "Environment label"
  default     = "sandbox"
}

variable "name_prefix" {
  type        = string
  description = "Prefix for consistent resource naming"
  default     = "cg"
}

variable "admin_cidr" {
  type        = string
  description = "CIDR block allowed for mgmt access"
  default     = "0.0.0.0/0"
}

variable "fw_ami_id" {
  description = "Palo Alto VM-Series AMI ID"
  type        = string
}

variable "fw_key_name" {
  description = "Existing EC2 key pair name"
  type        = string
}

variable "fw_instance_type" {
  description = "Firewall instance type"
  type        = string
  default     = "c5.xlarge"
}

variable "bootstrap_s3_bucket" {
  description = "S3 bucket for bootstrap (optional)"
  type        = string
  default     = ""
}

variable "fw_enable_flow_logs" {
  description = "Enable VPC Flow Logs"
  type        = bool
  default     = true
}

variable "tgw_asn" {
  description = "Amazon-side ASN for TGW"
  type        = number
  default     = 64512
}

variable "tgw_name" {
  description = "Transit Gateway name"
  type        = string
  default     = "cg-tgw"
}

variable "enable_appliance_mode" {
  description = "Enable Appliance Mode on Firewall VPC Attachment"
  type        = bool
  default     = true
}

########################################
# PHASE 2 – VPC AND SUBNETS
########################################

resource "aws_vpc" "mgmt_vpc" {
  cidr_block = "10.0.0.0/24"
  tags = {
    Name        = "${var.name_prefix}-mgmt-vpc"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_vpc" "fw_vpc" {
  cidr_block = "10.0.1.0/24"
  tags = {
    Name        = "${var.name_prefix}-fw-vpc"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_vpc" "app_vpc" {
  cidr_block = "10.0.2.0/24"
  tags = {
    Name        = "${var.name_prefix}-app-vpc"
    Project     = var.project_name
    Environment = var.environment
  }
}

# Firewall Subnets
resource "aws_subnet" "fw_mgmt_1" {
  vpc_id                  = aws_vpc.fw_vpc.id
  cidr_block              = "10.0.1.0/28"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = true
  tags = { Name = "${var.name_prefix}-fw-mgmt-1" }
}

resource "aws_subnet" "fw_trust_1" {
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.0.1.16/28"
  availability_zone = "${var.region}a"
  tags              = { Name = "${var.name_prefix}-fw-trust-1" }
}

resource "aws_subnet" "fw_trust_2" {
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.0.1.32/28"
  availability_zone = "${var.region}b"
  tags              = { Name = "${var.name_prefix}-fw-trust-2" }
}

resource "aws_subnet" "fw_untrust_1" {
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.0.1.48/28"
  availability_zone = "${var.region}a"
  tags              = { Name = "${var.name_prefix}-fw-untrust-1" }
}

resource "aws_subnet" "fw_untrust_2" {
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.0.1.64/28"
  availability_zone = "${var.region}b"
  tags              = { Name = "${var.name_prefix}-fw-untrust-2" }
}

########################################
# PHASE 4 – FIREWALL SECURITY GROUPS
########################################

resource "aws_security_group" "fw_mgmt_sg" {
  name        = "${var.name_prefix}-fw-mgmt-sg"
  description = "Mgmt access to firewall"
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
# PHASE 4 – IAM ROLE FOR SSM
########################################

resource "aws_iam_role" "fw_ssm_role" {
  name               = "${var.name_prefix}-fw-ssm-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
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

########################################
# PHASE 4 – NETWORK INTERFACES & FIREWALLS
########################################

locals {
  fw_pairs = [
    { mgmt = aws_subnet.fw_mgmt_1.id, trust = aws_subnet.fw_trust_1.id, untrust = aws_subnet.fw_untrust_1.id },
    { mgmt = aws_subnet.fw_mgmt_1.id, trust = aws_subnet.fw_trust_2.id, untrust = aws_subnet.fw_untrust_2.id }
  ]
}

resource "aws_network_interface" "fw_mgmt" {
  count           = length(local.fw_pairs)
  subnet_id       = local.fw_pairs[count.index].mgmt
  security_groups = [aws_security_group.fw_mgmt_sg.id]
  tags = { Name = "${var.name_prefix}-fw-mgmt-${count.index}" }
}

resource "aws_network_interface" "fw_trust" {
  count             = length(local.fw_pairs)
  subnet_id         = local.fw_pairs[count.index].trust
  source_dest_check = false
  tags              = { Name = "${var.name_prefix}-fw-trust-${count.index}" }
}

resource "aws_network_interface" "fw_untrust" {
  count             = length(local.fw_pairs)
  subnet_id         = local.fw_pairs[count.index].untrust
  source_dest_check = false
  tags              = { Name = "${var.name_prefix}-fw-untrust-${count.index}" }
}

resource "aws_eip" "fw_eip" {
  count             = length(local.fw_pairs)
  domain            = "vpc"
  network_interface = aws_network_interface.fw_untrust[count.index].id
  tags              = { Name = "${var.name_prefix}-fw-eip-${count.index}" }
}

resource "aws_instance" "fw_vm" {
  count                = length(local.fw_pairs)
  ami                  = var.fw_ami_id
  instance_type        = var.fw_instance_type
  key_name             = var.fw_key_name
  iam_instance_profile = aws_iam_instance_profile.fw_ssm_profile.name
  network_interface {
    network_interface_id = aws_network_interface.fw_mgmt[count.index].id
    device_index         = 0
  }
  tags = { Name = "${var.name_prefix}-fw-${count.index}" }
}

resource "aws_network_interface_attachment" "fw_trust_attach" {
  count                = length(local.fw_pairs)
  instance_id          = aws_instance.fw_vm[count.index].id
  network_interface_id = aws_network_interface.fw_trust[count.index].id
  device_index         = 1
}

resource "aws_network_interface_attachment" "fw_untrust_attach" {
  count                = length(local.fw_pairs)
  instance_id          = aws_instance.fw_vm[count.index].id
  network_interface_id = aws_network_interface.fw_untrust[count.index].id
  device_index         = 2
}

########################################
# PHASE 5 – LOGGING AND FLOW LOGS
########################################

resource "aws_s3_bucket" "logs" {
  bucket = "${var.name_prefix}-logs-${var.environment}"
  force_destroy = true
  tags = { Name = "${var.name_prefix}-logs" }
}

resource "aws_flow_log" "fw_vpc_logs" {
  count                 = var.fw_enable_flow_logs ? 1 : 0
  vpc_id                = aws_vpc.fw_vpc.id
  log_destination       = aws_s3_bucket.logs.arn
  log_destination_type  = "s3"
  traffic_type          = "ALL"
  tags = { Name = "${var.name_prefix}-fw-vpc-flow" }
}

########################################
# PHASE 6 – TRANSIT GATEWAY INSPECTION
########################################

resource "aws_ec2_transit_gateway" "tgw" {
  description                      = "Centralized TGW for inspection"
  amazon_side_asn                  = var.tgw_asn
  default_route_table_association  = "disable"
  default_route_table_propagation  = "disable"
  tags = { Name = var.tgw_name }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "mgmt_attach" {
  vpc_id             = aws_vpc.mgmt_vpc.id
  subnet_ids         = [aws_subnet.fw_mgmt_1.id]
  transit_gateway_id = aws_ec2_transit_gateway.tgw.id
  tags = { Name = "${var.name_prefix}-mgmt-tgw-attach" }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "fw_attach" {
  vpc_id                 = aws_vpc.fw_vpc.id
  subnet_ids             = [aws_subnet.fw_trust_1.id, aws_subnet.fw_trust_2.id]
  transit_gateway_id     = aws_ec2_transit_gateway.tgw.id
  appliance_mode_support = var.enable_appliance_mode ? "enable" : "disable"
  tags = { Name = "${var.name_prefix}-fw-tgw-attach" }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "app_attach" {
  vpc_id             = aws_vpc.app_vpc.id
  subnet_ids         = [aws_subnet.fw_untrust_1.id, aws_subnet.fw_untrust_2.id]
  transit_gateway_id = aws_ec2_transit_gateway.tgw.id
  tags = { Name = "${var.name_prefix}-app-tgw-attach" }
}

resource "aws_ec2_transit_gateway_route_table" "inspection_rt" {
  transit_gateway_id = aws_ec2_transit_gateway.tgw.id
  tags               = { Name = "${var.name_prefix}-inspection-rt" }
}

resource "aws_ec2_transit_gateway_route_table" "egress_rt" {
  transit_gateway_id = aws_ec2_transit_gateway.tgw.id
  tags               = { Name = "${var.name_prefix}-egress-rt" }
}

resource "aws_ec2_transit_gateway_vpc_attachment_association" "app_assoc" {
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.inspection_rt.id
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.app_attach.id
}

resource "aws_ec2_transit_gateway_vpc_attachment_association" "fw_assoc" {
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.egress_rt.id
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.fw_attach.id
}

resource "aws_ec2_transit_gateway_route" "app_to_fw" {
  destination_cidr_block         = "0.0.0.0/0"
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.inspection_rt.id
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.fw_attach.id
}

resource "aws_ec2_transit_gateway_route" "fw_to_app" {
  destination_cidr_block         = aws_vpc.app_vpc.cidr_block
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.egress_rt.id
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.app_attach.id
}

########################################
# OUTPUTS
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

output "tgw_id" {
  value = aws_ec2_transit_gateway.tgw.id
}
