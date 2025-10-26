########################################
# AWS Centralized Inspection – Phases 1–6
########################################

provider "aws" {
  region = var.region
}

########################################
# VARIABLES
########################################
variable "region"               { type = string  default = "us-west-2" }
variable "project_name"         { type = string }
variable "environment"          { type = string }
variable "name_prefix"          { type = string }
variable "admin_cidr"           { type = string }

# Firewall variables
variable "pan_ami_id"           { type = string  description = "AMI for Palo Alto VM-Series" }
variable "pan_instance_type"    { type = string  default = "c5.xlarge" }
variable "pan_key_name"         { type = string  default = "" }

# Terraform Cloud compatibility placeholders
variable "fw_ami_id"            { default = "" }
variable "tgw_id"               { default = "" }
variable "fw_bootstrap_user_data" { default = null }
variable "fw_desired_capacity"  { default = 1 }
variable "enable_s3_bootstrap"  { default = false }
variable "log_s3_bucket_name"   { default = null }

########################################
# PHASE 2 – CORE NETWORKING (FW VPC)
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

# Subnets (Mgmt / Trust / Untrust)
resource "aws_subnet" "fw_mgmt_1" {
  vpc_id                  = aws_vpc.fw_vpc.id
  cidr_block              = "10.20.0.0/28"
  availability_zone       = "us-west-2a"
  map_public_ip_on_launch = true
  tags = { Name = "${var.name_prefix}-fw-mgmt-1" }
}

resource "aws_subnet" "fw_trust_1" {
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.20.0.64/28"
  availability_zone = "us-west-2a"
  tags = { Name = "${var.name_prefix}-fw-trust-1" }
}

resource "aws_subnet" "fw_untrust_1" {
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.20.0.32/28"
  availability_zone = "us-west-2a"
  tags = { Name = "${var.name_prefix}-fw-untrust-1" }
}

########################################
# SECURITY GROUPS
########################################
resource "aws_security_group" "fw_mgmt_sg" {
  vpc_id = aws_vpc.fw_vpc.id
  name   = "${var.name_prefix}-fw-mgmt-sg"

  ingress { from_port = 22  to_port = 22  protocol = "tcp"  cidr_blocks = [var.admin_cidr] }
  ingress { from_port = 443 to_port = 443 protocol = "tcp"  cidr_blocks = [var.admin_cidr] }
  egress  { from_port = 0   to_port = 0   protocol = "-1"   cidr_blocks = ["0.0.0.0/0"] }
}

resource "aws_security_group" "fw_untrust_sg" {
  vpc_id = aws_vpc.fw_vpc.id
  name   = "${var.name_prefix}-fw-untrust-sg"
  egress { from_port = 0 to_port = 0 protocol = "-1" cidr_blocks = ["0.0.0.0/0"] }
}

resource "aws_security_group" "fw_trust_sg" {
  vpc_id = aws_vpc.fw_vpc.id
  name   = "${var.name_prefix}-fw-trust-sg"
  ingress { from_port = 0 to_port = 0 protocol = "-1" cidr_blocks = ["10.0.0.0/8"] }
  egress  { from_port = 0 to_port = 0 protocol = "-1" cidr_blocks = ["0.0.0.0/0"] }
}

########################################
# IAM ROLE + PROFILE (SSM Access)
########################################
resource "aws_iam_role" "fw_ssm_role" {
  name = "${var.name_prefix}-fw-ssm-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action = "sts:AssumeRole"
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
# FIREWALL INTERFACES & INSTANCE
########################################
resource "aws_network_interface" "fw_mgmt" {
  subnet_id       = aws_subnet.fw_mgmt_1.id
  security_groups = [aws_security_group.fw_mgmt_sg.id]
  tags = { Name = "${var.name_prefix}-fw-mgmt" }
}
resource "aws_network_interface" "fw_untrust" {
  subnet_id         = aws_subnet.fw_untrust_1.id
  security_groups   = [aws_security_group.fw_untrust_sg.id]
  source_dest_check = false
  tags = { Name = "${var.name_prefix}-fw-untrust" }
}
resource "aws_network_interface" "fw_trust" {
  subnet_id         = aws_subnet.fw_trust_1.id
  security_groups   = [aws_security_group.fw_trust_sg.id]
  source_dest_check = false
  tags = { Name = "${var.name_prefix}-fw-trust" }
}

resource "aws_eip" "fw_eip" {
  domain            = "vpc"
  network_interface = aws_network_interface.fw_untrust.id
  tags = { Name = "${var.name_prefix}-fw-eip" }
}

resource "aws_instance" "fw_vm" {
  ami                  = var.pan_ami_id
  instance_type        = var.pan_instance_type
  key_name             = var.pan_key_name
  iam_instance_profile = aws_iam_instance_profile.fw_ssm_profile.name

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
# FLOW LOGS + S3 (Best Practice)
########################################
resource "random_id" "suffix" { byte_length = 3 }

resource "aws_s3_bucket" "logs" {
  bucket        = "${var.name_prefix}-flowlogs-${random_id.suffix.hex}"
  force_destroy = true
  tags = { Name = "${var.name_prefix}-flowlogs" }
}

resource "aws_flow_log" "fw_vpc_logs" {
  log_destination      = aws_s3_bucket.logs.arn
  log_destination_type = "s3"
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.fw_vpc.id
  tags = { Name = "${var.name_prefix}-fw-flowlog" }
}

########################################
# PHASE 6 – TRANSIT GATEWAY INSPECTION
########################################
resource "aws_ec2_transit_gateway" "inspection_tgw" {
  description                       = "Central Inspection TGW"
  amazon_side_asn                   = 64512
  default_route_table_association   = "disable"
  default_route_table_propagation   = "disable"
  tags = {
    Name        = "${var.name_prefix}-inspection-tgw"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_ec2_transit_gateway_route_table" "inspection_rt" {
  transit_gateway_id = aws_ec2_transit_gateway.inspection_tgw.id
  tags = { Name = "${var.name_prefix}-inspection-rt" }
}
resource "aws_ec2_transit_gateway_route_table" "egress_rt" {
  transit_gateway_id = aws_ec2_transit_gateway.inspection_tgw.id
  tags = { Name = "${var.name_prefix}-egress-rt" }
}

# Attach FW VPC to TGW (Appliance Mode ON)
resource "aws_ec2_transit_gateway_vpc_attachment" "fw_attach" {
  vpc_id                  = aws_vpc.fw_vpc.id
  subnet_ids              = [aws_subnet.fw_trust_1.id]
  transit_gateway_id      = aws_ec2_transit_gateway.inspection_tgw.id
  appliance_mode_support  = "enable"
  tags = { Name = "${var.name_prefix}-fw-attach" }
}

# Example App VPC for Attachment
resource "aws_vpc" "app_vpc" {
  cidr_block = "10.30.0.0/24"
  tags = { Name = "${var.name_prefix}-app-vpc" }
}
resource "aws_subnet" "app_private_1" {
  vpc_id            = aws_vpc.app_vpc.id
  cidr_block        = "10.30.0.0/28"
  availability_zone = "us-west-2a"
  tags = { Name = "${var.name_prefix}-app-private-1" }
}
resource "aws_ec2_transit_gateway_vpc_attachment" "app_attach" {
  vpc_id             = aws_vpc.app_vpc.id
  subnet_ids         = [aws_subnet.app_private_1.id]
  transit_gateway_id = aws_ec2_transit_gateway.inspection_tgw.id
  tags = { Name = "${var.name_prefix}-app-attach" }
}

# ASSOCIATIONS
resource "aws_ec2_transit_gateway_route_table_association" "app_assoc" {
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.inspection_rt.id
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.app_attach.id
}
resource "aws_ec2_transit_gateway_route_table_association" "fw_assoc" {
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.egress_rt.id
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.fw_attach.id
}

# ROUTES
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
output "fw_public_ip"      { value = aws_eip.fw_eip.public_ip }
output "fw_private_ip"     { value = aws_instance.fw_vm.private_ip }
output "fw_vpc_id"         { value = aws_vpc.fw_vpc.id }
output "tgw_id"            { value = aws_ec2_transit_gateway.inspection_tgw.id }
output "tgw_route_tables"  {
  value = {
    inspection = aws_ec2_transit_gateway_route_table.inspection_rt.id
    egress     = aws_ec2_transit_gateway_route_table.egress_rt.id
  }
}
