provider "aws" {
  region = var.region
}

########################################
# VPCs
########################################

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

########################################
# Subnets
########################################

# Firewall VPC subnets
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

  tags = { Name = "${var.name_prefix}-fw-mgmt-sg" }
}
