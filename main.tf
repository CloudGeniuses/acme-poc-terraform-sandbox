########################
# Phase 1: Provider & Variables
########################

# AWS provider
provider "aws" {
  region = "us-west-2"
}

# Project identifier
variable "project_name" {
  description = "Project identifier for ACME POC environment"
  type        = string
}

# Environment (sandbox/dev/prod)
variable "environment" {
  description = "Indicates the environment (sandbox, dev, prod, etc.)"
  type        = string
}

# Prefix for consistent resource naming
variable "name_prefix" {
  description = "Prefix for consistent resource naming across resources"
  type        = string
}

########################
# Phase 2: VPCs
########################

# Management VPC
resource "aws_vpc" "mgmt_vpc" {
  cidr_block = "10.0.0.0/24"
  tags = {
    Name = "${var.name_prefix}-mgmt-vpc"
  }
}

# Firewall VPC
resource "aws_vpc" "fw_vpc" {
  cidr_block = "10.0.1.0/24"
  tags = {
    Name = "${var.name_prefix}-fw-vpc"
  }
}

# Application VPC
resource "aws_vpc" "app_vpc" {
  cidr_block = "10.0.2.0/24"
  tags = {
    Name = "${var.name_prefix}-app-vpc"
  }
}

########################
# Phase 2: Subnets
########################

# Management VPC Subnets
resource "aws_subnet" "mgmt_public_1" {
  vpc_id                  = aws_vpc.mgmt_vpc.id
  cidr_block              = "10.0.0.0/28"
  availability_zone       = "us-west-2a"
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.name_prefix}-mgmt-public-1"
  }
}

resource "aws_subnet" "mgmt_public_2" {
  vpc_id                  = aws_vpc.mgmt_vpc.id
  cidr_block              = "10.0.0.16/28"
  availability_zone       = "us-west-2b"
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.name_prefix}-mgmt-public-2"
  }
}

resource "aws_subnet" "mgmt_private_1" {
  vpc_id            = aws_vpc.mgmt_vpc.id
  cidr_block        = "10.0.0.32/28"
  availability_zone = "us-west-2a"
  tags = {
    Name = "${var.name_prefix}-mgmt-private-1"
  }
}

resource "aws_subnet" "mgmt_private_2" {
  vpc_id            = aws_vpc.mgmt_vpc.id
  cidr_block        = "10.0.0.48/28"
  availability_zone = "us-west-2b"
  tags = {
    Name = "${var.name_prefix}-mgmt-private-2"
  }
}

# Firewall VPC Subnets
resource "aws_subnet" "fw_untrust_1" {
  vpc_id                  = aws_vpc.fw_vpc.id
  cidr_block              = "10.0.1.0/28"
  availability_zone       = "us-west-2a"
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.name_prefix}-fw-untrust-1"
  }
}

resource "aws_subnet" "fw_untrust_2" {
  vpc_id                  = aws_vpc.fw_vpc.id
  cidr_block              = "10.0.1.16/28"
  availability_zone       = "us-west-2b"
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.name_prefix}-fw-untrust-2"
  }
}

resource "aws_subnet" "fw_trust_1" {
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.0.1.32/28"
  availability_zone = "us-west-2a"
  tags = {
    Name = "${var.name_prefix}-fw-trust-1"
  }
}

resource "aws_subnet" "fw_trust_2" {
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.0.1.48/28"
  availability_zone = "us-west-2b"
  tags = {
    Name = "${var.name_prefix}-fw-trust-2"
  }
}

resource "aws_subnet" "fw_mgmt_1" {
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.0.1.64/28"
  availability_zone = "us-west-2a"
  tags = {
    Name = "${var.name_prefix}-fw-mgmt-1"
  }
}

resource "aws_subnet" "fw_mgmt_2" {
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.0.1.80/28"
  availability_zone = "us-west-2b"
  tags = {
    Name = "${var.name_prefix}-fw-mgmt-2"
  }
}

# Application VPC Subnets
resource "aws_subnet" "app_private_1" {
  vpc_id            = aws_vpc.app_vpc.id
  cidr_block        = "10.0.2.0/28"
  availability_zone = "us-west-2a"
  tags = {
    Name = "${var.name_prefix}-app-private-1"
  }
}

resource "aws_subnet" "app_private_2" {
  vpc_id            = aws_vpc.app_vpc.id
  cidr_block        = "10.0.2.16/28"
  availability_zone = "us-west-2b"
  tags = {
    Name = "${var.name_prefix}-app-private-2"
  }
}
