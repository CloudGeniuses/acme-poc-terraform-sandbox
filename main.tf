########################
# Phase 1: Variables
########################

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

########################
# Provider
########################
provider "aws" {
  region = "us-west-2"  # Sandbox region as per project spec
}

########################
# Phase 2: VPCs
########################

# Management VPC
resource "aws_vpc" "mgmt_vpc" {
  cidr_block = "10.0.0.0/24"  # Management VPC CIDR
}

# Firewall VPC
resource "aws_vpc" "fw_vpc" {
  cidr_block = "10.0.1.0/24"  # Firewall VPC CIDR
}

# Application VPC
resource "aws_vpc" "app_vpc" {
  cidr_block = "10.0.2.0/24"  # Application VPC CIDR
}

########################
# Phase 2: Subnets
########################

# Management VPC Subnets
resource "aws_subnet" "mgmt_public_1" {
  vpc_id                   = aws_vpc.mgmt_vpc.id
  cidr_block               = "10.0.0.0/28"  # Public subnet AZ-A
  availability_zone        = "us-west-2a"
  map_public_ip_on_launch  = true
}

resource "aws_subnet" "mgmt_public_2" {
  vpc_id                   = aws_vpc.mgmt_vpc.id
  cidr_block               = "10.0.0.16/28"  # Public subnet AZ-B
  availability_zone        = "us-west-2b"
  map_public_ip_on_launch  = true
}

resource "aws_subnet" "mgmt_private_1" {
  vpc_id            = aws_vpc.mgmt_vpc.id
  cidr_block        = "10.0.0.32/28"  # Private subnet AZ-A
  availability_zone = "us-west-2a"
}

resource "aws_subnet" "mgmt_private_2" {
  vpc_id            = aws_vpc.mgmt_vpc.id
  cidr_block        = "10.0.0.48/28"  # Private subnet AZ-B
  availability_zone = "us-west-2b"
}

# Firewall VPC Subnets
resource "aws_subnet" "fw_untrust_1" {
  vpc_id                   = aws_vpc.fw_vpc.id
  cidr_block               = "10.0.1.0/28"  # Public/untrusted AZ-A
  availability_zone        = "us-west-2a"
  map_public_ip_on_launch  = true
}

resource "aws_subnet" "fw_untrust_2" {
  vpc_id                   = aws_vpc.fw_vpc.id
  cidr_block               = "10.0.1.16/28" # Public/untrusted AZ-B
  availability_zone        = "us-west-2b"
  map_public_ip_on_launch  = true
}

resource "aws_subnet" "fw_trust_1" {
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.0.1.32/28" # Private/trusted AZ-A
  availability_zone = "us-west-2a"
}

resource "aws_subnet" "fw_trust_2" {
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.0.1.48/28" # Private/trusted AZ-B
  availability_zone = "us-west-2b"
}

resource "aws_subnet" "fw_mgmt_1" {
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.0.1.64/28" # Firewall management AZ-A
  availability_zone = "us-west-2a"
}

resource "aws_subnet" "fw_mgmt_2" {
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.0.1.80/28" # Firewall management AZ-B
  availability_zone = "us-west-2b"
}

# Application VPC Subnets
resource "aws_subnet" "app_private_1" {
  vpc_id            = aws_vpc.app_vpc.id
  cidr_block        = "10.0.2.0/28" # App private AZ-A
  availability_zone = "us-west-2a"
}

resource "aws_subnet" "app_private_2" {
  vpc_id            = aws_vpc.app_vpc.id
  cidr_block        = "10.0.2.16/28" # App private AZ-B
  availability_zone = "us-west-2b"
}
