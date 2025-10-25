########################
# Phase 1: Provider & Variables
########################
provider "aws" {
  region = "us-west-2"
}

variable "project_name" {
  description = "Project identifier for ACME POC environment"
  type        = string
}

variable "environment" {
  description = "Indicates the environment (sandbox, dev, prod, etc.)"
  type        = string
}

variable "name_prefix" {
  description = "Prefix for consistent resource naming across resources"
  type        = string
}

# Phase-2/TGW handoff: leave empty in Phase 2; set in Phase 3
variable "tgw_id" {
  description = "Transit Gateway ID to target default routes. Leave empty in Phase 2."
  type        = string
  default     = ""
}

########################
# Phase 2: VPCs
########################

resource "aws_vpc" "mgmt_vpc" {
  cidr_block           = "10.0.0.0/24"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name        = "${var.name_prefix}-mgmt-vpc"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_vpc" "fw_vpc" {
  cidr_block           = "10.0.1.0/24"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name        = "${var.name_prefix}-fw-vpc"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_vpc" "app_vpc" {
  cidr_block           = "10.0.2.0/24"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name        = "${var.name_prefix}-app-vpc"
    Project     = var.project_name
    Environment = var.environment
  }
}

########################
# Phase 2: Subnets
########################

# Mgmt VPC Subnets
resource "aws_subnet" "mgmt_public_1" {
  vpc_id                  = aws_vpc.mgmt_vpc.id
  cidr_block              = "10.0.0.0/28"
  availability_zone       = "us-west-2a"
  map_public_ip_on_launch = true
  tags = {
    Name        = "${var.name_prefix}-mgmt-public-1"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_subnet" "mgmt_public_2" {
  vpc_id                  = aws_vpc.mgmt_vpc.id
  cidr_block              = "10.0.0.16/28"
  availability_zone       = "us-west-2b"
  map_public_ip_on_launch = true
  tags = {
    Name        = "${var.name_prefix}-mgmt-public-2"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_subnet" "mgmt_private_1" {
  vpc_id            = aws_vpc.mgmt_vpc.id
  cidr_block        = "10.0.0.32/28"
  availability_zone = "us-west-2a"
  tags = {
    Name        = "${var.name_prefix}-mgmt-private-1"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_subnet" "mgmt_private_2" {
  vpc_id            = aws_vpc.mgmt_vpc.id
  cidr_block        = "10.0.0.48/28"
  availability_zone = "us-west-2b"
  tags = {
    Name        = "${var.name_prefix}-mgmt-private-2"
    Project     = var.project_name
    Environment = var.environment
  }
}

# Firewall VPC Subnets
resource "aws_subnet" "fw_untrust_1" {
  vpc_id                  = aws_vpc.fw_vpc.id
  cidr_block              = "10.0.1.0/28"
  availability_zone       = "us-west-2a"
  map_public_ip_on_launch = true
  tags = {
    Name        = "${var.name_prefix}-fw-untrust-1"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_subnet" "fw_untrust_2" {
  vpc_id                  = aws_vpc.fw_vpc.id
  cidr_block              = "10.0.1.16/28"
  availability_zone       = "us-west-2b"
  map_public_ip_on_launch = true
  tags = {
    Name        = "${var.name_prefix}-fw-untrust-2"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_subnet" "fw_trust_1" {
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.0.1.32/28"
  availability_zone = "us-west-2a"
  tags = {
    Name        = "${var.name_prefix}-fw-trust-1"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_subnet" "fw_trust_2" {
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.0.1.48/28"
  availability_zone = "us-west-2b"
  tags = {
    Name        = "${var.name_prefix}-fw-trust-2"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_subnet" "fw_mgmt_1" {
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.0.1.64/28"
  availability_zone = "us-west-2a"
  tags = {
    Name        = "${var.name_prefix}-fw-mgmt-1"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_subnet" "fw_mgmt_2" {
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = "10.0.1.80/28"
  availability_zone = "us-west-2b"
  tags = {
    Name        = "${var.name_prefix}-fw-mgmt-2"
    Project     = var.project_name
    Environment = var.environment
  }
}

# Application VPC Subnets
resource "aws_subnet" "app_private_1" {
  vpc_id            = aws_vpc.app_vpc.id
  cidr_block        = "10.0.2.0/28"
  availability_zone = "us-west-2a"
  tags = {
    Name        = "${var.name_prefix}-app-private-1"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_subnet" "app_private_2" {
  vpc_id            = aws_vpc.app_vpc.id
  cidr_block        = "10.0.2.16/28"
  availability_zone = "us-west-2b"
  tags = {
    Name        = "${var.name_prefix}-app-private-2"
    Project     = var.project_name
    Environment = var.environment
  }
}

########################
# Phase 2: Internet Gateways
########################

resource "aws_internet_gateway" "mgmt_igw" {
  vpc_id = aws_vpc.mgmt_vpc.id
  tags = {
    Name        = "${var.name_prefix}-mgmt-igw"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_internet_gateway" "fw_igw" {
  vpc_id = aws_vpc.fw_vpc.id
  tags = {
    Name        = "${var.name_prefix}-fw-igw"
    Project     = var.project_name
    Environment = var.environment
  }
}

########################
# Phase 2: Route Tables & Associations
########################

# Mgmt public → IGW
resource "aws_route_table" "mgmt_public_rt" {
  vpc_id = aws_vpc.mgmt_vpc.id
  tags = {
    Name        = "${var.name_prefix}-mgmt-public-rt"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_route" "mgmt_public_default" {
  route_table_id         = aws_route_table.mgmt_public_rt.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.mgmt_igw.id
}

resource "aws_route_table_association" "mgmt_public_1_assoc" {
  subnet_id      = aws_subnet.mgmt_public_1.id
  route_table_id = aws_route_table.mgmt_public_rt.id
}

resource "aws_route_table_association" "mgmt_public_2_assoc" {
  subnet_id      = aws_subnet.mgmt_public_2.id
  route_table_id = aws_route_table.mgmt_public_rt.id
}

# Mgmt private → TGW
resource "aws_route_table" "mgmt_private_rt" {
  vpc_id = aws_vpc.mgmt_vpc.id
  tags = {
    Name        = "${var.name_prefix}-mgmt-private-rt"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_route" "mgmt_private_default" {
  count                  = var.tgw_id == "" ? 0 : 1
  route_table_id         = aws_route_table.mgmt_private_rt.id
  destination_cidr_block = "0.0.0.0/0"
  transit_gateway_id     = var.tgw_id
}

resource "aws_route_table_association" "mgmt_private_1_assoc" {
  subnet_id      = aws_subnet.mgmt_private_1.id
  route_table_id = aws_route_table.mgmt_private_rt.id
}

resource "aws_route_table_association" "mgmt_private_2_assoc" {
  subnet_id      = aws_subnet.mgmt_private_2.id
  route_table_id = aws_route_table.mgmt_private_rt.id
}

# FW untrust → IGW
resource "aws_route_table" "fw_untrust_rt" {
  vpc_id = aws_vpc.fw_vpc.id
  tags = {
    Name        = "${var.name_prefix}-fw-untrust-rt"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_route" "fw_untrust_default" {
  route_table_id         = aws_route_table.fw_untrust_rt.id
  destination_cidr_block = "0
