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
# Mgmt VPC
resource "aws_subnet" "mgmt_public" {
  for_each = {
    "1" = "10.0.0.0/28"
    "2" = "10.0.0.16/28"
  }
  vpc_id                  = aws_vpc.mgmt_vpc.id
  cidr_block              = each.value
  availability_zone       = "us-west-2${each.key}"
  map_public_ip_on_launch = true
  tags = {
    Name        = "${var.name_prefix}-mgmt-public-${each.key}"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_subnet" "mgmt_private" {
  for_each = {
    "1" = "10.0.0.32/28"
    "2" = "10.0.0.48/28"
  }
  vpc_id            = aws_vpc.mgmt_vpc.id
  cidr_block        = each.value
  availability_zone = "us-west-2${each.key}"
  tags = {
    Name        = "${var.name_prefix}-mgmt-private-${each.key}"
    Project     = var.project_name
    Environment = var.environment
  }
}

# FW VPC
resource "aws_subnet" "fw_untrust" {
  for_each = {
    "1" = "10.0.1.0/28"
    "2" = "10.0.1.16/28"
  }
  vpc_id                  = aws_vpc.fw_vpc.id
  cidr_block              = each.value
  availability_zone       = "us-west-2${each.key}"
  map_public_ip_on_launch = true
  tags = {
    Name        = "${var.name_prefix}-fw-untrust-${each.key}"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_subnet" "fw_trust" {
  for_each = {
    "1" = "10.0.1.32/28"
    "2" = "10.0.1.48/28"
  }
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = each.value
  availability_zone = "us-west-2${each.key}"
  tags = {
    Name        = "${var.name_prefix}-fw-trust-${each.key}"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_subnet" "fw_mgmt" {
  for_each = {
    "1" = "10.0.1.64/28"
    "2" = "10.0.1.80/28"
  }
  vpc_id            = aws_vpc.fw_vpc.id
  cidr_block        = each.value
  availability_zone = "us-west-2${each.key}"
  tags = {
    Name        = "${var.name_prefix}-fw-mgmt-${each.key}"
    Project     = var.project_name
    Environment = var.environment
  }
}

# App VPC
resource "aws_subnet" "app_private" {
  for_each = {
    "1" = "10.0.2.0/28"
    "2" = "10.0.2.16/28"
  }
  vpc_id            = aws_vpc.app_vpc.id
  cidr_block        = each.value
  availability_zone = "us-west-2${each.key}"
  tags = {
    Name        = "${var.name_prefix}-app-private-${each.key}"
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
# Phase 2: Route Tables
########################
# Function to conditionally add TGW route
locals {
  add_tgw = var.tgw_id != ""
}

# Mgmt
resource "aws_route_table" "mgmt_public_rt" {
  vpc_id = aws_vpc.mgmt_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.mgmt_igw.id
  }
  tags = { Name = "${var.name_prefix}-mgmt-public-rt" }
}

resource "aws_route_table" "mgmt_private_rt" {
  vpc_id = aws_vpc.mgmt_vpc.id
  dynamic "route" {
    for_each = local.add_tgw ? [1] : []
    content {
      destination_cidr_block = "0.0.0.0/0"
      transit_gateway_id     = var.tgw_id
    }
  }
  tags = { Name = "${var.name_prefix}-mgmt-private-rt" }
}

# FW
resource "aws_route_table" "fw_untrust_rt" {
  vpc_id = aws_vpc.fw_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.fw_igw.id
  }
  tags = { Name = "${var.name_prefix}-fw-untrust-rt" }
}

resource "aws_route_table" "fw_trust_rt" {
  vpc_id = aws_vpc.fw_vpc.id
  dynamic "route" {
    for_each = local.add_tgw ? [1] : []
    content {
      destination_cidr_block = "0.0.0.0/0"
      transit_gateway_id     = var.tgw_id
    }
  }
  tags = { Name = "${var.name_prefix}-fw-trust-rt" }
}

resource "aws_route_table" "fw_mgmt_rt" {
  vpc_id = aws_vpc.fw_vpc.id
  dynamic "route" {
    for_each = local.add_tgw ? [1] : []
    content {
      destination_cidr_block = "0.0.0.0/0"
      transit_gateway_id     = var.tgw_id
    }
  }
  tags = { Name = "${var.name_prefix}-fw-mgmt-rt" }
}

# App
resource "aws_route_table" "app_private_rt" {
  vpc_id = aws_vpc.app_vpc.id
  dynamic "route" {
    for_each = local.add_tgw ? [1] : []
    content {
      destination_cidr_block = "0.0.0.0/0"
      transit_gateway_id     = var.tgw_id
    }
  }
  tags = { Name = "${var.name_prefix}-app-private-rt" }
}

########################
# Phase 2: Route Table Associations
########################
# Mgmt
resource "aws_route_table_association" "mgmt_public_assoc" {
  for_each = aws_subnet.mgmt_public
  subnet_id      = each.value.id
  route_table_id = aws_route_table.mgmt_public_rt.id
}

resource "aws_route_table_association" "mgmt_private_assoc" {
  for_each = aws_subnet.mgmt_private
  subnet_id      = each.value.id
  route_table_id = aws_route_table.mgmt_private_rt.id
}

# FW
resource "aws_route_table_association" "fw_untrust_assoc" {
  for_each = aws_subnet.fw_untrust
  subnet_id      = each.value.id
  route_table_id = aws_route_table.fw_untrust_rt.id
}

resource "aws_route_table_association" "fw_trust_assoc" {
  for_each = aws_subnet.fw_trust
  subnet_id      = each.value.id
  route_table_id = aws_route_table.fw_trust_rt.id
}

resource "aws_route_table_association" "fw_mgmt_assoc" {
  for_each = aws_subnet.fw_mgmt
  subnet_id      = each.value.id
  route_table_id = aws_route_table.fw_mgmt_rt.id
}

# App
resource "aws_route_table_association" "app_private_assoc" {
  for_each = aws_subnet.app_private
  subnet_id      = each.value.id
  route_table_id = aws_route_table.app_private_rt.id
}

########################
# Phase 2: VPC Flow Logs to CloudWatch
########################
resource "aws_iam_role" "vpc_flow_logs_role" {
  name = "${var.name_prefix}-vpc-flow-logs-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Project = var.project_name, Environment = var.environment }
}

resource "aws_iam_policy" "vpc_flow_logs_policy" {
  name        = "${var.name_prefix}-vpc-flow-logs-policy"
  description = "Allow VPC Flow Logs to publish to CloudWatch Logs"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "vpc_flow_logs_attach" {
  role       = aws_iam_role.vpc_flow_logs_role.name
  policy_arn = aws_iam_policy.vpc_flow_logs_policy.arn
}

# Log Groups
resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  for_each = {
    "mgmt" = aws_vpc.mgmt_vpc.id
    "fw"   = aws_vpc.fw_vpc.id
    "app"  = aws_vpc.app_vpc.id
  }
  name = "/${var.name_prefix}/${each.key}-vpc-flowlogs"
}

# Flow Logs
resource "aws_flow_log" "vpc_flow_logs" {
  for_each = aws_cloudwatch_log_group.vpc_flow_logs
  vpc_id               = each.key
  log_destination_type = "cloud-watch-logs"
  log_group_name       = each.value.name
  iam_role_arn         = aws_iam_role.vpc_flow_logs_role.arn
  traffic_type         = "ALL"
}
