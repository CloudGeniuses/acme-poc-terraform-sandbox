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

# Management VPC Subnets
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

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.mgmt_igw.id
  }
}

resource "aws_route_table_association" "mgmt_public_1_assoc" {
  subnet_id      = aws_subnet.mgmt_public_1.id
  route_table_id = aws_route_table.mgmt_public_rt.id
}
resource "aws_route_table_association" "mgmt_public_2_assoc" {
  subnet_id      = aws_subnet.mgmt_public_2.id
  route_table_id = aws_route_table.mgmt_public_rt.id
}

# Mgmt private → TGW (route added only if tgw_id provided)
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

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.fw_igw.id
  }
}
resource "aws_route_table_association" "fw_untrust_1_assoc" {
  subnet_id      = aws_subnet.fw_untrust_1.id
  route_table_id = aws_route_table.fw_untrust_rt.id
}
resource "aws_route_table_association" "fw_untrust_2_assoc" {
  subnet_id      = aws_subnet.fw_untrust_2.id
  route_table_id = aws_route_table.fw_untrust_rt.id
}

# FW trust → TGW
resource "aws_route_table" "fw_trust_rt" {
  vpc_id = aws_vpc.fw_vpc.id
  tags = {
    Name        = "${var.name_prefix}-fw-trust-rt"
    Project     = var.project_name
    Environment = var.environment
  }
}
resource "aws_route" "fw_trust_default" {
  count                  = var.tgw_id == "" ? 0 : 1
  route_table_id         = aws_route_table.fw_trust_rt.id
  destination_cidr_block = "0.0.0.0/0"
  transit_gateway_id     = var.tgw_id
}
resource "aws_route_table_association" "fw_trust_1_assoc" {
  subnet_id      = aws_subnet.fw_trust_1.id
  route_table_id = aws_route_table.fw_trust_rt.id
}
resource "aws_route_table_association" "fw_trust_2_assoc" {
  subnet_id      = aws_subnet.fw_trust_2.id
  route_table_id = aws_route_table.fw_trust_rt.id
}

# FW mgmt → TGW
resource "aws_route_table" "fw_mgmt_rt" {
  vpc_id = aws_vpc.fw_vpc.id
  tags = {
    Name        = "${var.name_prefix}-fw-mgmt-rt"
    Project     = var.project_name
    Environment = var.environment
  }
}
resource "aws_route" "fw_mgmt_default" {
  count                  = var.tgw_id == "" ? 0 : 1
  route_table_id         = aws_route_table.fw_mgmt_rt.id
  destination_cidr_block = "0.0.0.0/0"
  transit_gateway_id     = var.tgw_id
}
resource "aws_route_table_association" "fw_mgmt_1_assoc" {
  subnet_id      = aws_subnet.fw_mgmt_1.id
  route_table_id = aws_route_table.fw_mgmt_rt.id
}
resource "aws_route_table_association" "fw_mgmt_2_assoc" {
  subnet_id      = aws_subnet.fw_mgmt_2.id
  route_table_id = aws_route_table.fw_mgmt_rt.id
}

# App private → TGW
resource "aws_route_table" "app_private_rt" {
  vpc_id = aws_vpc.app_vpc.id
  tags = {
    Name        = "${var.name_prefix}-app-private-rt"
    Project     = var.project_name
    Environment = var.environment
  }
}
resource "aws_route" "app_private_default" {
  count                  = var.tgw_id == "" ? 0 : 1
  route_table_id         = aws_route_table.app_private_rt.id
  destination_cidr_block = "0.0.0.0/0"
  transit_gateway_id     = var.tgw_id
}
resource "aws_route_table_association" "app_private_1_assoc" {
  subnet_id      = aws_subnet.app_private_1.id
  route_table_id = aws_route_table.app_private_rt.id
}
resource "aws_route_table_association" "app_private_2_assoc" {
  subnet_id      = aws_subnet.app_private_2.id
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
  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_iam_policy" "vpc_flow_logs_policy" {
  name        = "${var.name_prefix}-vpc-flow-logs-policy"
  description = "Allow VPC Flow Logs to publish to CloudWatch Logs"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
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

resource "aws_cloudwatch_log_group" "mgmt_vpc_flow" {
  name = "/${var.name_prefix}/mgmt-vpc-flowlogs"
}
resource "aws_cloudwatch_log_group" "fw_vpc_flow" {
  name = "/${var.name_prefix}/fw-vpc-flowlogs"
}
resource "aws_cloudwatch_log_group" "app_vpc_flow" {
  name = "/${var.name_prefix}/app-vpc-flowlogs"
}

resource "aws_flow_log" "mgmt_vpc" {
  vpc_id               = aws_vpc.mgmt_vpc.id
  log_destination_type = "cloud-watch-logs"
  log_group_name       = aws_cloudwatch_log_group.mgmt_vpc_flow.name
  iam_role_arn         = aws_iam_role.vpc_flow_logs_role.arn
  traffic_type         = "ALL"
}

resource "aws_flow_log" "fw_vpc" {
  vpc_id               = aws_vpc.fw_vpc.id
  log_destination_type = "cloud-watch-logs"
  log_group_name       = aws_cloudwatch_log_group.fw_vpc_flow.name
  iam_role_arn         = aws_iam_role.vpc_flow_logs_role.arn
  traffic_type         = "ALL"
}

resource "aws_flow_log" "app_vpc" {
  vpc_id               = aws_vpc.app_vpc.id
  log_destination_type = "cloud-watch-logs"
  log_group_name       = aws_cloudwatch_log_group.app_vpc_flow.name
  iam_role_arn         = aws_iam_role.vpc_flow_logs_role.arn
  traffic_type         = "ALL"
}
