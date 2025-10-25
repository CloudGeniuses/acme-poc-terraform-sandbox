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

# If you want to BYO TGW, set this; otherwise we'll create one in Phase 3 and use it.
variable "tgw_id" {
  description = "Transit Gateway ID to target default routes. Leave empty to create a new TGW."
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

# Firewall VPC
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

# Application VPC
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
# Phase 3: Transit Gateway & Inspection
########################

# Create a TGW if not provided via var.tgw_id; we will always reference local.effective_tgw_id below.
resource "aws_ec2_transit_gateway" "poc_tgw" {
  count                           = var.tgw_id == "" ? 1 : 0
  description                     = "ACME POC TGW"
  default_route_table_association = "disable"
  default_route_table_propagation = "disable"
  dns_support                     = "enable"
  vpn_ecmp_support                = "enable"
  tags = {
    Name        = "${var.name_prefix}-tgw"
    Project     = var.project_name
    Environment = var.environment
  }
}

# Pick user-provided TGW or the one we just created.
locals {
  effective_tgw_id = var.tgw_id != "" ? var.tgw_id : (length(aws_ec2_transit_gateway.poc_tgw) > 0 ? aws_ec2_transit_gateway.poc_tgw[0].id : "")
}

# VPC Attachments (Mgmt/App/FW-trust)
resource "aws_ec2_transit_gateway_vpc_attachment" "att_mgmt" {
  transit_gateway_id = local.effective_tgw_id
  vpc_id             = aws_vpc.mgmt_vpc.id
  subnet_ids         = [aws_subnet.mgmt_private_1.id, aws_subnet.mgmt_private_2.id]
  dns_support        = "enable"
  tags = {
    Name        = "${var.name_prefix}-tgw-att-mgmt"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "att_app" {
  transit_gateway_id = local.effective_tgw_id
  vpc_id             = aws_vpc.app_vpc.id
  subnet_ids         = [aws_subnet.app_private_1.id, aws_subnet.app_private_2.id]
  dns_support        = "enable"
  tags = {
    Name        = "${var.name_prefix}-tgw-att-app"
    Project     = var.project_name
    Environment = var.environment
  }
}

# Firewall VPC attachment — Appliance Mode ENABLED
resource "aws_ec2_transit_gateway_vpc_attachment" "att_fw" {
  transit_gateway_id     = local.effective_tgw_id
  vpc_id                 = aws_vpc.fw_vpc.id
  subnet_ids             = [aws_subnet.fw_trust_1.id, aws_subnet.fw_trust_2.id]
  dns_support            = "enable"
  appliance_mode_support = "enable"
  tags = {
    Name        = "${var.name_prefix}-tgw-att-fw"
    Project     = var.project_name
    Environment = var.environment
  }
}

# TGW Route Tables
resource "aws_ec2_transit_gateway_route_table" "rt_spokes" {
  transit_gateway_id = local.effective_tgw_id
  tags = {
    Name        = "${var.name_prefix}-tgw-rt-spokes"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_ec2_transit_gateway_route_table" "rt_firewall" {
  transit_gateway_id = local.effective_tgw_id
  tags = {
    Name        = "${var.name_prefix}-tgw-rt-firewall"
    Project     = var.project_name
    Environment = var.environment
  }
}

# Associations: spokes (mgmt/app) → spoke RT ; firewall → firewall RT
resource "aws_ec2_transit_gateway_route_table_association" "assoc_mgmt" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.att_mgmt.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.rt_spokes.id
}

resource "aws_ec2_transit_gateway_route_table_association" "assoc_app" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.att_app.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.rt_spokes.id
}

resource "aws_ec2_transit_gateway_route_table_association" "assoc_fw" {
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.att_fw.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.rt_firewall.id
}

# TGW Routes
# Spoke RT: send default to firewall
resource "aws_ec2_transit_gateway_route" "spokes_default_to_fw" {
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.rt_spokes.id
  destination_cidr_block         = "0.0.0.0/0"
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.att_fw.id
}

# Firewall RT: return routes to spokes
resource "aws_ec2_transit_gateway_route" "fw_to_mgmt" {
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.rt_firewall.id
  destination_cidr_block         = "10.0.0.0/24"
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.att_mgmt.id
}

resource "aws_ec2_transit_gateway_route" "fw_to_app" {
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.rt_firewall.id
  destination_cidr_block         = "10.0.2.0/24"
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.att_app.id
}

########################
# Phase 2: Route Tables & Routes (VPC side)
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
  route_table_id         = aws_route_table.mgmt_private_rt.id
  destination_cidr_block = "0.0.0.0/0"
  transit_gateway_id     = local.effective_tgw_id
}

resource "aws_route_table_association" "mgmt_private_1_assoc" {
  subnet_id      = aws_subnet.mgmt_private_1.id
  route_table_id = aws_route_table.mgmt_private_rt.id
}

resource "aws_route_table_association" "mgmt_private_2_assoc" {
  subnet_id      = aws_subnet.mgmt_private_2.id
  route_table_id = aws_route_table.mgmt_private_rt.id
}

# FW VPC: Untrust (public) → IGW
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
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.fw_igw.id
}

resource "aws_route_table_association" "fw_untrust_1_assoc" {
  subnet_id      = aws_subnet.fw_untrust_1.id
  route_table_id = aws_route_table.fw_untrust_rt.id
}

resource "aws_route_table_association" "fw_untrust_2_assoc" {
  subnet_id      = aws_subnet.fw_untrust_2.id
  route_table_id = aws_route_table.fw_untrust_rt.id
}

# FW VPC: Trust + Mgmt (private) → TGW
resource "aws_route_table" "fw_trust_rt" {
  vpc_id = aws_vpc.fw_vpc.id
  tags = {
    Name        = "${var.name_prefix}-fw-trust-rt"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_route" "fw_trust_default" {
  route_table_id         = aws_route_table.fw_trust_rt.id
  destination_cidr_block = "0.0.0.0/0"
  transit_gateway_id     = local.effective_tgw_id
}

resource "aws_route_table_association" "fw_trust_1_assoc" {
  subnet_id      = aws_subnet.fw_trust_1.id
  route_table_id = aws_route_table.fw_trust_rt.id
}

resource "aws_route_table_association" "fw_trust_2_assoc" {
  subnet_id      = aws_subnet.fw_trust_2.id
  route_table_id = aws_route_table.fw_trust_rt.id
}

resource "aws_route_table" "fw_mgmt_rt" {
  vpc_id = aws_vpc.fw_vpc.id
  tags = {
    Name        = "${var.name_prefix}-fw-mgmt-rt"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_route" "fw_mgmt_default" {
  route_table_id         = aws_route_table.fw_mgmt_rt.id
  destination_cidr_block = "0.0.0.0/0"
  transit_gateway_id     = local.effective_tgw_id
}

resource "aws_route_table_association" "fw_mgmt_1_assoc" {
  subnet_id      = aws_subnet.fw_mgmt_1.id
  route_table_id = aws_route_table.fw_mgmt_rt.id
}

resource "aws_route_table_association" "fw_mgmt_2_assoc" {
  subnet_id      = aws_subnet.fw_mgmt_2.id
  route_table_id = aws_route_table.fw_mgmt_rt.id
}

# APP VPC: Private → TGW
resource "aws_route_table" "app_private_rt" {
  vpc_id = aws_vpc.app_vpc.id
  tags = {
    Name        = "${var.name_prefix}-app-private-rt"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_route" "app_private_default" {
  route_table_id         = aws_route_table.app_private_rt.id
  destination_cidr_block = "0.0.0.0/0"
  transit_gateway_id     = local.effective_tgw_id
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
# Outputs
########################
output "tgw_id" {
  value = local.effective_tgw_id
}

output "tgw_attachments" {
  value = {
    mgmt = aws_ec2_transit_gateway_vpc_attachment.att_mgmt.id
    app  = aws_ec2_transit_gateway_vpc_attachment.att_app.id
    fw   = aws_ec2_transit_gateway_vpc_attachment.att_fw.id
  }
}

output "route_tables" {
  value = {
    mgmt_public = {
      id   = aws_route_table.mgmt_public_rt.id
      name = aws_route_table.mgmt_public_rt.tags["Name"]
    }
    mgmt_private = {
      id   = aws_route_table.mgmt_private_rt.id
      name = aws_route_table.mgmt_private_rt.tags["Name"]
    }
    fw_untrust = {
      id   = aws_route_table.fw_untrust_rt.id
      name = aws_route_table.fw_untrust_rt.tags["Name"]
    }
    fw_trust = {
      id   = aws_route_table.fw_trust_rt.id
      name = aws_route_table.fw_trust_rt.tags["Name"]
    }
    fw_mgmt = {
      id   = aws_route_table.fw_mgmt_rt.id
      name = aws_route_table.fw_mgmt_rt.tags["Name"]
    }
    app_private = {
      id   = aws_route_table.app_private_rt.id
      name = aws_route_table.app_private_rt.tags["Name"]
    }
  }
}
