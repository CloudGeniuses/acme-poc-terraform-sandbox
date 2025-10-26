########################################
# AWS TGW + GWLB Centralized Inspection – Best Practice
# Phases 1–5 (production-ready, Terraform Cloud compatible)
########################################

########################################
# PROVIDER
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

variable "tgw_id" {
  type        = string
  default     = ""
  description = "Optional existing TGW ID"
}

variable "fw_ami_id" {
  description = "AMI ID for Palo Alto VM-Series firewall"
  type        = string
}

variable "fw_instance_type" {
  description = "Firewall instance type"
  type        = string
  default     = "c6i.large"
}

variable "fw_key_name" {
  description = "SSH key pair for mgmt access"
  type        = string
  default     = null
}

variable "fw_desired_capacity" {
  description = "Firewall instances per AZ"
  type        = number
  default     = 1
}

variable "fw_bootstrap_user_data" {
  description = "Base64-encoded user_data (if not using S3)"
  type        = string
  default     = null
}

variable "enable_s3_bootstrap" {
  description = "Enable S3-based bootstrap"
  type        = bool
  default     = true
}

variable "bootstrap_s3_bucket" {
  description = "S3 bucket for bootstrap files"
  type        = string
}

variable "bootstrap_s3_prefix" {
  description = "Prefix within S3 bootstrap bucket"
  type        = string
  default     = "bootstrap"
}

variable "log_s3_bucket_name" {
  description = "S3 bucket for flow/GWLB/TGW logs"
  type        = string
}

variable "fw_enable_flow_logs" {
  description = "Enable VPC flow logs for all VPCs"
  type        = bool
  default     = true
}

variable "admin_cidr" {
  description = "Public IP CIDR allowed for mgmt SSH/GUI"
  type        = string
}

########################################
# ASSUMED EXISTING VPCS & SUBNETS
# mgmt_vpc, fw_vpc, app_vpc, their subnets, TGW, etc.
########################################

########################################
# PHASE 4 – GWLB & INSPECTION PLANE
########################################
# Security Groups
resource "aws_security_group" "fw_trust_sg" {
  name        = "${var.name_prefix}-fw-trust-sg"
  description = "Trust side SG"
  vpc_id      = aws_vpc.fw_vpc.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [aws_vpc.mgmt_vpc.cidr_block, aws_vpc.app_vpc.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.name_prefix}-fw-trust-sg"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_security_group" "fw_untrust_sg" {
  name        = "${var.name_prefix}-fw-untrust-sg"
  description = "Untrust side SG"
  vpc_id      = aws_vpc.fw_vpc.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.name_prefix}-fw-untrust-sg"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_security_group" "fw_mgmt_sg" {
  name        = "${var.name_prefix}-fw-mgmt-sg"
  description = "Mgmt SG (locked to admin CIDR)"
  vpc_id      = aws_vpc.fw_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
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

# GWLB
resource "aws_lb" "gwlb" {
  name               = "${var.name_prefix}-gwlb"
  load_balancer_type = "gateway"

  subnet_mappings { subnet_id = aws_subnet.fw_trust_1.id }
  subnet_mappings { subnet_id = aws_subnet.fw_trust_2.id }

  tags = {
    Name        = "${var.name_prefix}-gwlb"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_lb_target_group" "gwlb_tg" {
  name        = "${var.name_prefix}-gwlb-tg"
  port        = 6081
  protocol    = "GENEVE"
  vpc_id      = aws_vpc.fw_vpc.id
  target_type = "instance"

  health_check {
    port     = "traffic-port"
    protocol = "TCP"
  }

  tags = {
    Name        = "${var.name_prefix}-gwlb-tg"
    Project     = var.project_name
    Environment = var.environment
  }
}

# Firewall ENIs + Instances (AZ-A/B)
# (same as your previous validated configuration)
# ...
# (include all fw_a_mgmt/trust/untrust, fw_b_*, instance definitions, and attachments)
# ...

# Endpoint Service & GWLBe
locals {
  gwlb_service_name = aws_vpc_endpoint_service.gwlb_service.service_name
}

resource "aws_vpc_endpoint_service" "gwlb_service" {
  acceptance_required        = false
  gateway_load_balancer_arns = [aws_lb.gwlb.arn]
  tags = {
    Name        = "${var.name_prefix}-gwlb-svc"
    Project     = var.project_name
    Environment = var.environment
  }
}

# (Keep your GWLBe endpoint resources & routes unchanged)
# ...

########################################
# PHASE 5 – HARDENING & LOGGING
########################################
# SSM IAM Role + Profile
data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ssm_role" {
  name               = "${var.name_prefix}-ssm-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ssm_instance_profile" {
  name = "${var.name_prefix}-ssm-instance-profile"
  role = aws_iam_role.ssm_role.name
}

# Flow Logs
resource "aws_flow_log" "mgmt_vpc_fl" {
  count                  = var.fw_enable_flow_logs ? 1 : 0
  log_destination        = aws_s3_bucket.logs.arn
  log_destination_type   = "s3"
  traffic_type           = "ALL"
  vpc_id                 = aws_vpc.mgmt_vpc.id
  deliver_logs_permission_arn = null
  tags = {
    Name        = "${var.name_prefix}-mgmt-vpc-flow"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_flow_log" "app_vpc_fl" {
  count                  = var.fw_enable_flow_logs ? 1 : 0
  log_destination        = aws_s3_bucket.logs.arn
  log_destination_type   = "s3"
  traffic_type           = "ALL"
  vpc_id                 = aws_vpc.app_vpc.id
  deliver_logs_permission_arn = null
  tags = {
    Name        = "${var.name_prefix}-app-vpc-flow"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_flow_log" "fw_vpc_fl" {
  count                  = var.fw_enable_flow_logs ? 1 : 0
  log_destination        = aws_s3_bucket.logs.arn
  log_destination_type   = "s3"
  traffic_type           = "ALL"
  vpc_id                 = aws_vpc.fw_vpc.id
  deliver_logs_permission_arn = null
  tags = {
    Name        = "${var.name_prefix}-fw-vpc-flow"
    Project     = var.project_name
    Environment = var.environment
  }
}

# CloudWatch Alarms (as in previous version)
# ...

########################################
# OUTPUTS
########################################
output "gwlb_arn"              { value = aws_lb.gwlb.arn }
output "gwlb_tg_arn"           { value = aws_lb_target_group.gwlb_tg.arn }
output "gwlb_service_name"     { value = aws_vpc_endpoint_service.gwlb_service.service_name }
output "fw_instance_ids"       { value = [aws_instance.fw_a.id, aws_instance.fw_b.id] }
output "mgmt_gwlbe_ids"        { value = [aws_vpc_endpoint.mgmt_gwlbe_a.id, aws_vpc_endpoint.mgmt_gwlbe_b.id] }
output "app_gwlbe_ids"         { value = [aws_vpc_endpoint.app_gwlbe_a.id,  aws_vpc_endpoint.app_gwlbe_b.id] }
