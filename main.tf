########################################
# AWS TGW + GWLB Centralized Inspection – Best Practice
# Phases 1–5 in one file (modular-friendly)
# Notes:
# - Builds on your existing Phase 1–3 objects
# - Adds Phase 4 (GWLB + Endpoint Service + GWLBe) and Phase 5 (hardening/logging)
# - Includes Palo Alto (or other NVA) placeholder instances with 3 ENIs (mgmt/trust/untrust)
# - Replace PLACEHOLDER values (AMI, bootstrap, PAN license, etc.) before apply
########################################

########################################
# PHASE 0 – PROVIDER & COMMON (uses your existing provider/vars)
########################################
provider "aws" {
  region = var.region
}

variable "region" { type = string  default = "us-west-2" }

variable "project_name" { type = string }
variable "environment" { type = string }
variable "name_prefix" { type = string }

# Admin CIDR for mgmt access (SSH/HTTPS)
variable "admin_cidr" {
  description = "Admin IP/CIDR allowed to reach firewall mgmt"
  type        = string
}

# BYO TGW optional (already present in your file)
variable "tgw_id" { type = string default = "" }

# Enable/disable VPC Flow Logs from workspace
variable "fw_enable_flow_logs" {
  description = "Whether to enable VPC flow logs"
  type        = bool
  default     = true
}

# NEW: NGFW / NVA variables
variable "fw_ami_id" {
  description = "AMI ID for Palo Alto (or other NVA). Ensure marketplace terms accepted."
  type        = string
}

variable "fw_instance_type" {
  description = "Instance type for firewall."
  type        = string
  default     = "c6i.large"
}

variable "fw_key_name" {
  description = "Optional SSH key pair name for firewall mgmt access."
  type        = string
  default     = null
}

variable "fw_desired_capacity" {
  description = "Number of firewall instances (per AZ)."
  type        = number
  default     = 1
}

variable "fw_bootstrap_user_data" {
  description = "Base64-encoded bootstrap/user-data for the firewall (PAN-OS init, licenses)."
  type        = string
  default     = null
}

# Logging
variable "log_s3_bucket_name" {
  description = "S3 bucket for flow/GWLB/TGW logs."
  type        = string
}

# Bootstrap (S3-based pointer OR inline user_data)
variable "enable_s3_bootstrap" {
  description = "If true, pass S3 bootstrap pointer to PAN-OS via user_data; else use fw_bootstrap_user_data"
  type        = bool
  default     = true
}
variable "bootstrap_s3_bucket" {
  description = "Existing S3 bucket that hosts /bootstrap/{config,content,license,software}"
  type        = string
  default     = ""
}
variable "bootstrap_s3_prefix" {
  description = "Prefix under the bucket that contains bootstrap files (default: bootstrap)"
  type        = string
  default     = "bootstrap"
}

locals {
  pan_bootstrap_string = "bootstrap-aws-s3-bucket=${var.bootstrap_s3_bucket};bootstrap-aws-s3-prefix=${var.bootstrap_s3_prefix}"
  pan_bootstrap_b64    = base64encode(local.pan_bootstrap_string)
}

########################################
# ASSUMED EXISTING (FROM YOUR FILE):
# - VPCs: mgmt_vpc, fw_vpc, app_vpc
# - Subnets: mgmt_* (pub/priv), fw_* (untrust/trust/mgmt), app_private_*
# - IGWs: mgmt_igw, fw_igw
# - TGW + attachments + TGW route tables + associations
# - Spoke route tables (you created), etc.
# Keep those intact. We will add GWLB and adjust spoke VPC routes for 0.0.0.0/0 to GWLBe.
########################################

########################################
# PHASE 4 – INSPECTION DATA PLANE (GWLB + Endpoint Service + GWLBe)
########################################
# 4.1 Security groups for firewall ENIs (least privilege placeholders)
resource "aws_security_group" "fw_trust_sg" {
  name        = "${var.name_prefix}-fw-trust-sg"
  description = "Trust side SG"
  vpc_id      = aws_vpc.fw_vpc.id
  tags = { Name = "${var.name_prefix}-fw-trust-sg", Project = var.project_name, Environment = var.environment }

  ingress { from_port = 0 to_port = 0 protocol = "-1" cidr_blocks = [aws_vpc.mgmt_vpc.cidr_block, aws_vpc.app_vpc.cidr_block] }
  egress  { from_port = 0 to_port = 0 protocol = "-1" cidr_blocks = ["0.0.0.0/0"] }
}

resource "aws_security_group" "fw_untrust_sg" {
  name        = "${var.name_prefix}-fw-untrust-sg"
  description = "Untrust side SG"
  vpc_id      = aws_vpc.fw_vpc.id
  tags = { Name = "${var.name_prefix}-fw-untrust-sg", Project = var.project_name, Environment = var.environment }

  ingress { from_port = 0 to_port = 0 protocol = "-1" cidr_blocks = ["0.0.0.0/0"] }
  egress  { from_port = 0 to_port = 0 protocol = "-1" cidr_blocks = ["0.0.0.0/0"] }
}

resource "aws_security_group" "fw_mgmt_sg" {
  name        = "${var.name_prefix}-fw-mgmt-sg"
  description = "Mgmt side SG (lock down to your admin IPs + Client VPN)"
  vpc_id      = aws_vpc.fw_vpc.id
  tags = { Name = "${var.name_prefix}-fw-mgmt-sg", Project = var.project_name, Environment = var.environment }

  # Direct admin /32 (retain if you still want direct access without VPN)
  ingress { from_port = 22 to_port = 22 protocol = "tcp" cidr_blocks = [var.admin_cidr] description = "SSH from admin /32" }

  # Allow GUI/SSH from the Client VPN security group (preferred)
  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.vpn_to_fw_mgmt_sg.id]
    description     = "GUI (HTTPS) from Client VPN"
  }
  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.vpn_to_fw_mgmt_sg.id]
    description     = "SSH from Client VPN"
  }

  egress  { from_port = 0  to_port = 0  protocol = "-1" cidr_blocks = ["0.0.0.0/0"] }
}


# 4.2 GWLB in the FW VPC (in trust subnets – traffic arrives via GWLBe)
resource "aws_lb" "gwlb" {
  name               = "${var.name_prefix}-gwlb"
  load_balancer_type = "gateway"

  subnet_mappings {
    subnet_id = aws_subnet.fw_trust_1.id
  }
  subnet_mappings {
    subnet_id = aws_subnet.fw_trust_2.id
  }

  tags = { Name = "${var.name_prefix}-gwlb", Project = var.project_name, Environment = var.environment }
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

  tags = { Name = "${var.name_prefix}-gwlb-tg", Project = var.project_name, Environment = var.environment }
}

# 4.3 Firewall instances (per AZ) with 3 ENIs (mgmt, trust, untrust)
#    NOTE: For production, consider ASG with lifecycle hooks; many NGFWs don’t support ASG well. Use instance set + scripts.
resource "aws_network_interface" "fw_a_mgmt" {
  subnet_id       = aws_subnet.fw_mgmt_1.id
  security_groups = [aws_security_group.fw_mgmt_sg.id]
  tags = { Name = "${var.name_prefix}-fw-a-mgmt", Project = var.project_name, Environment = var.environment }
}
resource "aws_network_interface" "fw_a_trust" {
  subnet_id       = aws_subnet.fw_trust_1.id
  security_groups = [aws_security_group.fw_trust_sg.id]
  tags = { Name = "${var.name_prefix}-fw-a-trust", Project = var.project_name, Environment = var.environment }
}
resource "aws_network_interface" "fw_a_untrust" {
  subnet_id       = aws_subnet.fw_untrust_1.id
  security_groups = [aws_security_group.fw_untrust_sg.id]
  tags = { Name = "${var.name_prefix}-fw-a-untrust", Project = var.project_name, Environment = var.environment }
}

resource "aws_instance" "fw_a" {
  ami                         = var.fw_ami_id
  instance_type               = var.fw_instance_type
  key_name                    = var.fw_key_name
  # If enable_s3_bootstrap=true and bucket name provided, pass S3 pointer; else use inline fw_bootstrap_user_data (can be null)
  user_data_base64            = var.enable_s3_bootstrap && var.bootstrap_s3_bucket != "" ? local.pan_bootstrap_b64 : var.fw_bootstrap_user_data
  iam_instance_profile        = aws_iam_instance_profile.ssm_instance_profile.name
  disable_api_stop            = false
  disable_api_termination     = false
  ebs_optimized               = true
  monitoring                  = true

  network_interface {
    device_index         = 0
    network_interface_id = aws_network_interface.fw_a_mgmt.id
  }
  network_interface {
    device_index         = 1
    network_interface_id = aws_network_interface.fw_a_trust.id
  }
  network_interface {
    device_index         = 2
    network_interface_id = aws_network_interface.fw_a_untrust.id
  }

  tags = { Name = "${var.name_prefix}-fw-a", Project = var.project_name, Environment = var.environment }
}

# AZ-b
resource "aws_network_interface" "fw_b_mgmt" {
  subnet_id       = aws_subnet.fw_mgmt_2.id
  security_groups = [aws_security_group.fw_mgmt_sg.id]
  tags = { Name = "${var.name_prefix}-fw-b-mgmt", Project = var.project_name, Environment = var.environment }
}
resource "aws_network_interface" "fw_b_trust" {
  subnet_id       = aws_subnet.fw_trust_2.id
  security_groups = [aws_security_group.fw_trust_sg.id]
  tags = { Name = "${var.name_prefix}-fw-b-trust", Project = var.project_name, Environment = var.environment }
}
resource "aws_network_interface" "fw_b_untrust" {
  subnet_id       = aws_subnet.fw_untrust_2.id
  security_groups = [aws_security_group.fw_untrust_sg.id]
  tags = { Name = "${var.name_prefix}-fw-b-untrust", Project = var.project_name, Environment = var.environment }
}

resource "aws_instance" "fw_b" {
  ami                  = var.fw_ami_id
  instance_type        = var.fw_instance_type
  key_name             = var.fw_key_name
  # If enable_s3_bootstrap=true and bucket name provided, pass S3 pointer; else use inline fw_bootstrap_user_data
  user_data_base64     = var.enable_s3_bootstrap && var.bootstrap_s3_bucket != "" ? local.pan_bootstrap_b64 : var.fw_bootstrap_user_data
  iam_instance_profile = aws_iam_instance_profile.ssm_instance_profile.name
  monitoring           = true

  network_interface {
    device_index         = 0
    network_interface_id = aws_network_interface.fw_b_mgmt.id
  }
  network_interface {
    device_index         = 1
    network_interface_id = aws_network_interface.fw_b_trust.id
  }
  network_interface {
    device_index         = 2
    network_interface_id = aws_network_interface.fw_b_untrust.id
  }

  tags = { Name = "${var.name_prefix}-fw-b", Project = var.project_name, Environment = var.environment }
}

# Register FW instances with GWLB target group
resource "aws_lb_target_group_attachment" "gwlb_attach_a" {
  target_group_arn = aws_lb_target_group.gwlb_tg.arn
  target_id        = aws_instance.fw_a.id
}
resource "aws_lb_target_group_attachment" "gwlb_attach_b" {
  target_group_arn = aws_lb_target_group.gwlb_tg.arn
  target_id        = aws_instance.fw_b.id
}

# 4.4 GWLB Listener (dummy – GWLB doesn’t use listeners like ALB/NLB; attach TG directly)
# NOTE: For GWLB, no listener resource is needed. Traffic is steered via Endpoint Service below.

# 4.5 Endpoint Service for GWLB (consumed by GWLBe in spokes)
resource "aws_vpc_endpoint_service" "gwlb_service" {
  acceptance_required        = false
  gateway_load_balancer_arns = [aws_lb.gwlb.arn]
  tags = { Name = "${var.name_prefix}-gwlb-svc", Project = var.project_name, Environment = var.environment }
}

# 4.6 GWLBe in Spokes (Mgmt/App private subnets)
# Use the generated service name from endpoint service
locals {
  gwlb_service_name = aws_vpc_endpoint_service.gwlb_service.service_name
}

resource "aws_vpc_endpoint" "mgmt_gwlbe_a" {
  vpc_id            = aws_vpc.mgmt_vpc.id
  service_name      = local.gwlb_service_name
  vpc_endpoint_type = "GatewayLoadBalancer"
  subnet_ids        = [aws_subnet.mgmt_private_1.id]
  tags = { Name = "${var.name_prefix}-mgmt-gwlbe-a", Project = var.project_name, Environment = var.environment }
}
resource "aws_vpc_endpoint" "mgmt_gwlbe_b" {
  vpc_id            = aws_vpc.mgmt_vpc.id
  service_name      = local.gwlb_service_name
  vpc_endpoint_type = "GatewayLoadBalancer"
  subnet_ids        = [aws_subnet.mgmt_private_2.id]
  tags = { Name = "${var.name_prefix}-mgmt-gwlbe-b", Project = var.project_name, Environment = var.environment }
}

resource "aws_vpc_endpoint" "app_gwlbe_a" {
  vpc_id            = aws_vpc.app_vpc.id
  service_name      = local.gwlb_service_name
  vpc_endpoint_type = "GatewayLoadBalancer"
  subnet_ids        = [aws_subnet.app_private_1.id]
  tags = { Name = "${var.name_prefix}-app-gwlbe-a", Project = var.project_name, Environment = var.environment }
}
resource "aws_vpc_endpoint" "app_gwlbe_b" {
  vpc_id            = aws_vpc.app_vpc.id
  service_name      = local.gwlb_service_name
  vpc_endpoint_type = "GatewayLoadBalancer"
  subnet_ids        = [aws_subnet.app_private_2.id]
  tags = { Name = "${var.name_prefix}-app-gwlbe-b", Project = var.project_name, Environment = var.environment }
}

# 4.7 Spoke VPC Routing changes
# - Default route for Internet egress: private subnets -> GWLBe endpoint
# - East-West between spokes: keep TGW for 10.0.0.0/24, 10.0.2.0/24, etc.
# Mgmt private RT: replace 0.0.0.0/0 to TGW with GWLBe
resource "aws_route" "mgmt_private_default_to_gwlbe_a" {
  route_table_id         = aws_route_table.mgmt_private_rt.id
  destination_cidr_block = "0.0.0.0/0"
  vpc_endpoint_id        = aws_vpc_endpoint.mgmt_gwlbe_a.id
  depends_on             = [aws_vpc_endpoint.mgmt_gwlbe_a]
}

# App private RT: default to GWLBe
resource "aws_route" "app_private_default_to_gwlbe_a" {
  route_table_id         = aws_route_table.app_private_rt.id
  destination_cidr_block = "0.0.0.0/0"
  vpc_endpoint_id        = aws_vpc_endpoint.app_gwlbe_a.id
  depends_on             = [aws_vpc_endpoint.app_gwlbe_a]
}

# Add explicit east-west prefixes to TGW on both spoke RTs (so internal VPC comms bypass Internet)
resource "aws_route" "mgmt_to_app_via_tgw" {
  count                  = var.tgw_id == "" ? 0 : 1
  route_table_id         = aws_route_table.mgmt_private_rt.id
  destination_cidr_block = aws_vpc.app_vpc.cidr_block
  transit_gateway_id     = var.tgw_id
}
resource "aws_route" "app_to_mgmt_via_tgw" {
  count                  = var.tgw_id == "" ? 0 : 1
  route_table_id         = aws_route_table.app_private_rt.id
  destination_cidr_block = aws_vpc.mgmt_vpc.cidr_block
  transit_gateway_id     = var.tgw_id
}

# 4.8 FW VPC routing
# Trust subnets: return traffic for spokes back to TGW (you already added via TGW RT: fw_to_mgmt/app)
# Untrust subnets: default route to IGW for Internet egress
# Ensure fw_untrust_rt has 0.0.0.0/0 -> IGW (already present in your file).

########################################
# PHASE 5 – HARDENING, LOGGING, AND OPERATIONS
########################################
# 5.1 SSM role for EC2 mgmt (no SSH requirement if using SSM)
resource "aws_iam_role" "ssm_role" {
  name               = "${var.name_prefix}-ssm-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals { type = "Service" identifiers = ["ec2.amazonaws.com"] }
  }
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ssm_instance_profile" {
  name = "${var.name_prefix}-ssm-instance-profile"
  role = aws_iam_role.ssm_role.name
}

# Allow PAN VM-Series to read bootstrap files from S3 (if S3 bootstrap is enabled)
resource "aws_iam_policy" "pan_bootstrap_read" {
  count  = var.enable_s3_bootstrap && var.bootstrap_s3_bucket != "" ? 1 : 0
  name   = "${var.name_prefix}-pan-bootstrap-read"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect: "Allow",
        Action: ["s3:GetObject","s3:ListBucket"],
        Resource: [
          "arn:aws:s3:::${var.bootstrap_s3_bucket}",
          "arn:aws:s3:::${var.bootstrap_s3_bucket}/${var.bootstrap_s3_prefix}/*"
        ]
      }
    ]
  })
}
resource "aws_iam_role_policy_attachment" "attach_bootstrap" {
  count      = var.enable_s3_bootstrap && var.bootstrap_s3_bucket != "" ? 1 : 0
  role       = aws_iam_role.ssm_role.name
  policy_arn = aws_iam_policy.pan_bootstrap_read[0].arn
}

# 5.2 Flow Logs (to S3) for all VPCs
# S3 bucket for logs (minimal; hardening can be added)
resource "aws_s3_bucket" "logs" {
  bucket        = var.log_s3_bucket_name
  force_destroy = false
  tags = { Name = "${var.name_prefix}-logs", Project = var.project_name, Environment = var.environment }
}
resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_flow_log" "mgmt_vpc_fl" {
  count                 = var.fw_enable_flow_logs ? 1 : 0
  log_destination      = aws_s3_bucket.logs.arn
  log_destination_type = "s3"
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.mgmt_vpc.id
  deliver_logs_permission_arn = null
  tags = { Name = "${var.name_prefix}-mgmt-vpc-flow", Project = var.project_name, Environment = var.environment }
}
resource "aws_flow_log" "app_vpc_fl" {
  count                 = var.fw_enable_flow_logs ? 1 : 0
  log_destination      = aws_s3_bucket.logs.arn
  log_destination_type = "s3"
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.app_vpc.id
  deliver_logs_permission_arn = null
  tags = { Name = "${var.name_prefix}-app-vpc-flow", Project = var.project_name, Environment = var.environment }
}
resource "aws_flow_log" "fw_vpc_fl" {
  count                 = var.fw_enable_flow_logs ? 1 : 0
  log_destination      = aws_s3_bucket.logs.arn
  log_destination_type = "s3"
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.fw_vpc.id
  deliver_logs_permission_arn = null
  tags = { Name = "${var.name_prefix}-fw-vpc-flow", Project = var.project_name, Environment = var.environment }
}
}

# 5.3 TGW Flow Logs (optional; requires CloudWatch or S3 – here S3 via CloudWatch log group would be separate)
# Skipped for brevity; enable via aws_ec2_transit_gateway + ec2:CreateTransitGatewayVpcAttachment logging where needed.

# 5.4 GWLB access logs (S3) – enable via LB attributes
resource "aws_lb_attribute" "gwlb_access_logs" {
  load_balancer_arn = aws_lb.gwlb.arn
  key               = "access_logs.s3.enabled"
  value             = "true"
}
resource "aws_lb_attribute" "gwlb_access_logs_bucket" {
  load_balancer_arn = aws_lb.gwlb.arn
  key               = "access_logs.s3.bucket"
  value             = aws_s3_bucket.logs.bucket
}
resource "aws_lb_attribute" "gwlb_access_logs_prefix" {
  load_balancer_arn = aws_lb.gwlb.arn
  key               = "access_logs.s3.prefix"
  value             = "gwlb"
}

# 5.5 NACLs (optional, sample baseline – keep simple here)
# Consider adding NACLs for trust/untrust subnets according to your org standard.

# 5.6 Explicit dependency ordering to avoid race on routes/endpoints
# (We used depends_on on key routes; Terraform graphs most of it automatically.)

########################################
# 5.7 CloudWatch alarms for resiliency & ops
########################################
# Target group health alarms
resource "aws_cloudwatch_metric_alarm" "gwlb_unhealthy_hosts" {
  alarm_name          = "${var.name_prefix}-gwlb-unhealthy-hosts"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "UnHealthyHostCount"
  namespace           = "AWS/NetworkELB"
  period              = 60
  statistic           = "Average"
  threshold           = 0
  alarm_description   = "GWLB target group has unhealthy hosts"
  dimensions = {
    TargetGroup  = aws_lb_target_group.gwlb_tg.arn_suffix
    LoadBalancer = aws_lb.gwlb.arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "gwlb_healthy_hosts_low" {
  alarm_name          = "${var.name_prefix}-gwlb-healthy-hosts-low"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "HealthyHostCount"
  namespace           = "AWS/NetworkELB"
  period              = 60
  statistic           = "Average"
  threshold           = 2
  alarm_description   = "GWLB target group healthy hosts fell below HA threshold"
  dimensions = {
    TargetGroup  = aws_lb_target_group.gwlb_tg.arn_suffix
    LoadBalancer = aws_lb.gwlb.arn_suffix
  }
}

# Instance status checks for firewalls
resource "aws_cloudwatch_metric_alarm" "fw_a_status_check" {
  alarm_name          = "${var.name_prefix}-fw-a-status-check"
  namespace           = "AWS/EC2"
  metric_name         = "StatusCheckFailed"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  dimensions = { InstanceId = aws_instance.fw_a.id }
  alarm_description   = "Instance status check failed for fw-a"
}

resource "aws_cloudwatch_metric_alarm" "fw_b_status_check" {
  alarm_name          = "${var.name_prefix}-fw-b-status-check"
  namespace           = "AWS/EC2"
  metric_name         = "StatusCheckFailed"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  dimensions = { InstanceId = aws_instance.fw_b.id }
  alarm_description   = "Instance status check failed for fw-b"
}

########################################
# 5.8 (Optional) NACL baselines – example placeholders
########################################
# NOTE: Tune to your org; keep SGs as primary control. NACLs shown for audit posture.
# resource "aws_network_acl" "fw_trust_nacl" { ... }
# resource "aws_network_acl" "fw_untrust_nacl" { ... }

########################################
# PHASE 6 – VALIDATION TEST INSTANCE (App Private Subnet)
# ... (existing content)
output "app_test_vm_private_ip" {
  description = "Private IP of the App Test VM for inspection testing"
  value       = aws_instance.app_test_vm.private_ip
}

########################################
# PHASE 7 – SECURE GUI/SSH ACCESS TO FIREWALLS (Client VPN)
########################################
# Purpose:
# - Provide secure, auditable GUI/SSH access to firewall management interfaces
# - Use AWS Client VPN (mutual-auth or SAML/AD as preferred). This example uses
#   mutual authentication with client certs (placeholder ARNs below).

variable "client_vpn_server_cert_arn" {
  description = "ACM certificate ARN for the Client VPN server endpoint (in us-west-2)"
  type        = string
  default     = ""
}
variable "client_vpn_client_cert_arn" {
  description = "ACM client certificate ARN chain or client authentication options (optional for mutual-auth)"
  type        = string
  default     = ""
}
variable "client_vpn_client_cidr" {
  description = "CIDR from which VPN clients will receive an IP (must not overlap VPCs). Eg: 10.250.0.0/22"
  type        = string
  default     = "10.250.0.0/22"
}

# Security group to allow VPN clients to reach firewall mgmt (443/22 as needed)
resource "aws_security_group" "vpn_to_fw_mgmt_sg" {
  name        = "${var.name_prefix}-vpn-to-fw-mgmt-sg"
  description = "Allows VPN clients to reach firewall mgmt ports"
  vpc_id      = aws_vpc.fw_vpc.id
  tags = { Name = "${var.name_prefix}-vpn-to-fw-mgmt-sg", Project = var.project_name, Environment = var.environment }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.client_vpn_client_cidr]
    description = "Allow HTTPS to firewall mgmt GUI from VPN clients"
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.client_vpn_client_cidr]
    description = "Allow SSH to firewall mgmt from VPN clients"
  }
  egress { from_port = 0 to_port = 0 protocol = "-1" cidr_blocks = ["0.0.0.0/0"] }
}

# Attach the VPN SG to the firewall mgmt SG by allowing traffic from the VPN SG (security group references)
# Note: Some firewall mgmt SGs currently reference var.admin_cidr; augment to allow VPN CIDR or SG where needed.

# Client VPN endpoint
resource "aws_ec2_client_vpn_endpoint" "mgmt_vpn" {
  description            = "${var.name_prefix}-mgmt-client-vpn"
  client_cidr_block      = var.client_vpn_client_cidr
  server_certificate_arn = var.client_vpn_server_cert_arn
  # For mutual-auth client certs, set authentication_options accordingly; placeholder below
  authentication_options {
    type = "certificate-authentication"
    root_certificate_chain_arn = var.client_vpn_client_cert_arn
  }

  connection_log_options {
    enabled = false
  }

  dns_servers = []
  split_tunnel = true
  tags = { Name = "${var.name_prefix}-mgmt-client-vpn", Project = var.project_name, Environment = var.environment }
}

# Associate the VPN with mgmt subnets (one per AZ)
resource "aws_ec2_client_vpn_network_association" "mgmt_assoc_a" {
  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.mgmt_vpn.id
  subnet_id               = aws_subnet.fw_mgmt_1.id
}
resource "aws_ec2_client_vpn_network_association" "mgmt_assoc_b" {
  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.mgmt_vpn.id
  subnet_id               = aws_subnet.fw_mgmt_2.id
}

# Authorization rule: allow clients access to firewall management CIDRs (trust mgmt subnet)
resource "aws_ec2_client_vpn_authorization_rule" "allow_mgmt" {
  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.mgmt_vpn.id
  target_network_cidr    = aws_subnet.fw_mgmt_1.cidr_block
  authorize_all_groups   = true
}

# Route to firewall management subnet via the VPC association
resource "aws_ec2_client_vpn_route" "route_to_mgmt_a" {
  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.mgmt_vpn.id
  destination_cidr_block = aws_subnet.fw_mgmt_1.cidr_block
  target_vpc_subnet_id   = aws_subnet.fw_mgmt_1.id
}
resource "aws_ec2_client_vpn_route" "route_to_mgmt_b" {
  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.mgmt_vpn.id
  destination_cidr_block = aws_subnet.fw_mgmt_2.cidr_block
  target_vpc_subnet_id   = aws_subnet.fw_mgmt_2.id
}

# Optionally add a route so VPN clients can reach internal VPCs (app/mgmt) over TGW — add if needed
resource "aws_ec2_client_vpn_route" "route_to_app" {
  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.mgmt_vpn.id
  destination_cidr_block = aws_vpc.app_vpc.cidr_block
  target_vpc_subnet_id   = aws_subnet.fw_mgmt_1.id
}

# Output VPN endpoint ID and DNS name
output "client_vpn_endpoint_id" { value = aws_ec2_client_vpn_endpoint.mgmt_vpn.id }
output "client_vpn_endpoint_dns_name" { value = aws_ec2_client_vpn_endpoint.mgmt_vpn.dns_name }

# NOTE: You must provide ACM certificates (server + client root) in var.client_vpn_server_cert_arn and var.client_vpn_client_cert_arn
# Alternatively, you can configure SAML or Active Directory authentication instead of mutual-cert auth.

########################################
# OUTPUTS
########################################
output "gwlb_arn" { value = aws_lb.gwlb.arn }
output "gwlb_tg_arn" { value = aws_lb_target_group.gwlb_tg.arn }
output "gwlb_service_name" { value = aws_vpc_endpoint_service.gwlb_service.service_name }
output "mgmt_gwlbe_ids" { value = [aws_vpc_endpoint.mgmt_gwlbe_a.id, aws_vpc_endpoint.mgmt_gwlbe_b.id] }
output "app_gwlbe_ids"  { value = [aws_vpc_endpoint.app_gwlbe_a.id,  aws_vpc_endpoint.app_gwlbe_b.id] }
output "fw_instance_ids" { value = [aws_instance.fw_a.id, aws_instance.fw_b.id] }
output "client_vpn_endpoint_id" { value = aws_ec2_client_vpn_endpoint.mgmt_vpn.id }
output "client_vpn_endpoint_dns_name" { value = aws_ec2_client_vpn_endpoint.mgmt_vpn.dns_name }
output "app_test_vm_id" { value = aws_instance.app_test_vm.id }
output "app_test_vm_private_ip" { value = aws_instance.app_test_vm.private_ip }

########################################
# APPENDIX – Bootstrap artifacts (best‑practice examples)
########################################
# Create a local ./bootstrap tree and upload to S3. Keep secrets out of VCS.
#
# ./bootstrap/
#   └── config/
#       ├── init-cfg.txt
#       └── bootstrap.xml
#   ├── content/   (optional)
#   ├── license/   (optional)
#   └── software/  (optional)

# Example: bootstrap/config/init-cfg.txt (Panorama-capable; DHCP mgmt)
# -------------------------------------------------------------------
# type=dhcp-client
# hostname=acme-fw-a
# # Panorama (optional):
# panorama-server=198.51.100.10
# tplname=aws-template
# dgname=aws-dg
# vm-auth-key=REDACTED_VM_AUTH_KEY
# # DNS (AWS resolver):
# dns-primary=169.254.169.253
# dhcp-send-hostname=yes
# dhcp-send-client-id=yes

# Example: bootstrap/config/bootstrap.xml (minimal hardening)
# ----------------------------------------------------------
# <config version="11.0.0">
#   <mgt-config>
#     <users>
#       <entry name="admin">
#         <!-- Prefer pre-hashed phash exported from a lab firewall; change on first login -->
#         <phash>$1$REDACTED_HASH$SALT...REDACTED...</phash>
#         <permissions>
#           <role-based><superuser>yes</superuser></role-based>
#         </permissions>
#       </entry>
#     </users>
#   </mgt-config>
#   <devices>
#     <entry name="localhost.localdomain">
#       <deviceconfig>
#         <system>
#           <hostname>acme-fw-a</hostname>
#           <service>
#             <disable-http>yes</disable-http>
#             <disable-telnet>yes</disable-telnet>
#           </service>
#         </system>
#       </deviceconfig>
#     </entry>
#   </devices>
# </config>

# Makefile helper (optional): create bucket & upload bootstrap safely
# ------------------------------------------------------------------
# Save the following as Makefile (same folder as this TF) and run:
#   make bootstrap BUCKET=acme-pan-bootstrap-usw2 PREFIX=bootstrap
#   make kms          # (optional) create a CMK for the bucket
#
# Requires: awscli v2 installed & configured with access to the account
#
# BOOTSTRAP_DIR ?= ./bootstrap
# BUCKET ?= acme-pan-bootstrap-usw2
# PREFIX ?= bootstrap
# REGION ?= us-west-2
#
# .PHONY: bucket policy upload bootstrap kms
#
# bucket:
# 	aws s3api create-bucket --bucket $(BUCKET) --region $(REGION) --create-bucket-configuration LocationConstraint=$(REGION) || true
# 	aws s3api put-public-access-block --bucket $(BUCKET) --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
#
# policy:
# 	cat > /tmp/$(BUCKET)-policy.json <<EOF
# {
#   "Version": "2012-10-17",
#   "Statement": [
#     {"Sid":"DenyInsecureTransport","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::$(BUCKET)","arn:aws:s3:::$(BUCKET)/*"],"Condition":{"Bool":{"aws:SecureTransport":false}}}
#   ]
# }
# EOF
# 	aws s3api put-bucket-policy --bucket $(BUCKET) --policy file:///tmp/$(BUCKET)-policy.json
#
# upload:
# 	aws s3 sync $(BOOTSTRAP_DIR) s3://$(BUCKET)/$(PREFIX)/ --delete
#
# kms:
# 	aws kms create-key --description "PAN bootstrap CMK" --region $(REGION) || true
#
# bootstrap: bucket policy upload
