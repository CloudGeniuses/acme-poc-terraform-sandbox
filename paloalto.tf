########################################
# Phase 4-5: Palo Alto VM-Series + GWLB
########################################

# --- Security Groups ---
resource "aws_security_group" "fw_mgmt_sg" {
  name        = "${var.name_prefix}-fw-mgmt-sg"
  description = "Mgmt access (HTTPS/SSH)"
  vpc_id      = aws_vpc.fw_vpc.id

  ingress { from_port = 22 to_port = 22 protocol = "tcp" cidr_blocks = [var.admin_cidr] }
  ingress { from_port = 443 to_port = 443 protocol = "tcp" cidr_blocks = [var.admin_cidr] }
  egress  { from_port = 0 to_port = 0 protocol = "-1" cidr_blocks = ["0.0.0.0/0"] }

  tags = { Name = "${var.name_prefix}-fw-mgmt-sg" }
}

resource "aws_security_group" "fw_trust_sg" {
  name        = "${var.name_prefix}-fw-trust-sg"
  description = "Trust dataplane"
  vpc_id      = aws_vpc.fw_vpc.id
  ingress { from_port = 0 to_port = 0 protocol = "-1" cidr_blocks = ["10.0.0.0/8"] }
  egress  { from_port = 0 to_port = 0 protocol = "-1" cidr_blocks = ["0.0.0.0/0"] }
}

resource "aws_security_group" "fw_untrust_sg" {
  name        = "${var.name_prefix}-fw-untrust-sg"
  description = "Untrust dataplane"
  vpc_id      = aws_vpc.fw_vpc.id
  egress { from_port = 0 to_port = 0 protocol = "-1" cidr_blocks = ["0.0.0.0/0"] }
}

# --- IAM Role + SSM ---
resource "aws_iam_role" "fw_ssm_role" {
  name = "${var.name_prefix}-fw-ssm-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "fw_ssm_policy" {
  role       = aws_iam_role.fw_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "fw_ssm_profile" {
  name = "${var.name_prefix}-fw-ssm-profile"
  role = aws_iam_role.fw_ssm_role.name
}

# --- Gateway Load Balancer ---
resource "aws_lb" "gwlb" {
  name               = "${var.name_prefix}-gwlb"
  load_balancer_type = "gateway"
  subnet_mapping { subnet_id = aws_subnet.fw_trust_1.id }
  subnet_mapping { subnet_id = aws_subnet.fw_trust_2.id }
  tags = { Name = "${var.name_prefix}-gwlb" }
}

resource "aws_lb_target_group" "gwlb_tg" {
  name        = "${var.name_prefix}-gwlb-tg"
  port        = 6081
  protocol    = "GENEVE"
  vpc_id      = aws_vpc.fw_vpc.id
  target_type = "instance"
  health_check { protocol = "TCP" }
}

resource "aws_vpc_endpoint_service" "gwlb_service" {
  acceptance_required        = false
  gateway_load_balancer_arns = [aws_lb.gwlb.arn]
}

# --- Palo Alto VM-Series ---
locals {
  fw_user_data = "vmseries-bootstrap-aws-s3bucket=${var.bootstrap_s3_bucket}"
}

resource "aws_instance" "vmseries" {
  count               = 2
  ami                 = var.fw_ami_id
  instance_type       = var.fw_instance_type
  key_name            = var.fw_key_name
  iam_instance_profile = aws_iam_instance_profile.fw_ssm_profile.name
  user_data_base64     = base64encode(local.fw_user_data)
  subnet_id            = aws_subnet.fw_mgmt_1.id
  vpc_security_group_ids = [aws_security_group.fw_mgmt_sg.id]

  tags = {
    Name        = "${var.name_prefix}-vmseries-${count.index}"
    Project     = var.project_name
    Environment = var.environment
  }
}

# --- Flow Logs ---
resource "aws_flow_log" "fw_vpc_fl" {
  count                  = var.fw_enable_flow_logs ? 1 : 0
  log_destination        = aws_s3_bucket.logs.arn
  log_destination_type   = "s3"
  traffic_type           = "ALL"
  vpc_id                 = aws_vpc.fw_vpc.id
  tags = { Name = "${var.name_prefix}-fw-vpc-flow" }
}

# --- Outputs ---
output "gwlb_service_name" { value = aws_vpc_endpoint_service.gwlb_service.service_name }
output "vmseries_private_ips" { value = aws_instance.vmseries[*].private_ip }
