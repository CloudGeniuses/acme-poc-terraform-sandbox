########################################
# Phase 4: Palo Alto VM-Series (PAYG) — Multi-AZ Deployment
########################################

# ---- Variables ----
variable "pan_ami_id" {
  description = "PAYG VM-Series AMI (us-west-2)"
  type        = string
}

variable "pan_instance_type" {
  description = "VM-Series size"
  type        = string
  default     = "c5n.xlarge"
}

variable "pan_key_name" {
  description = "Existing EC2 key pair name"
  type        = string
}

variable "admin_cidr" {
  description = "CIDR allowed to management (HTTPS/SSH)"
  type        = string
  default     = "10.0.0.0/8"
}

variable "enable_bootstrap" {
  description = "Use S3 bootstrap configuration?"
  type        = bool
  default     = false
}

variable "bootstrap_s3_bucket" {
  description = "S3 bucket for bootstrap (if enabled)"
  type        = string
  default     = ""
}

########################################
# Security Groups — Firewall VPC
########################################
resource "aws_security_group" "fw_mgmt_sg" {
  name        = "${var.name_prefix}-fw-mgmt-sg"
  description = "Mgmt access to VM-Series"
  vpc_id      = aws_vpc.fw_vpc.id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }

  ingress {
    description = "HTTPS"
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

  tags = {
    Name        = "${var.name_prefix}-fw-mgmt-sg"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_security_group" "fw_untrust_sg" {
  name        = "${var.name_prefix}-fw-untrust-sg"
  description = "Untrust dataplane ENI"
  vpc_id      = aws_vpc.fw_vpc.id

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

resource "aws_security_group" "fw_trust_sg" {
  name        = "${var.name_prefix}-fw-trust-sg"
  description = "Trust dataplane ENI"
  vpc_id      = aws_vpc.fw_vpc.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/24", "10.0.2.0/24"]
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

########################################
# IAM Role for SSM (optional but recommended)
########################################
resource "aws_iam_role" "fw_ssm_role" {
  name               = "${var.name_prefix}-fw-ssm-role"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    Name        = "${var.name_prefix}-fw-ssm-role"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_iam_role_policy_attachment" "fw_ssm_policy" {
  role       = aws_iam_role.fw_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "fw_ssm_profile" {
  name = "${var.name_prefix}-fw-ssm-profile"
  role = aws_iam_role.fw_ssm_role.name
}

########################################
# Local Mappings
########################################
locals {
  fw_pairs = [
    { mgmt = aws_subnet.fw_mgmt_1.id,  untrust = aws_subnet.fw_untrust_1.id, trust = aws_subnet.fw_trust_1.id },
    { mgmt = aws_subnet.fw_mgmt_2.id,  untrust = aws_subnet.fw_untrust_2.id, trust = aws_subnet.fw_trust_2.id }
  ]

  fw_user_data = var.enable_bootstrap ? "vmseries-bootstrap-aws-s3bucket=${var.bootstrap_s3_bucket}" : ""
}

########################################
# ENIs & EIPs
########################################
resource "aws_network_interface" "fw_untrust_eni" {
  count             = length(local.fw_pairs)
  subnet_id         = local.fw_pairs[count.index].untrust
  security_groups   = [aws_security_group.fw_untrust_sg.id]
  source_dest_check = false

  tags = {
    Name        = "${var.name_prefix}-fw-untrust-eni-${count.index}"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_eip" "fw_untrust_eip" {
  count             = length(local.fw_pairs)
  domain            = "vpc"
  network_interface = aws_network_interface.fw_untrust_eni[count.index].id

  tags = {
    Name        = "${var.name_prefix}-fw-untrust-eip-${count.index}"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_network_interface" "fw_trust_eni" {
  count             = length(local.fw_pairs)
  subnet_id         = local.fw_pairs[count.index].trust
  security_groups   = [aws_security_group.fw_trust_sg.id]
  source_dest_check = false

  tags = {
    Name        = "${var.name_prefix}-fw-trust-eni-${count.index}"
    Project     = var.project_name
    Environment = var.environment
  }
}

########################################
# VM-Series Instances
########################################
resource "aws_instance" "vmseries" {
  count         = length(local.fw_pairs)
  ami           = var.pan_ami_id
  instance_type = var.pan_instance_type
  key_name      = var.pan_key_name

  subnet_id              = local.fw_pairs[count.index].mgmt
  vpc_security_group_ids = [aws_security_group.fw_mgmt_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.fw_ssm_profile.name
  user_data_base64       = base64encode(local.fw_user_data)
  associate_public_ip_address = false

  # Attach dataplane ENIs
  network_interface {
    network_interface_id = aws_network_interface.fw_untrust_eni[count.index].id
    device_index         = 1
  }
  network_interface {
    network_interface_id = aws_network_interface.fw_trust_eni[count.index].id
    device_index         = 2
  }

  lifecycle {
    ignore_changes = [ami, user_data]
  }

  tags = {
    Name        = "${var.name_prefix}-vmseries-${count.index}"
    Project     = var.project_name
    Environment = var.environment
  }
}

########################################
# Outputs
########################################
output "vmseries_mgmt_private_ips" {
  value = aws_instance.vmseries[*].private_ip
}

output "vmseries_untrust_eips" {
  value = aws_eip.fw_untrust_eip[*].public_ip
}

output "vmseries_trust_private_ips" {
  value = aws_network_interface.fw_trust_eni[*].private_ip
}
