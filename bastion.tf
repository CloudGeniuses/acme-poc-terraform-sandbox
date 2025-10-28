########################################
# SSM Bastion for PAN Mgmt (private-only)
########################################

# Latest Amazon Linux 2 AMI
data "aws_ami" "amazon_linux2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

# IAM role/profile for SSM
resource "aws_iam_role" "ssm_bastion_role" {
  name = "${var.name_prefix}-ssm-bastion-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "ec2.amazonaws.com" },
      Action   = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm_core_attach" {
  role       = aws_iam_role.ssm_bastion_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ssm_bastion_profile" {
  name = "${var.name_prefix}-ssm-bastion-profile"
  role = aws_iam_role.ssm_bastion_role.name
}

# SG: no inbound (SSM only); allow all egress
resource "aws_security_group" "ssm_bastion_sg" {
  name   = "${var.name_prefix}-ssm-bastion-sg"
  vpc_id = aws_vpc.fw_vpc.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name_prefix}-ssm-bastion-sg" }
}

# Bastion in the mgmt subnet (private IP only)
resource "aws_instance" "ssm_bastion" {
  ami                         = data.aws_ami.amazon_linux2.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.fw_mgmt_az1.id
  iam_instance_profile        = aws_iam_instance_profile.ssm_bastion_profile.name
  vpc_security_group_ids      = [aws_security_group.ssm_bastion_sg.id]
  associate_public_ip_address = false

  tags = { Name = "${var.name_prefix}-ssm-bastion" }
}

# Use the mgmt ENI you already created
# (Change to fw2_mgmt if you want the second device.)
locals {
  pan_fw1_mgmt_ip = aws_network_interface.fw1_mgmt.private_ip
}

########################################
# Helpful outputs (copy/paste commands)
########################################

output "ssm_bastion_instance_id" {
  value       = aws_instance.ssm_bastion.id
  description = "SSM-enabled bastion instance ID"
}

output "pan_fw1_mgmt_ip" {
  value       = local.pan_fw1_mgmt_ip
  description = "Private mgmt IP of PAN fw1"
}

# HTTPS GUI via local port 8443
output "ssm_port_forward_cmd_https" {
  description = "Run this to open PAN GUI at https://localhost:8443"
  value = "aws ssm start-session --target ${aws_instance.ssm_bastion.id} --document-name AWS-StartPortForwardingSessionToRemoteHost --parameters 'host=[${local.pan_fw1_mgmt_ip}],portNumber=[443],localPortNumber=[8443]'"
}

# SSH CLI via local port 2222
output "ssm_port_forward_cmd_ssh" {
  description = "Run this then: ssh admin@localhost -p 2222"
  value = "aws ssm start-session --target ${aws_instance.ssm_bastion.id} --document-name AWS-StartPortForwardingSessionToRemoteHost --parameters 'host=[${local.pan_fw1_mgmt_ip}],portNumber=[22],localPortNumber=[2222]'"
}
