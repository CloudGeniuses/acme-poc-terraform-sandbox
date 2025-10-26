########################################
# IAM for SSM
########################################
resource "aws_iam_role" "fw_ssm_role" {
  name               = "${var.name_prefix}-fw-ssm-role"
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

########################################
# Palo Alto Firewall (VM-Series PAYG)
########################################
locals {
  fw_pairs = [
    { mgmt = aws_subnet.fw_mgmt_1.id, untrust = aws_subnet.fw_untrust_1.id, trust = aws_subnet.fw_trust_1.id },
    { mgmt = aws_subnet.fw_mgmt_1.id, untrust = aws_subnet.fw_untrust_2.id, trust = aws_subnet.fw_trust_2.id }
  ]

  fw_user_data = var.enable_s3_bootstrap ? "vmseries-bootstrap-aws-s3bucket=${var.bootstrap_s3_bucket}" : ""
}

resource "aws_network_interface" "fw_mgmt" {
  count           = length(local.fw_pairs)
  subnet_id       = local.fw_pairs[count.index].mgmt
  security_groups = [aws_security_group.fw_mgmt_sg.id]
  tags = { Name = "${var.name_prefix}-fw-mgmt-${count.index}" }
}

resource "aws_network_interface" "fw_untrust" {
  count             = length(local.fw_pairs)
  subnet_id         = local.fw_pairs[count.index].untrust
  source_dest_check = false
  tags = { Name = "${var.name_prefix}-fw-untrust-${count.index}" }
}

resource "aws_eip" "fw_eip" {
  count             = length(local.fw_pairs)
  domain            = "vpc"
  network_interface = aws_network_interface.fw_untrust[count.index].id
  tags = { Name = "${var.name_prefix}-fw-eip-${count.index}" }
}

resource "aws_network_interface" "fw_trust" {
  count             = length(local.fw_pairs)
  subnet_id         = local.fw_pairs[count.index].trust
  source_dest_check = false
  tags = { Name = "${var.name_prefix}-fw-trust-${count.index}" }
}

resource "aws_instance" "fw_vm" {
  count                = length(local.fw_pairs)
  ami                  = var.fw_ami_id
  instance_type        = var.fw_instance_type
  key_name             = var.fw_key_name
  iam_instance_profile = aws_iam_instance_profile.fw_ssm_profile.name
  user_data_base64     = base64encode(local.fw_user_data)

  primary_network_interface {
    network_interface_id = aws_network_interface.fw_mgmt[count.index].id
  }

  tags = { Name = "${var.name_prefix}-fw-${count.index}" }
}

resource "aws_network_interface_attachment" "fw_untrust_attach" {
  count                = length(local.fw_pairs)
  instance_id          = aws_instance.fw_vm[count.index].id
  network_interface_id = aws_network_interface.fw_untrust[count.index].id
  device_index         = 1
}

resource "aws_network_interface_attachment" "fw_trust_attach" {
  count                = length(local.fw_pairs)
  instance_id          = aws_instance.fw_vm[count.index].id
  network_interface_id = aws_network_interface.fw_trust[count.index].id
  device_index         = 2
}

########################################
# VPC Flow Logs (Phase 5)
########################################
resource "aws_s3_bucket" "logs" {
  bucket = var.log_s3_bucket_name
}

resource "aws_flow_log" "fw_vpc_logs" {
  log_destination        = aws_s3_bucket.logs.arn
  log_destination_type   = "s3"
  traffic_type           = "ALL"
  vpc_id                 = aws_vpc.fw_vpc.id
}

########################################
# Outputs
########################################
output "firewall_public_ips" {
  value = aws_eip.fw_eip[*].public_ip
}

output "firewall_private_ips" {
  value = aws_instance.fw_vm[*].private_ip
}
