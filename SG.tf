#############################################
# Bastion → Palo Alto MGMT (HTTPS/SSH)
# Paste into your stack and adjust variables.
#############################################

# --- Vars (override in *.tfvars or workspace vars) ---
variable "vpc_id" {
  description = "VPC ID that contains the bastion and firewall mgmt ENI"
  type        = string
}

variable "name_prefix" {
  description = "Name prefix used for SGs (e.g., acme-sandbox)"
  type        = string
  default     = "acme-sandbox"
}

# If you know the exact SG IDs, set them and the data lookups will be skipped.
variable "fw_mgmt_sg_id" {
  description = "(Optional) Security Group ID attached to Palo mgmt ENI"
  type        = string
  default     = null
}

variable "bastion_sg_id" {
  description = "(Optional) Security Group ID attached to SSM bastion instance"
  type        = string
  default     = null
}

# --- Lookups (used only when IDs are not provided) ---
# Looks for SGs named:
#   <name_prefix>-fw-mgmt-sg
#   <name_prefix>-ssm-bastion-sg
data "aws_security_group" "fw_mgmt" {
  count = var.fw_mgmt_sg_id == null ? 1 : 0

  filter {
    name   = "group-name"
    values = ["${var.name_prefix}-fw-mgmt-sg"]
  }

  vpc_id = var.vpc_id
}

data "aws_security_group" "bastion" {
  count = var.bastion_sg_id == null ? 1 : 0

  filter {
    name   = "group-name"
    values = ["${var.name_prefix}-ssm-bastion-sg"]
  }

  vpc_id = var.vpc_id
}

locals {
  resolved_fw_mgmt_sg_id   = var.fw_mgmt_sg_id != null ? var.fw_mgmt_sg_id : data.aws_security_group.fw_mgmt[0].id
  resolved_bastion_sg_id   = var.bastion_sg_id != null ? var.bastion_sg_id : data.aws_security_group.bastion[0].id
}

# --- Least-privilege ingress from Bastion SG → FW MGMT SG (HTTPS) ---
resource "aws_security_group_rule" "bastion_to_fw_mgmt_https" {
  description              = "Allow bastion to access Palo mgmt over HTTPS (443)"
  type                     = "ingress"
  protocol                 = "tcp"
  from_port                = 443
  to_port                  = 443
  security_group_id        = local.resolved_fw_mgmt_sg_id
  source_security_group_id = local.resolved_bastion_sg_id
}

# --- Optional: SSH via tunnel as well (remove if not needed) ---
resource "aws_security_group_rule" "bastion_to_fw_mgmt_ssh" {
  description              = "Allow bastion to access Palo mgmt over SSH (22)"
  type                     = "ingress"
  protocol                 = "tcp"
  from_port                = 22
  to_port                  = 22
  security_group_id        = local.resolved_fw_mgmt_sg_id
  source_security_group_id = local.resolved_bastion_sg_id
}

# Helpful outputs
output "fw_mgmt_sg_id_effective" {
  value = local.resolved_fw_mgmt_sg_id
}

output "bastion_sg_id_effective" {
  value = local.resolved_bastion_sg_id
}
