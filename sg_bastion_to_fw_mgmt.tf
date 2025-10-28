#############################################
# Bastion → Palo Alto MGMT (HTTPS/SSH)
# Works with your existing var.name_prefix and aws_vpc.fw_vpc.
# Only NEW variables below (no duplicates).
#############################################

# Optional overrides (unique names to avoid clashes)
variable "fw_mgmt_sg_id_override" {
  description = "(Optional) If set, use this SG ID for PAN mgmt ENI instead of lookup"
  type        = string
  default     = null
}

variable "bastion_sg_id_override" {
  description = "(Optional) If set, use this SG ID for the SSM bastion instead of lookup"
  type        = string
  default     = null
}

variable "enable_ssh_to_mgmt" {
  description = "Also allow SSH (22) from bastion to PAN mgmt"
  type        = bool
  default     = true
}

# Use your existing VPC resource
locals {
  vpc_id = aws_vpc.fw_vpc.id
}

# Look up SGs by name ONLY if overrides are not supplied
# Expected names: <name_prefix>-fw-mgmt-sg and <name_prefix>-ssm-bastion-sg
data "aws_security_group" "fw_mgmt" {
  count = var.fw_mgmt_sg_id_override == null ? 1 : 0

  filter {
    name   = "group-name"
    values = ["${var.name_prefix}-fw-mgmt-sg"]
  }

  vpc_id = local.vpc_id
}

data "aws_security_group" "bastion" {
  count = var.bastion_sg_id_override == null ? 1 : 0

  filter {
    name   = "group-name"
    values = ["${var.name_prefix}-ssm-bastion-sg"]
  }

  vpc_id = local.vpc_id
}

locals {
  resolved_fw_mgmt_sg_id = var.fw_mgmt_sg_id_override != null ? var.fw_mgmt_sg_id_override : data.aws_security_group.fw_mgmt[0].id
  resolved_bastion_sg_id = var.bastion_sg_id_override != null ? var.bastion_sg_id_override : data.aws_security_group.bastion[0].id
}

# HTTPS rule (least privilege)
resource "aws_security_group_rule" "bastion_to_fw_mgmt_https" {
  description              = "Allow bastion to access Palo mgmt over HTTPS (443)"
  type                     = "ingress"
  protocol                 = "tcp"
  from_port                = 443
  to_port                  = 443
  security_group_id        = local.resolved_fw_mgmt_sg_id
  source_security_group_id = local.resolved_bastion_sg_id
}

# Optional SSH rule
resource "aws_security_group_rule" "bastion_to_fw_mgmt_ssh" {
  count                    = var.enable_ssh_to_mgmt ? 1 : 0
  description              = "Allow bastion to access Palo mgmt over SSH (22)"
  type                     = "ingress"
  protocol                 = "tcp"
  from_port                = 22
  to_port                  = 22
  security_group_id        = local.resolved_fw_mgmt_sg_id
  source_security_group_id = local.resolved_bastion_sg_id
}

output "fw_mgmt_sg_id_effective" {
  value = local.resolved_fw_mgmt_sg_id
}

output "bastion_sg_id_effective" {
  value = local.resolved_bastion_sg_id
}
