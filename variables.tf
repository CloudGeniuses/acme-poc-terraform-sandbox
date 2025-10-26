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
  description = "Environment (sandbox/dev/prod)"
}

variable "name_prefix" {
  type        = string
  description = "Prefix for consistent naming"
}

variable "admin_cidr" {
  description = "Public IP CIDR allowed for SSH/GUI"
  type        = string
}

variable "fw_ami_id" {
  description = "Palo Alto AMI ID"
  type        = string
}

variable "fw_instance_type" {
  description = "Firewall instance type"
  type        = string
  default     = "c5.xlarge"
}

variable "fw_key_name" {
  description = "Key pair for management access"
  type        = string
}

variable "fw_enable_flow_logs" {
  type    = bool
  default = true
}

variable "bootstrap_s3_bucket" {
  type        = string
  description = "S3 bucket for bootstrap config"
}

variable "bootstrap_s3_prefix" {
  type        = string
  default     = "bootstrap"
}

variable "log_s3_bucket_name" {
  type        = string
  description = "S3 bucket for flow/GWLB logs"
}

variable "enable_s3_bootstrap" {
  description = "Enable S3-based bootstrap config"
  type        = bool
  default     = true
}

variable "tgw_id" {
  description = "Optional existing Transit Gateway ID"
  type        = string
  default     = ""
}
