variable "region"          { type = string  default = "us-west-2" }
variable "project_name"    { type = string  description = "Project identifier" }
variable "environment"     { type = string  description = "Environment (dev/prod)" }
variable "name_prefix"     { type = string  description = "Naming prefix" }
variable "admin_cidr"      { type = string  description = "CIDR allowed for SSH/GUI" }

# Firewall
variable "fw_ami_id"       { type = string  description = "Palo Alto AMI ID" }
variable "fw_instance_type"{ type = string  default = "c6i.large" }
variable "fw_key_name"     { type = string  description = "SSH key pair name" }
variable "bootstrap_s3_bucket" { type = string  description = "S3 bucket for bootstrap" }
variable "bootstrap_s3_prefix" { type = string  default = "bootstrap" }
variable "log_s3_bucket_name"  { type = string  description = "S3 bucket for flow/GWLB logs" }
variable "fw_enable_flow_logs" { type = bool    default = true }
