ACME POC Terraform Sandbox
Overview

This repository contains Terraform configurations to deploy the ACME proof-of-concept (POC) sandbox environment on AWS. It implements a secure, highly available, and audit-compliant network architecture with:

Management, Firewall/NVA, and Application VPCs

Multi-AZ subnets for high availability

Transit Gateway (TGW) for centralized routing (East-West and North-South traffic)

Internet access via NVAs

VPC Flow Logs for auditing and compliance

Terraform Cloud integration for remote state and secure variable management

Architecture Diagram

(Add diagram showing VPCs, subnets, TGW, route tables, and IGWs. Use AWS icons or draw.io)

Prerequisites

AWS account with required permissions

Terraform Cloud account with workspace: acme-poc-sandbox

GitHub repository connected to Terraform Cloud workspace (VCS integration)

Terraform Cloud workspace variables configured:

project_name

environment

name_prefix

Optional: AWS CLI for manual validation

Deployment Instructions (Remote-Only Workflow)

Push changes to the repository branch connected to Terraform Cloud.

Terraform Cloud automatically detects the changes via VCS integration.

Terraform Cloud executes Plan and Apply remotely.

Monitor execution and review logs in the Terraform Cloud workspace UI.

Confirm resource deployment and routing in AWS console.

Note: No Terraform CLI commands are required for remote-only workflow.

Components Deployed
Component	Purpose
mgmt-vpc	Management & bastion hosts
fw-vpc	Firewall / NVA deployment
app-vpc	Application workloads
Subnets	Multi-AZ for HA
IGWs	Internet access for public subnets
Route Tables	Routing via TGW & placeholders for IGW/TGW
Transit Gateway	Central hub for East-West/North-South traffic
VPC Flow Logs	Security auditing & compliance
Terraform Variables

Variables are managed in Terraform Cloud and referenced in code:

variable "project_name" {}
variable "environment" {}
variable "name_prefix" {}


Sensitive variables (e.g., secrets, API keys) are stored securely in Terraform Cloud.

Audit & Compliance Notes

Flow logs enabled for all VPCs

Private subnets not exposed to IGW

Multi-AZ deployment ensures HA

All Terraform changes logged in Terraform Cloud

Naming conventions standardized for easy resource tracking
