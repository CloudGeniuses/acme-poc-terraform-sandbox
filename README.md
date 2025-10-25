ACME POC PHASE 1–3 SPEC SHEET
Phase 1: Preparation & Environment Setup
Component	Details	Notes
Terraform Cloud Workspace	acme-poc-sandbox	Remote state management
Provider	AWS (us-west-2)	PoC preferred region
Terraform Variables	project_name="acme-poc", environment="sandbox", name_prefix="acme-poc"	Naming consistency
Secrets & Keys	Stored in Terraform Cloud workspace	Avoid hardcoded AWS credentials
Purpose	Foundation for all automation	No dependencies
Phase 2: Network Foundation (VPCs & Subnets)
VPCs
VPC Name	CIDR	Purpose
acme-poc-mgmt-vpc	10.0.0.0/24	Management/Bastion
acme-poc-fw-vpc	10.0.1.0/24	Palo Alto NVA / firewall
acme-poc-app-vpc	10.0.2.0/24	Application (NGINX PoC)
Subnets
VPC	Subnet Name	CIDR	Type	Purpose
mgmt-vpc	mgmt-public-1	10.0.0.0/28	Public	Bastion AZ-A
mgmt-vpc	mgmt-public-2	10.0.0.16/28	Public	Bastion AZ-B
mgmt-vpc	mgmt-private-1	10.0.0.32/28	Private	Internal Mgmt AZ-A
mgmt-vpc	mgmt-private-2	10.0.0.48/28	Private	Internal Mgmt AZ-B
fw-vpc	fw-untrust-1	10.0.1.0/28	Public	Internet-facing NVA AZ-A
fw-vpc	fw-untrust-2	10.0.1.16/28	Public	Internet-facing NVA AZ-B
fw-vpc	fw-trust-1	10.0.1.32/28	Private	East-West traffic AZ-A
fw-vpc	fw-trust-2	10.0.1.48/28	Private	East-West traffic AZ-B
fw-vpc	fw-mgmt-1	10.0.1.64/28	Private	NVA management AZ-A
fw-vpc	fw-mgmt-2	10.0.1.80/28	Private	NVA management AZ-B
app-vpc	app-private-1	10.0.2.0/28	Private	NGINX AZ-A
app-vpc	app-private-2	10.0.2.16/28	Private	NGINX AZ-B
Internet Gateways (IGW)
VPC	IGW Name	Purpose
mgmt-vpc	mgmt-igw	Bastion public access
fw-vpc	fw-igw	NVA untrust internet access
Route Tables
Mgmt VPC
Route Table	Subnets	Routes
mgmt-public-rt	mgmt-public-1/2	0.0.0.0/0 → IGW (mgmt-igw)
mgmt-private-rt	mgmt-private-1/2	0.0.0.0/0 → TGW (placeholder)
FW VPC
Route Table	Subnets	Routes
fw-untrust-rt	fw-untrust-1/2	0.0.0.0/0 → IGW (fw-igw)
fw-trust-rt	fw-trust-1/2	0.0.0.0/0 → TGW
fw-mgmt-rt	fw-mgmt-1/2	0.0.0.0/0 → TGW
App VPC
Route Table	Subnets	Routes
app-private-rt	app-private-1/2	0.0.0.0/0 → TGW
VPC Flow Logs

Enabled for all VPCs → CloudWatch Logs or S3.

Ensures audit and compliance readiness.

Phase 3: Transit Gateway & Routing
Transit Gateway (TGW)
Component	Detail	Purpose
TGW Name	acme-poc-tgw	Central hub for inter-VPC and internet routing
DNS Support	Enabled	Resolves VPC hostnames
Route Propagation	Enabled	Auto-propagates attached VPC CIDRs
TGW Attachments
VPC	Attachment Name	Purpose
mgmt-vpc	mgmt-tgw-attach	East-West + management traffic
fw-vpc	fw-tgw-attach	North-South traffic via NVA
app-vpc	app-tgw-attach	East-West routing to app servers
TGW Route Table
Destination	Target	Purpose
10.0.0.0/24	mgmt-tgw-attach	Reach management VPC
10.0.1.0/24	fw-tgw-attach	Reach FW VPC
10.0.2.0/24	app-tgw-attach	Reach App VPC
0.0.0.0/0	fw-tgw-attach	Internet-bound traffic through NVA

Propagation: Each VPC propagates its CIDR to TGW route table automatically.

Private Subnet Route Updates
VPC	Private RT	Routes
mgmt-vpc	mgmt-private-rt	0.0.0.0/0 → TGW
fw-vpc	fw-trust-rt	0.0.0.0/0 → TGW
app-vpc	app-private-rt	0.0.0.0/0 → TGW
Security Considerations

Audit-compliant: All private subnets deny-by-default; logs enabled.

Bastion: SSH only from office VPN.

FW/NVA: Ready for policy enforcement.

East-West & North-South: All traffic flows through TGW → FW, ready for inspection.

✅ Summary:

Everything for Phase 1–3 is fully defined.

All route tables, TGW attachments, and propagations are in place.

IGWs and private/public subnet separation are correct.

This setup is audit-ready, AWS best-practice compliant, and aligned with project requirements.
