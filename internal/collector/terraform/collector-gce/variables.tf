# The template's input contract: one variable per CLI-rendered input
# (gcpInputKeys). Changing this set is a template-version bump. No variable
# carries a credential — the CLI writes the secrets to Secret Manager itself,
# so nothing sensitive enters the deployment's input values or state.

variable "collector_config" {
  description = "Base64-encoded collector.toml. Contains no secrets, only $${ENV} references."
  type        = string
}

variable "collector_image" {
  description = "Collector container image (digest-pinned by the CLI)."
  type        = string
}

variable "cloud_sql_roles" {
  description = "Grant the collector's service account the Cloud SQL viewer, client and IAM-login roles. On for a Cloud SQL target only: the grants are project-wide (login_instances narrows the login one)."
  type        = bool
  default     = true
}

variable "alloydb_roles" {
  description = "Grant the collector's service account the AlloyDB viewer, client and IAM-login roles. On for an AlloyDB target only: the grants are project-wide, and AlloyDB's login role cannot be narrowed by an IAM Condition."
  type        = bool
  default     = false
}

variable "login_instances" {
  description = "Cloud SQL instance ids (comma-separated) the collector's IAM database login is restricted to, as an IAM Condition on roles/cloudsql.instanceUser: the monitored instance and its read replicas. Empty grants login to every Cloud SQL instance in the project."
  type        = string
  default     = ""
}

variable "network" {
  description = "VPC the collector instance joins (projects/<project>/global/networks/<name>)."
  type        = string
}

variable "subnetwork" {
  description = "Subnetwork in the region for the collector instance. Required on a custom-mode VPC; empty on an auto-mode VPC."
  type        = string
  default     = ""
}

variable "region" {
  description = "Region for the instance group (the databases' region)."
  type        = string
}

variable "runtime_service_account" {
  description = "Email of the service account this template creates for the collector VM. Its local part names the deployment's resources."
  type        = string
}

variable "stable_egress" {
  description = "Create a dedicated subnetwork routed through a Cloud NAT with a reserved static address, so the collector's outbound IP never changes (IP-allowlist-gated databases require it)."
  type        = bool
  default     = false
}

variable "nat_subnet_cidr" {
  description = "Unused CIDR in the VPC for the stable-egress subnetwork, e.g. 10.10.200.0/28. Required when stable_egress is true."
  type        = string
  default     = ""
}
