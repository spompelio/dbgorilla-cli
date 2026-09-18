# The DBGorilla collector on Google Cloud: a single-instance regional managed
# instance group running the collector container on Container-Optimized OS,
# deployed by Infrastructure Manager (or plain Terraform).
#
# template-version: v1.4
#
# This file is published, never embedded in the CLI. Secret values never reach
# it: the CLI writes them to Secret Manager before deploying (v1.2 passed them
# as input variables, which Infrastructure Manager retains on the deployment
# resource and in its Terraform state, readable by config.* read roles). This
# template only grants the instance's service account read access by name;
# the instance fetches the values at boot, so they never appear in instance
# metadata either.
#
# v1.4 scopes the IAM grants: each database service's roles only when it hosts
# the target (cloud_sql_roles / alloydb_roles), and Cloud SQL's IAM database
# login only to the monitored instances (login_instances, an IAM Condition).
# It also leaves the group's size alone on re-apply, so `dbg collector
# install` (update) and `upgrade` keep a stopped collector stopped.
#
# Naming contract with the CLI (a change is a version bump): every resource is
# named by the local part of var.runtime_service_account, which the CLI sets to
# the deployment name — including the three secrets the CLI creates before
# deploying: <name>-server-secret, <name>-db-password,
# <name>-instaclustr-api-key.
#
# The instance has no public IP. Image pulls and the collector's connection to
# DBGorilla need egress from the VPC (Cloud NAT, or an equivalent route).

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
  }
}

locals {
  name    = split("@", var.runtime_service_account)[0]
  project = split(".", split("@", var.runtime_service_account)[1])[0]
}

provider "google" {
  project = local.project
  region  = var.region
}

# --- identity ---------------------------------------------------------------

resource "google_service_account" "collector" {
  account_id   = local.name
  display_name = "DBGorilla collector"
}

# Read-only monitoring plus log writing for `dbg collector logs` always. The
# viewer, connect and IAM-login roles of a database service only when that
# service hosts the target: they are project-wide grants, so a source that is
# not a Google database (the instaclustr source) carries neither set, and a
# Cloud SQL target does not carry AlloyDB's.
#
# IAM database login is scoped one step further. On Cloud SQL,
# roles/cloudsql.instanceUser carries an IAM Condition naming the monitored
# instance and its read replicas (var.login_instances), so the collector's
# service account can log in nowhere else in the project. AlloyDB's login
# check exposes no resource name an IAM Condition can match, so
# roles/alloydb.databaseUser stays project-wide; the CLI says so when it
# deploys one. Either way the account only logs in where it has been
# registered as a database user.
locals {
  login_instances = compact(split(",", var.login_instances))
  login_condition = join(" || ", [
    for i in local.login_instances : "resource.name == \"projects/${local.project}/instances/${i}\""
  ])
}

resource "google_project_iam_member" "collector" {
  for_each = toset(concat(
    [
      "roles/monitoring.viewer",
      "roles/logging.logWriter",
    ],
    var.cloud_sql_roles ? [
      "roles/cloudsql.viewer",
      "roles/cloudsql.client",
      "roles/cloudsql.instanceUser",
    ] : [],
    var.alloydb_roles ? [
      "roles/alloydb.viewer",
      "roles/alloydb.client",
      "roles/alloydb.databaseUser",
    ] : [],
  ))
  project = local.project
  role    = each.value
  member  = "serviceAccount:${google_service_account.collector.email}"

  dynamic "condition" {
    for_each = each.value == "roles/cloudsql.instanceUser" && length(local.login_instances) > 0 ? [1] : []
    content {
      title       = "${local.name}-login"
      description = "DBGorilla collector: IAM database login only to the instances it monitors"
      expression  = "resource.type == \"sqladmin.googleapis.com/Instance\" && (${local.login_condition})"
    }
  }
}

# --- secrets ----------------------------------------------------------------

# The CLI creates these secrets before deploying and owns their lifecycle;
# this template never sees their values, only grants the collector's service
# account read access by the naming contract.
locals {
  secret_ids = [
    "${local.name}-server-secret",
    "${local.name}-db-password",
    "${local.name}-instaclustr-api-key",
  ]
}

resource "google_secret_manager_secret_iam_member" "collector" {
  for_each  = toset(local.secret_ids)
  secret_id = "projects/${local.project}/secrets/${each.value}"
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.collector.email}"
}

# --- stable egress (optional) -----------------------------------------------

# A dedicated subnetwork routed through a Cloud NAT that holds a reserved
# static address. The NAT is scoped to ONLY this subnetwork
# (LIST_OF_SUBNETWORKS), so it coexists with other subnet-scoped NATs — GCP
# allows several NATs on one network as long as their subnet sets are
# disjoint. A pre-existing NAT configured for ALL subnetworks in this region
# does block adding this one; the escape is stable_egress=false with the
# CLI's --allow-ip naming that NAT's address.
resource "google_compute_subnetwork" "egress" {
  count                    = var.stable_egress ? 1 : 0
  name                     = "${local.name}-egress"
  ip_cidr_range            = var.nat_subnet_cidr
  region                   = var.region
  network                  = var.network
  private_ip_google_access = true
}

resource "google_compute_address" "egress" {
  count  = var.stable_egress ? 1 : 0
  name   = "${local.name}-egress"
  region = var.region
}

resource "google_compute_router" "egress" {
  count   = var.stable_egress ? 1 : 0
  name    = "${local.name}-egress"
  region  = var.region
  network = var.network
}

resource "google_compute_router_nat" "egress" {
  count                              = var.stable_egress ? 1 : 0
  name                               = "${local.name}-egress"
  router                             = google_compute_router.egress[0].name
  region                             = var.region
  nat_ip_allocate_option             = "MANUAL_ONLY"
  nat_ips                            = [google_compute_address.egress[0].self_link]
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

  subnetwork {
    name                    = google_compute_subnetwork.egress[0].id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }
}

# --- the instance -----------------------------------------------------------

# Boot: fetch the secrets with the VM's own token (retrying while IAM
# bindings propagate), materialize the config from metadata, run the
# container. Secrets reach docker by variable name, never on a command line.
locals {
  startup_script = <<-EOT
    #!/bin/bash
    set -euo pipefail
    retry() {
      local attempts=$1
      shift
      for ((i = 1; i <= attempts; i++)); do
        "$@" && return 0
        sleep 10
      done
      return 1
    }
    metadata() {
      curl -sf -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/$1"
    }
    access_token() {
      metadata instance/service-accounts/default/token \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'
    }
    secret() {
      printf 'Authorization: Bearer %s' "$(access_token)" | curl -sf -H @- \
        "https://secretmanager.googleapis.com/v1/projects/${local.project}/secrets/$1/versions/latest:access" \
        | python3 -c 'import json,sys,base64; print(base64.b64decode(json.load(sys.stdin)["payload"]["data"]).decode())'
    }
    DBG_SERVER_SECRET=$(retry 30 secret "${local.name}-server-secret")
    DBG_DB_PASSWORD=$(retry 30 secret "${local.name}-db-password")
    INSTACLUSTR_API_KEY=$(retry 30 secret "${local.name}-instaclustr-api-key")
    export DBG_SERVER_SECRET DBG_DB_PASSWORD INSTACLUSTR_API_KEY
    mkdir -p /var/lib/dbgorilla
    retry 30 metadata instance/attributes/collector-config | base64 -d > /var/lib/dbgorilla/collector.toml
    docker run -d --name dbg-collector --restart=always --network=host \
      -v /var/lib/dbgorilla/collector.toml:/etc/dbgorilla/collector.toml:ro \
      -e DBG_SERVER_SECRET \
      -e DBG_DB_PASSWORD \
      -e INSTACLUSTR_API_KEY \
      "${var.collector_image}" --config-file /etc/dbgorilla/collector.toml
  EOT
}

resource "google_compute_instance_template" "collector" {
  name_prefix  = "${local.name}-"
  machine_type = "e2-small"
  region       = var.region

  disk {
    source_image = "projects/cos-cloud/global/images/family/cos-stable"
    auto_delete  = true
    boot         = true
    disk_size_gb = 20
  }

  network_interface {
    # Under stable egress the instance lives in the NAT-routed subnetwork the
    # template owns; otherwise in the caller's (or the auto-mode default).
    network    = var.network
    subnetwork = var.stable_egress ? google_compute_subnetwork.egress[0].id : (var.subnetwork == "" ? null : var.subnetwork)
  }

  service_account {
    email  = google_service_account.collector.email
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  metadata = {
    startup-script         = local.startup_script
    collector-config       = var.collector_config
    google-logging-enabled = "true"
    cos-update-strategy    = "update_enabled"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "google_compute_region_instance_group_manager" "collector" {
  name               = local.name
  region             = var.region
  base_instance_name = local.name
  target_size        = 1

  # A zonal capacity stockout must not brick the deploy. The default EVEN
  # shape pins the single instance to its assigned zone and recreates it there
  # forever (observed live 2026-09-03: us-central1-f out of e2-small, the
  # group never converged and no CLI lever could move it). ANY lets a recreate
  # land in whichever zone has capacity.
  distribution_policy_target_shape = "ANY"

  version {
    instance_template = google_compute_instance_template.collector.id
  }

  update_policy {
    type                  = "PROACTIVE"
    minimal_action        = "REPLACE"
    max_surge_fixed       = 0
    max_unavailable_fixed = 3
    replacement_method    = "RECREATE"
  }

  # `dbg collector stop` resizes the group to 0 and `start` back to 1. An
  # update or upgrade re-applies this template and must not undo that.
  lifecycle {
    ignore_changes = [target_size]
  }

  # The instance reads its secrets at boot; do not start it before it may
  # (the secrets themselves exist before the deploy — the CLI writes them
  # first). Under stable egress it must also not start before its route to
  # the internet exists, or the boot script times out fetching the image.
  depends_on = [
    google_project_iam_member.collector,
    google_secret_manager_secret_iam_member.collector,
    google_compute_router_nat.egress,
  ]
}

output "instance_group" {
  value = google_compute_region_instance_group_manager.collector.instance_group
}

output "service_account" {
  value = google_service_account.collector.email
}

output "egress_ip" {
  # The reserved static address all collector egress leaves through under
  # stable egress — the address to allowlist on IP-gated databases.
  value = var.stable_egress ? google_compute_address.egress[0].address : ""
}
