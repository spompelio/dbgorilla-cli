package collector

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The template's input contract and version live in the Go constants the CLI
// deploys with and in the published Terraform files; these pins keep the two
// together.

func TestGcpTemplateContract_VersionMatches(t *testing.T) {
	main, err := os.ReadFile("terraform/collector-gce/main.tf")
	if err != nil {
		t.Fatalf("read template: %v", err)
	}
	marker := regexp.MustCompile(`(?m)^# template-version: (\S+)$`).FindSubmatch(main)
	if marker == nil {
		t.Fatal("main.tf must carry a '# template-version: <v>' marker")
	}
	if got := string(marker[1]); got != GcpTemplateVersion {
		t.Fatalf("template says %s, the CLI deploys %s — bump them together", got, GcpTemplateVersion)
	}
}

func TestGcpTemplateContract_VariablesMatchInputKeys(t *testing.T) {
	raw, err := os.ReadFile("terraform/collector-gce/variables.tf")
	if err != nil {
		t.Fatalf("read variables: %v", err)
	}
	var declared []string
	for _, m := range regexp.MustCompile(`(?m)^variable "([^"]+)"`).FindAllSubmatch(raw, -1) {
		declared = append(declared, string(m[1]))
	}
	sort.Strings(declared)
	contract := append([]string{}, gcpInputKeys...)
	sort.Strings(contract)
	if strings.Join(declared, ",") != strings.Join(contract, ",") {
		t.Fatalf("template variables %v != the CLI's input keys %v — bump the template contract",
			declared, contract)
	}
}

// Secret values never enter the template: no secret-shaped variable, no
// secret_data, and the boot script + IAM grants address the secrets by the
// names EnsureGcpSecrets writes.
func TestGcpTemplateContract_SecretsStayOut(t *testing.T) {
	main, err := os.ReadFile("terraform/collector-gce/main.tf")
	if err != nil {
		t.Fatalf("read template: %v", err)
	}
	vars, err := os.ReadFile("terraform/collector-gce/variables.tf")
	if err != nil {
		t.Fatalf("read variables: %v", err)
	}
	for _, forbidden := range []string{"secret_data", "google_secret_manager_secret_version"} {
		if strings.Contains(string(main), forbidden) {
			t.Errorf("main.tf must not carry secret values (%q found) — the CLI writes them to Secret Manager", forbidden)
		}
	}
	if regexp.MustCompile(`(?m)^\s*sensitive\s*=`).Match(vars) {
		t.Error("no template variable should need sensitive = true — none may carry a credential")
	}
	for _, id := range GcpSecretIDs("dbgorilla-collector") {
		ref := strings.Replace(id, "dbgorilla-collector", "${local.name}", 1)
		if !strings.Contains(string(main), ref) {
			t.Errorf("main.tf must address secret %s (the CLI's naming contract)", ref)
		}
	}
	if !strings.Contains(string(main), `secret_id = "projects/${local.project}/secrets/${each.value}"`) ||
		!strings.Contains(string(main), "roles/secretmanager.secretAccessor") {
		t.Error("main.tf must grant the collector's service account access to the CLI-written secrets")
	}
}

func TestGcpTemplateContract_NamingContractHolds(t *testing.T) {
	sa := GcpRuntimeServiceAccountFor("dbgorilla-collector", "acme-prod")
	if sa != "dbgorilla-collector@acme-prod.iam.gserviceaccount.com" {
		t.Fatalf("service-account naming contract changed: %s", sa)
	}
	main, err := os.ReadFile("terraform/collector-gce/main.tf")
	if err != nil {
		t.Fatalf("read template: %v", err)
	}
	for _, want := range []string{"name               = local.name", "base_instance_name = local.name"} {
		if !strings.Contains(string(main), want) {
			t.Errorf("the MIG and its instances must carry the deployment name (%q missing)", want)
		}
	}
	if got := migPath("acme-prod", "us-central1", "dbgorilla-collector"); !strings.HasSuffix(got, "/instanceGroupManagers/dbgorilla-collector") {
		t.Errorf("day-2 helpers must address the MIG by the deployment name, got %s", got)
	}
}

// What `dbg collector logs` and the boot sequence rely on in the template.
func TestGcpTemplateContract_RuntimePins(t *testing.T) {
	raw, err := os.ReadFile("terraform/collector-gce/main.tf")
	if err != nil {
		t.Fatalf("read template: %v", err)
	}
	// `terraform fmt` aligns the `=` of a block's attributes to its longest
	// key, so adding an unrelated attribute re-spaces the lines pinned here.
	// Collapse runs of spaces first: these pins are about what the template
	// says, not how it is laid out.
	main := regexp.MustCompile(` +`).ReplaceAllString(string(raw), " ")
	for _, want := range []string{
		`google-logging-enabled = "true"`,
		`--name ` + gcpCollectorContainerName,
		`subnetwork = var.stable_egress ? google_compute_subnetwork.egress[0].id : (var.subnetwork == "" ? null : var.subnetwork)`,
		"depends_on = [",
		// stop/start resize the group; an update or upgrade must not undo it.
		"ignore_changes = [target_size]",
		// A private Artifact Registry image pulls as the VM's own identity,
		// with Docker's config somewhere COS lets root write.
		`export HOME=/var/lib/dbgorilla DOCKER_CONFIG=/var/lib/dbgorilla/.docker`,
		`docker-credential-gcr configure-docker --registries="$registry"`,
		`"$IMAGE" --config-file /etc/dbgorilla/collector.toml`,
	} {
		if !strings.Contains(main, want) {
			t.Errorf("main.tf must contain %q", want)
		}
	}
}

func TestGcpDeployInputs_RendersTheFullContract(t *testing.T) {
	inputs, err := GcpDeployInputs(GcpStackInput{
		AgentID: "agent123", TenantID: "tenant123",
		Image: "example.registry/collector@sha256:abc",
		Targets: []GcpTarget{{
			ProviderType: "cloud_sql", Project: "p", Region: "us-central1",
			InstanceID: "orders-pg", Engine: "postgres", Host: "h.", Port: 5432,
			AuthMethod: "gcp_iam", User: "u",
		}},
		Network:         "projects/p/global/networks/default",
		Region:          "us-central1",
		DeploymentName:  "dbgorilla-collector",
		Project:         "p",
		CommandsEnabled: true,
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var keys []string
	for k := range inputs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if strings.Join(keys, ",") != strings.Join(gcpInputKeys, ",") {
		t.Fatalf("rendered inputs %v != contract %v", keys, gcpInputKeys)
	}
	if inputs["cloud_sql_roles"] != "true" || inputs["alloydb_roles"] != "false" {
		t.Fatalf("a Cloud SQL install grants the Cloud SQL roles and not AlloyDB's, got cloud_sql=%s alloydb=%s",
			inputs["cloud_sql_roles"], inputs["alloydb_roles"])
	}
	if inputs["login_instances"] != "orders-pg" {
		t.Fatalf("IAM login is scoped to the monitored instance, got login_instances=%q", inputs["login_instances"])
	}
	decoded, err := DecodeConfig(inputs["collector_config"])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Credentials reach the config only as env-var references the boot
	// script resolves from Secret Manager; GcpStackInput cannot carry one.
	if !strings.Contains(decoded, "${DBG_SERVER_SECRET}") {
		t.Fatalf("config must reference the secret env var:\n%s", decoded)
	}
}

// The IAM Condition names every instance the collector logs in to; the
// opt-out and AlloyDB (whose login cannot be conditioned) leave it empty.
func TestGcpDeployInputs_LoginScope(t *testing.T) {
	render := func(t *testing.T, in GcpStackInput) map[string]string {
		t.Helper()
		in.AgentID, in.TenantID, in.Image = "a", "t", "img"
		in.Network, in.Region, in.DeploymentName, in.Project =
			"projects/p/global/networks/default", "us-central1", "dbgorilla-collector", "p"
		inputs, err := GcpDeployInputs(in)
		if err != nil {
			t.Fatalf("render: %v", err)
		}
		return inputs
	}
	cloudSQL := GcpTarget{ProviderType: "cloud_sql", Project: "p", Region: "us-central1", InstanceID: "orders-pg",
		Replicas: []string{"orders-pg-r1", "orders-pg-r2"}, Engine: "postgres", Host: "h.", Port: 5432, AuthMethod: "gcp_iam", User: "u"}
	alloy := GcpTarget{ProviderType: "alloydb", Project: "p", Region: "us-central1", ClusterID: "orders", InstanceID: "orders-primary",
		Engine: "postgres", Host: "10.0.0.5", Port: 5432, AuthMethod: "gcp_iam", User: "u"}

	t.Run("primary and replicas", func(t *testing.T) {
		inputs := render(t, GcpStackInput{Targets: []GcpTarget{cloudSQL}})
		if inputs["login_instances"] != "orders-pg,orders-pg-r1,orders-pg-r2" {
			t.Errorf("login_instances = %q", inputs["login_instances"])
		}
	})
	t.Run("opt-out drops the condition, not the roles", func(t *testing.T) {
		inputs := render(t, GcpStackInput{Targets: []GcpTarget{cloudSQL}, AllowProjectWideLogin: true})
		if inputs["login_instances"] != "" || inputs["cloud_sql_roles"] != "true" {
			t.Errorf("login_instances = %q, cloud_sql_roles = %q", inputs["login_instances"], inputs["cloud_sql_roles"])
		}
	})
	t.Run("alloydb grants its own roles, unconditioned", func(t *testing.T) {
		inputs := render(t, GcpStackInput{Targets: []GcpTarget{alloy}})
		if inputs["alloydb_roles"] != "true" || inputs["cloud_sql_roles"] != "false" || inputs["login_instances"] != "" {
			t.Errorf("cloud_sql_roles=%s alloydb_roles=%s login_instances=%q",
				inputs["cloud_sql_roles"], inputs["alloydb_roles"], inputs["login_instances"])
		}
	})
}

// What the template does with login_instances: an IAM Condition on the Cloud
// SQL login role only, in the resource form Cloud SQL enforces; and the roles
// gated per service.
func TestGcpTemplateContract_LoginCondition(t *testing.T) {
	raw, err := os.ReadFile("terraform/collector-gce/main.tf")
	if err != nil {
		t.Fatalf("read template: %v", err)
	}
	main := regexp.MustCompile(` +`).ReplaceAllString(string(raw), " ")
	for _, want := range []string{
		`compact(split(",", var.login_instances))`,
		`resource.name == \"projects/${local.project}/instances/${i}\"`,
		`for_each = each.value == "roles/cloudsql.instanceUser" && length(local.login_instances) > 0 ? [1] : []`,
		`expression = "resource.type == \"sqladmin.googleapis.com/Instance\" && (${local.login_condition})"`,
		`var.cloud_sql_roles ? [`,
		`var.alloydb_roles ? [`,
	} {
		if !strings.Contains(main, want) {
			t.Errorf("main.tf must contain %q", want)
		}
	}
	if strings.Contains(main, "database_roles") {
		t.Error("database_roles was replaced by the per-service gates")
	}
}

// An update moves a deployment forward to this CLI's template, never back.
func TestGcpTemplateVersions(t *testing.T) {
	if v := GcpTemplateSourceVersion("gs://dbgorilla-collector-templates/collector/gce/v1.3/"); v != "v1.3" {
		t.Errorf("source version = %q", v)
	}
	if v := GcpTemplateSourceVersion(HostedGcpTemplateSource()); v != GcpTemplateVersion {
		t.Errorf("the hosted source must carry the pinned version, got %q", v)
	}
	for _, tc := range []struct {
		a, b string
		cmp  int
		ok   bool
	}{
		{"v1.3", "v1.4", -1, true},
		{"v1.10", "v1.9", 1, true},
		{"v2.0", "v1.9", 1, true},
		{"v1.4", "v1.4", 0, true},
		{"dev", "v1.4", 0, false},
		{"1.4", "v1.4", 0, false},
	} {
		cmp, ok := CompareGcpTemplateVersions(tc.a, tc.b)
		if cmp != tc.cmp || ok != tc.ok {
			t.Errorf("compare(%s, %s) = %d, %v; want %d, %v", tc.a, tc.b, cmp, ok, tc.cmp, tc.ok)
		}
	}
}
