package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dbgorilla/dbgorilla-cli/internal/collector"
	"github.com/spf13/cobra"
)

// The `--target gcp` install, driven end to end with every Google Cloud call
// faked through the seams.

// --- seams -----------------------------------------------------------------

func stubGCPOK(t *testing.T) {
	t.Helper()
	stubGcpAvailable(t, nil)
	stubGcpIdentity(t, "dev@example.com", nil)
	stubGcpProject(t, "acme-prod", nil)
	stubGcpDeploymentStatus(t, "", nil)
	stubResolveGcpSubnetwork(t, "", nil)
	stubGcpSubnetworkPGA(t, true, nil)
	stubRemoteDigest(t, nil)
	stubWaitGcpMigStable(t, nil)
}

// --- update / upgrade seams -------------------------------------------------

func stubReadGcpDeployment(t *testing.T, spec *collector.GcpDeploymentSpec, err error) *int {
	t.Helper()
	calls := new(int)
	orig := readGcpDeployment
	readGcpDeployment = func(string, string, string) (*collector.GcpDeploymentSpec, error) {
		*calls++
		return spec, err
	}
	t.Cleanup(func() { readGcpDeployment = orig })
	return calls
}

func stubUpgradeGcpImage(t *testing.T, err error) *[]string {
	t.Helper()
	images := new([]string)
	orig := upgradeGcpImage
	upgradeGcpImage = func(project, region, name, image string) error {
		if project != "acme-prod" || region != "us-central1" || name != "dbg-test" {
			t.Errorf("upgrade addressed %s/%s/%s", project, region, name)
		}
		*images = append(*images, image)
		return err
	}
	t.Cleanup(func() { upgradeGcpImage = orig })
	return images
}

func stubWaitGcpMigStable(t *testing.T, err error) *int {
	t.Helper()
	calls := new(int)
	orig := waitGcpMigStable
	waitGcpMigStable = func(string, string, string) error { *calls++; return err }
	t.Cleanup(func() { waitGcpMigStable = orig })
	return calls
}

func stubEnsureGcpDBPassword(t *testing.T, err error) *[]string {
	t.Helper()
	passwords := new([]string)
	orig := ensureGcpDBPassword
	ensureGcpDBPassword = func(_, _ string, password string) error {
		*passwords = append(*passwords, password)
		return err
	}
	t.Cleanup(func() { ensureGcpDBPassword = orig })
	return passwords
}

// storedGcpConfig renders the collector.toml an earlier install stored on the
// deployment: identity agent-old/tenant-old, its own endpoints, one target.
func storedGcpConfig(t *testing.T, target collector.GcpTarget) string {
	t.Helper()
	cfg, err := collector.GcpConfigTOML("agent-old", "tenant-old", []collector.GcpTarget{target}, collector.Endpoints{
		OpampBaseURL: "https://opamp.example", OtlpBaseURL: "https://otlp.example:4318", AuthBaseURL: "https://auth.example",
	}, true)
	if err != nil {
		t.Fatalf("render stored config: %v", err)
	}
	return cfg
}

// deployedGcpSpec is a deployment as an earlier CLI applied it: template
// v1.3 (database_roles, no login_instances), its own networking and image.
func deployedGcpSpec(t *testing.T, configTOML, templateVersion string) *collector.GcpDeploymentSpec {
	t.Helper()
	encoded, err := collector.EncodeConfig(configTOML)
	if err != nil {
		t.Fatalf("encode stored config: %v", err)
	}
	return &collector.GcpDeploymentSpec{
		State:          "ACTIVE",
		TemplateSource: "gs://dbgorilla-collector-templates/collector/gce/" + templateVersion,
		ServiceAccount: "projects/acme-prod/serviceAccounts/deployer@acme-prod.iam.gserviceaccount.com",
		Inputs: map[string]string{
			"collector_config":        encoded,
			"collector_image":         "example.registry/collector@sha256:old",
			"database_roles":          "true",
			"nat_subnet_cidr":         "",
			"network":                 "projects/acme-prod/global/networks/prod-vpc",
			"region":                  "us-central1",
			"runtime_service_account": "dbg-test@acme-prod.iam.gserviceaccount.com",
			"stable_egress":           "false",
			"subnetwork":              "projects/acme-prod/regions/us-central1/subnetworks/prod-subnet",
		},
	}
}

// installedGcpTarget is completeGcpTarget as the earlier install settled it:
// IAM auth, one database, one command.
func installedGcpTarget() collector.GcpTarget {
	t := completeGcpTarget()
	t.Replicas = nil // the replica appeared after the install
	t.AuthMethod = "gcp_iam"
	t.User = "dbg-test@acme-prod.iam"
	t.Databases = []string{"app"}
	t.Commands = []string{"explain"}
	return t
}

func saveGcpState(t *testing.T, image string) *collector.State {
	t.Helper()
	st := &collector.State{AgentID: "agent-old", TenantID: "tenant-old", Target: "gcp", Image: image,
		TargetName: "prod-pg", Project: "acme-prod", Region: "us-central1", DeploymentName: "dbg-test"}
	if err := collector.SaveState(st); err != nil {
		t.Fatal(err)
	}
	return st
}

func stubResolveGcpSubnetwork(t *testing.T, subnetwork string, err error) {
	t.Helper()
	orig := resolveGcpSubnetwork
	resolveGcpSubnetwork = func(string, string) (string, error) { return subnetwork, err }
	t.Cleanup(func() { resolveGcpSubnetwork = orig })
}

func stubGcpSubnetworkPGA(t *testing.T, enabled bool, err error) {
	t.Helper()
	orig := gcpSubnetworkPGA
	gcpSubnetworkPGA = func(_, subnetwork, _ string) (bool, string, error) {
		return enabled, subnetwork, err
	}
	t.Cleanup(func() { gcpSubnetworkPGA = orig })
}

func stubGcpAvailable(t *testing.T, err error) *int {
	t.Helper()
	calls := new(int)
	orig := gcpAvailable
	gcpAvailable = func() error { *calls++; return err }
	t.Cleanup(func() { gcpAvailable = orig })
	return calls
}

func stubGcpIdentity(t *testing.T, email string, err error) {
	t.Helper()
	orig := gcpIdentity
	gcpIdentity = func() (string, error) { return email, err }
	t.Cleanup(func() { gcpIdentity = orig })
}

func stubGcpProject(t *testing.T, project string, err error) {
	t.Helper()
	orig := gcpProject
	gcpProject = func() (string, error) { return project, err }
	t.Cleanup(func() { gcpProject = orig })
}

// stubGcpDiscover answers discovery with target; explicit seed fields win.
func stubGcpDiscover(t *testing.T, target collector.GcpTarget, err error) {
	t.Helper()
	orig := discoverGcpTarget
	discoverGcpTarget = func(id, provider string, into collector.GcpTarget) (collector.GcpTarget, error) {
		if err != nil {
			return into, err
		}
		out := target
		out.Project = into.Project
		if id != "" {
			out.InstanceID = id
		}
		if provider != "" {
			out.ProviderType = provider
		}
		if len(into.Databases) > 0 {
			out.Databases = into.Databases
		}
		if into.User != "" {
			out.User = into.User
		}
		return out, nil
	}
	t.Cleanup(func() { discoverGcpTarget = orig })
}

func stubGcpDeploymentStatus(t *testing.T, status string, err error) {
	t.Helper()
	orig := gcpDeploymentStatus
	gcpDeploymentStatus = func(string, string, string) (string, error) { return status, err }
	t.Cleanup(func() { gcpDeploymentStatus = orig })
}

type gcpDeployCall struct {
	count  int
	deploy collector.GcpDeploy
	// The Secret Manager seam: what a real install would have written there,
	// and whether the rollback removed it.
	secretsWritten int
	secrets        collector.GcpSecretValues
	secretsDeleted int
}

func stubGcpDeploy(t *testing.T, err error) *gcpDeployCall {
	t.Helper()
	rec := &gcpDeployCall{}
	orig := runGcpDeploy
	runGcpDeploy = func(d collector.GcpDeploy) error {
		rec.count++
		rec.deploy = d
		return err
	}
	t.Cleanup(func() { runGcpDeploy = orig })
	stubGcpSecrets(t, rec, nil)
	return rec
}

// stubGcpSecrets fakes the Secret Manager seam, recording into rec.
func stubGcpSecrets(t *testing.T, rec *gcpDeployCall, ensureErr error) {
	t.Helper()
	origEnsure, origDelete := ensureGcpSecrets, deleteGcpSecrets
	ensureGcpSecrets = func(_, _ string, v collector.GcpSecretValues) error {
		rec.secretsWritten++
		rec.secrets = v
		return ensureErr
	}
	deleteGcpSecrets = func(string, string) error {
		rec.secretsDeleted++
		return nil
	}
	t.Cleanup(func() { ensureGcpSecrets, deleteGcpSecrets = origEnsure, origDelete })
}

func stubDeleteGcpDeployment(t *testing.T, err error) *bool {
	t.Helper()
	called := new(bool)
	orig := deleteGcpDeployment
	deleteGcpDeployment = func(string, string, string) error { *called = true; return err }
	t.Cleanup(func() { deleteGcpDeployment = orig })
	return called
}

// gcpCmd builds a command carrying the flags the GCP install path reads.
func gcpCmd(t *testing.T) *cobra.Command {
	t.Helper()
	c := baseCmd()
	c.Flags().String("target", "gcp", "")
	c.Flags().String("db-instance-id", "", "")
	c.Flags().String("provider-type", "", "")
	c.Flags().String("db-name", "", "")
	c.Flags().String("db-user", "", "")
	c.Flags().String("db-password", "", "")
	c.Flags().String("image", collector.DefaultImage, "")
	c.Flags().String("commands", "", "")
	c.Flags().Bool("enable-commands", true, "")
	c.Flags().Bool("yes", false, "")
	c.Flags().Bool("dry-run", false, "")
	c.Flags().String("auth-url", "", "")
	c.Flags().String("otlp-url", "", "")
	c.Flags().String("project", "", "")
	c.Flags().String("deployment-name", "dbg-test", "")
	c.Flags().String("template-source", "", "")
	c.Flags().String("deploy-service-account", "projects/acme-prod/serviceAccounts/deployer@acme-prod.iam.gserviceaccount.com", "")
	c.Flags().String("network", "", "")
	c.Flags().String("subnetwork", "", "")
	c.Flags().Bool("allow-project-wide-login", false, "")
	c.Flags().Bool("allow-downgrade", false, "")
	c.SetContext(context.Background())
	return c
}

// completeGcpTarget is a fully-discovered Cloud SQL Postgres instance with IAM
// auth on.
func completeGcpTarget() collector.GcpTarget {
	return collector.GcpTarget{
		ProviderType: "cloud_sql",
		Project:      "acme-prod",
		Region:       "us-central1",
		InstanceID:   "prod-pg",
		Engine:       "postgres",
		Host:         "abc.us-central1.sql-psa.goog.",
		Port:         5432,
		ServerCaMode: "GOOGLE_MANAGED_CAS_CA",
		IamEnabled:   true,
		Network:      "projects/acme-prod/global/networks/default",
		Replicas:     []string{"prod-pg-replica"},
	}
}

// alloyDBGcpTarget is a discovered AlloyDB cluster with its primary.
func alloyDBGcpTarget() collector.GcpTarget {
	return collector.GcpTarget{
		ProviderType: "alloydb",
		Project:      "acme-prod",
		Region:       "us-central1",
		ClusterID:    "orders",
		InstanceID:   "orders-primary",
		Engine:       "postgres",
		Host:         "10.0.0.5",
		Port:         5432,
		IamEnabled:   true,
		Network:      "projects/acme-prod/global/networks/default",
	}
}

// decodedConfig returns the collector.toml a deploy carried.
func decodedConfig(t *testing.T, d collector.GcpDeploy) string {
	t.Helper()
	cfg, err := collector.DecodeConfig(d.Inputs["collector_config"])
	if err != nil {
		t.Fatalf("decode config: %v", err)
	}
	return cfg
}

// --- install ---------------------------------------------------------------

func TestRunInstallGCP_HappyPath(t *testing.T) {
	isolate(t)
	writeTokens(t)
	stubGCPOK(t)
	stubGcpDiscover(t, completeGcpTarget(), nil)
	deploys := stubGcpDeploy(t, nil)
	srv := installServer(t, "agent-gcp")
	defer srv.Close()

	c := gcpCmd(t)
	mustSet(t, c, "api-url", srv.URL)
	mustSet(t, c, "yes", "true")

	var err error
	out := capture(t, func() { err = runInstallGCP(c) })
	if err != nil {
		t.Fatalf("runInstallGCP: %v\n%s", err, out)
	}
	if deploys.count != 1 || deploys.deploy.DryRun {
		t.Fatalf("want exactly one real deploy, got %+v", deploys)
	}
	d := deploys.deploy
	if d.Project != "acme-prod" || d.Region != "us-central1" || d.DeploymentName != "dbg-test" {
		t.Errorf("deployment addressed wrongly: %+v", d)
	}
	if d.ServiceAccount == "" || d.TemplateSource != collector.HostedGcpTemplateSource() {
		t.Errorf("deploy must carry the actuating account and the published template, got %+v", d)
	}
	if d.Inputs["runtime_service_account"] != "dbg-test@acme-prod.iam.gserviceaccount.com" {
		t.Errorf("runtime SA = %q", d.Inputs["runtime_service_account"])
	}
	cfg := decodedConfig(t, d)
	for _, want := range []string{`method = "gcp_iam"`, `user = "dbg-test@acme-prod.iam"`, `ssl_mode = "verify-full"`, `enabled = true`} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %s:\n%s", want, cfg)
		}
	}
	if strings.Contains(cfg, "sek") || deploys.secrets.ServerSecret != "sek" {
		t.Error("the server secret goes to Secret Manager, never the config")
	}
	if deploys.secretsWritten != 1 {
		t.Errorf("secrets should be written exactly once before the deploy, got %d", deploys.secretsWritten)
	}
	if d.Inputs["server_secret"] != "" || d.Inputs["db_password"] != "" {
		t.Error("no credential may enter the deployment's input values")
	}
	if !strings.Contains(d.Inputs["collector_image"], "@sha256:") {
		t.Errorf("image should be pinned, got %s", d.Inputs["collector_image"])
	}
	// The IAM grants are Cloud SQL's only, with login conditioned on the
	// primary and its replica — and the scope is said out loud.
	if d.Inputs["login_instances"] != "prod-pg,prod-pg-replica" || d.Inputs["cloud_sql_roles"] != "true" || d.Inputs["alloydb_roles"] != "false" {
		t.Errorf("IAM inputs = login_instances=%q cloud_sql_roles=%q alloydb_roles=%q",
			d.Inputs["login_instances"], d.Inputs["cloud_sql_roles"], d.Inputs["alloydb_roles"])
	}
	if !strings.Contains(out, "IAM database login scoped to prod-pg, prod-pg-replica") {
		t.Errorf("the login scope should be printed, got:\n%s", out)
	}
	// State is saved before the slow deploy.
	st, lerr := collector.LoadState()
	if lerr != nil || st == nil {
		t.Fatalf("state not saved: %v", lerr)
	}
	if st.AgentID != "agent-gcp" || !st.IsGCP() || st.Project != "acme-prod" || st.Region != "us-central1" || st.DeploymentName != "dbg-test" {
		t.Errorf("state = %+v", st)
	}
	// IAM auth needs the operator to register the service account as a user,
	// then grant it; the SQL is the GCP script, not the RDS one.
	if !strings.Contains(out, "gcloud sql users create dbg-test@acme-prod.iam.gserviceaccount.com") {
		t.Errorf("grant guidance should name the gcloud step, got:\n%s", out)
	}
	if !strings.Contains(out, `GRANT pg_monitor TO "dbg-test@acme-prod.iam";`) ||
		strings.Contains(out, "rds_iam") || strings.Contains(out, "CREATE USER") {
		t.Errorf("grant guidance should be the GCP script, got:\n%s", out)
	}
	if !strings.Contains(out, "dbg collector status") {
		t.Errorf("the operator should be pointed at status to confirm the connection, got:\n%s", out)
	}
}

// Where the collector's IAM database login reaches is said out loud: scoped
// by default, project-wide only by explicit opt-out, and project-wide on
// AlloyDB because nothing can narrow it there.
func TestRunInstallGCP_LoginScope(t *testing.T) {
	setup := func(t *testing.T, target collector.GcpTarget) (*cobra.Command, *gcpDeployCall) {
		t.Helper()
		isolate(t)
		writeTokens(t)
		stubGCPOK(t)
		stubGcpDiscover(t, target, nil)
		deploys := stubGcpDeploy(t, nil)
		srv := installServer(t, "agent-gcp")
		t.Cleanup(srv.Close)
		c := gcpCmd(t)
		mustSet(t, c, "api-url", srv.URL)
		mustSet(t, c, "yes", "true")
		return c, deploys
	}
	t.Run("opt-out widens the login and warns", func(t *testing.T) {
		c, deploys := setup(t, completeGcpTarget())
		mustSet(t, c, "allow-project-wide-login", "true")
		var err error
		out := capture(t, func() { err = runInstallGCP(c) })
		if err != nil {
			t.Fatalf("runInstallGCP: %v\n%s", err, out)
		}
		if got := deploys.deploy.Inputs["login_instances"]; got != "" {
			t.Errorf("login_instances = %q, want empty", got)
		}
		if deploys.deploy.Inputs["cloud_sql_roles"] != "true" {
			t.Error("the opt-out widens the login; it does not drop the roles")
		}
		if !strings.Contains(out, "--allow-project-wide-login") || !strings.Contains(out, "any Cloud SQL instance in project acme-prod") {
			t.Errorf("the opt-out must be warned about, got:\n%s", out)
		}
	})
	t.Run("alloydb is project-wide and says so", func(t *testing.T) {
		c, deploys := setup(t, alloyDBGcpTarget())
		var err error
		out := capture(t, func() { err = runInstallGCP(c) })
		if err != nil {
			t.Fatalf("runInstallGCP: %v\n%s", err, out)
		}
		in := deploys.deploy.Inputs
		if in["alloydb_roles"] != "true" || in["cloud_sql_roles"] != "false" || in["login_instances"] != "" {
			t.Errorf("IAM inputs = login_instances=%q cloud_sql_roles=%q alloydb_roles=%q",
				in["login_instances"], in["cloud_sql_roles"], in["alloydb_roles"])
		}
		if !strings.Contains(out, "AlloyDB IAM login cannot be scoped") || strings.Contains(out, "login scoped to") {
			t.Errorf("AlloyDB's project-wide login must be warned about, got:\n%s", out)
		}
	})
	t.Run("dry run shows the scope", func(t *testing.T) {
		c, _ := setup(t, completeGcpTarget())
		mustSet(t, c, "dry-run", "true")
		var err error
		out := capture(t, func() { err = runInstallGCP(c) })
		if err != nil {
			t.Fatalf("runInstallGCP: %v\n%s", err, out)
		}
		if !strings.Contains(out, "login_instances = prod-pg,prod-pg-replica") {
			t.Errorf("the dry run should show the condition's instances, got:\n%s", out)
		}
	})
}

func TestRunInstallGCP_DryRunMintsNothing(t *testing.T) {
	isolate(t)
	writeTokens(t)
	stubGCPOK(t)
	stubGcpDiscover(t, completeGcpTarget(), nil)
	deploys := stubGcpDeploy(t, nil)
	srv := installServer(t, "agent-gcp")
	defer srv.Close()

	c := gcpCmd(t)
	mustSet(t, c, "api-url", srv.URL)
	mustSet(t, c, "dry-run", "true")
	mustSet(t, c, "deploy-service-account", "") // not needed to probe

	var err error
	out := capture(t, func() { err = runInstallGCP(c) })
	if err != nil {
		t.Fatalf("dry run: %v\n%s", err, out)
	}
	if !deploys.deploy.DryRun {
		t.Error("the deploy must be marked dry-run")
	}
	if st, _ := collector.LoadState(); st != nil {
		t.Error("a dry run must not save state")
	}
	// The rendered inputs are shown with the config decoded to readable TOML.
	for _, want := range []string{"no identity minted", "collector_config =", `type = "cloud_sql"`, "runtime_service_account = dbg-test@acme-prod.iam.gserviceaccount.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("output should contain %q, got:\n%s", want, out)
		}
	}
}

func TestRunInstallGCP_FailedDeployRollsBackIdentityAndDeployment(t *testing.T) {
	isolate(t)
	writeTokens(t)
	stubGCPOK(t)
	stubGcpDiscover(t, completeGcpTarget(), nil)
	stubGcpDeploy(t, errors.New("terraform apply failed"))
	deleted := stubDeleteGcpDeployment(t, nil)
	srv := installServer(t, "agent-gcp")
	defer srv.Close()

	c := gcpCmd(t)
	mustSet(t, c, "api-url", srv.URL)
	mustSet(t, c, "yes", "true")

	var err error
	out := capture(t, func() { err = runInstallGCP(c) })
	if err == nil || !strings.Contains(err.Error(), "Rolled back") {
		t.Fatalf("a failed deploy must fail the install saying it rolled back, got %v", err)
	}
	if !*deleted {
		t.Error("the deployment must be deleted on rollback")
	}
	if !strings.Contains(out, "rolling back the provisioned identity and deployment") {
		t.Errorf("the rollback should be announced, got: %s", out)
	}
	if st, _ := collector.LoadState(); st != nil {
		t.Error("rollback must clear local state")
	}
}

// A deploy timeout is not a failure: the deployment is still converging.
func TestRunInstallGCP_TimeoutDoesNotRollBack(t *testing.T) {
	isolate(t)
	writeTokens(t)
	stubGCPOK(t)
	stubGcpDiscover(t, completeGcpTarget(), nil)
	stubGcpDeploy(t, collector.ErrDeployTimeout)
	deleted := stubDeleteGcpDeployment(t, nil)
	srv := installServer(t, "agent-gcp")
	defer srv.Close()

	c := gcpCmd(t)
	mustSet(t, c, "api-url", srv.URL)
	mustSet(t, c, "yes", "true")

	var err error
	out := capture(t, func() { err = runInstallGCP(c) })
	if err != nil {
		t.Fatalf("a timeout must not fail the install, got %v", err)
	}
	if *deleted {
		t.Error("a timeout must not delete the deployment")
	}
	if st, _ := collector.LoadState(); st == nil {
		t.Error("state must survive a timeout so status can find the deployment")
	}
	if !strings.Contains(out, "NOT rolled back") || !strings.Contains(out, "dbg collector status") {
		t.Errorf("the operator should be told to watch it, got: %s", out)
	}
	// The deployment was kept, so the grant steps IAM auth needs still print.
	if !strings.Contains(out, "gcloud sql users create") {
		t.Errorf("grant guidance should print when the deployment is kept, got: %s", out)
	}
}

// Ctrl-C under the spinner and a lost operation are both unknown outcomes:
// nothing is rolled back, state stays for `status`, and the grant steps print.
func TestRunInstallGCP_UnknownOutcomeLeavesEverything(t *testing.T) {
	for name, deployErr := range map[string]error{
		"interrupted": fmt.Errorf("%w: program was interrupted", errInterrupted),
		"lost":        fmt.Errorf("polling failed: %w", collector.ErrDeployUnknown),
	} {
		t.Run(name, func(t *testing.T) {
			isolate(t)
			writeTokens(t)
			stubGCPOK(t)
			stubGcpDiscover(t, completeGcpTarget(), nil)
			stubGcpDeploy(t, deployErr)
			deleted := stubDeleteGcpDeployment(t, nil)
			srv := installServer(t, "agent-gcp")
			defer srv.Close()

			c := gcpCmd(t)
			mustSet(t, c, "api-url", srv.URL)
			mustSet(t, c, "yes", "true")

			var err error
			out := capture(t, func() { err = runInstallGCP(c) })
			if err == nil || !strings.Contains(err.Error(), "dbg collector status") {
				t.Fatalf("err = %v, want a pointer at status", err)
			}
			if *deleted {
				t.Error("an unknown outcome must not delete the deployment")
			}
			if st, _ := collector.LoadState(); st == nil {
				t.Error("state must survive so status/uninstall can find the deployment")
			}
			if !strings.Contains(out, "nothing was rolled back") || !strings.Contains(out, "gcloud sql users create") {
				t.Errorf("want the no-rollback notice and the grant steps, got: %s", out)
			}
		})
	}
}

// A deployment of that name with no local record: updating it in place would
// hand it a new identity and orphan the old one.
func TestRunInstallGCP_ExistingDeploymentWithoutStateIsRefused(t *testing.T) {
	isolate(t)
	writeTokens(t)
	stubGCPOK(t)
	stubGcpDeploymentStatus(t, "ACTIVE", nil)
	stubGcpDiscover(t, completeGcpTarget(), nil)
	deploys := stubGcpDeploy(t, nil)
	srv := installServer(t, "agent-gcp")
	defer srv.Close()

	c := gcpCmd(t)
	mustSet(t, c, "api-url", srv.URL)
	mustSet(t, c, "yes", "true")

	var err error
	capture(t, func() { err = runInstallGCP(c) })
	if err == nil || !strings.Contains(err.Error(), "already exists") || !strings.Contains(err.Error(), "--deployment-name") {
		t.Fatalf("err = %v, want the existing-deployment refusal", err)
	}
	if deploys.count != 0 {
		t.Error("nothing may be deployed over an unrecorded deployment")
	}
	if st, _ := collector.LoadState(); st != nil {
		t.Error("a refused install must not record state")
	}
}

func TestRunInstallGCP_PriorInstall(t *testing.T) {
	setup := func(t *testing.T) *cobra.Command {
		isolate(t)
		writeTokens(t)
		stubGCPOK(t)
		stubGcpDiscover(t, completeGcpTarget(), nil)
		stubGcpDeploy(t, nil)
		srv := installServer(t, "agent-new")
		t.Cleanup(srv.Close)
		c := gcpCmd(t)
		mustSet(t, c, "api-url", srv.URL)
		mustSet(t, c, "yes", "true")
		return c
	}

	t.Run("another target blocks", func(t *testing.T) {
		c := setup(t)
		if err := collector.SaveState(&collector.State{AgentID: "agent-aws", Target: "aws", StackName: "s"}); err != nil {
			t.Fatal(err)
		}
		var err error
		capture(t, func() { err = runInstallGCP(c) })
		if err == nil || !strings.Contains(err.Error(), "already installed") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("a live deployment is updated in place", func(t *testing.T) {
		c := setup(t)
		saveGcpState(t, "example.registry/collector@sha256:old")
		stubGcpDeploymentStatus(t, "ACTIVE", nil)
		stubReadGcpDeployment(t, deployedGcpSpec(t, storedGcpConfig(t, installedGcpTarget()), "v1.3"), nil)
		deploys := stubGcpDeploy(t, nil)
		var err error
		out := capture(t, func() { err = runInstallGCP(c) })
		if err != nil {
			t.Fatalf("runInstallGCP: %v\n%s", err, out)
		}
		if deploys.count != 1 || !deploys.deploy.RequireExisting {
			t.Fatalf("want one update of the existing deployment, got %+v", deploys)
		}
		d := deploys.deploy
		// The deployment's own values carry through: actuating account,
		// networking, image. Only the template moves — to this CLI's.
		if d.ServiceAccount != "projects/acme-prod/serviceAccounts/deployer@acme-prod.iam.gserviceaccount.com" {
			t.Errorf("actuating account = %q", d.ServiceAccount)
		}
		if d.Inputs["network"] != "projects/acme-prod/global/networks/prod-vpc" ||
			d.Inputs["subnetwork"] != "projects/acme-prod/regions/us-central1/subnetworks/prod-subnet" ||
			d.Inputs["collector_image"] != "example.registry/collector@sha256:old" {
			t.Errorf("networking and image must come from the deployment, got %v", d.Inputs)
		}
		if d.TemplateSource != collector.HostedGcpTemplateSource() || !strings.Contains(out, "Moving the deployment from template v1.3 to "+collector.GcpTemplateVersion) {
			t.Errorf("a v1.3 deployment moves to this CLI's template, got %s:\n%s", d.TemplateSource, out)
		}
		if _, stale := d.Inputs["database_roles"]; stale || d.Inputs["login_instances"] != "prod-pg,prod-pg-replica" {
			t.Errorf("inputs must be the current contract with the new replica in the login condition, got %v", d.Inputs)
		}
		// Identity, endpoints and commands are read back, never re-minted;
		// the databases and commands the install settled survive.
		cfg := decodedConfig(t, d)
		for _, want := range []string{`agent_id = "agent-old"`, `tenant_id = "tenant-old"`, `opamp_base_url = "https://opamp.example"`,
			`otlp_base_url = "https://otlp.example:4318"`, `databases = ["app"]`, `commands = ["explain"]`, `enabled = true`, `method = "gcp_iam"`} {
			if !strings.Contains(cfg, want) {
				t.Errorf("config missing %s:\n%s", want, cfg)
			}
		}
		if strings.Contains(cfg, "agent-new") {
			t.Error("an update must not mint a new identity")
		}
		if deploys.secretsWritten != 0 {
			t.Error("an update without a new password touches no secret")
		}
		st, _ := collector.LoadState()
		if st == nil || st.AgentID != "agent-old" || st.TargetName != "prod-pg" {
			t.Errorf("state = %+v", st)
		}
		if !strings.Contains(out, "Collector updated") || !strings.Contains(out, "rolled to the new configuration") {
			t.Errorf("the update and the rollout should be reported, got:\n%s", out)
		}
		if strings.Contains(out, "gcloud sql users create") {
			t.Errorf("the same target under the same auth needs no new grant, got:\n%s", out)
		}
	})

	t.Run("a vanished deployment installs fresh", func(t *testing.T) {
		c := setup(t)
		if err := collector.SaveState(&collector.State{AgentID: "agent-old", Target: "gcp", Project: "acme-prod", Region: "us-central1", DeploymentName: "dbg-test"}); err != nil {
			t.Fatal(err)
		}
		stubGcpDeploymentStatus(t, "", nil)
		var err error
		out := capture(t, func() { err = runInstallGCP(c) })
		if err != nil {
			t.Fatalf("runInstallGCP: %v\n%s", err, out)
		}
		if !strings.Contains(out, "no longer exists") || !strings.Contains(out, "agent-old") {
			t.Errorf("the stale record should be explained, got: %s", out)
		}
		if st, _ := collector.LoadState(); st == nil || st.AgentID != "agent-new" {
			t.Errorf("state should record the fresh install, got %+v", st)
		}
	})
}

// Flag mistakes are caught before a single cloud call is made.
func TestRunInstallGCP_FlagMistakesFailFirst(t *testing.T) {
	cases := map[string]struct {
		set  func(*cobra.Command)
		want string
	}{
		"missing deploy service account": {
			func(c *cobra.Command) { mustSet(t, c, "deploy-service-account", "") },
			"--deploy-service-account",
		},
		"deploy service account not in resource form": {
			func(c *cobra.Command) {
				mustSet(t, c, "deploy-service-account", "deployer@acme-prod.iam.gserviceaccount.com")
			},
			"projects/<project>/serviceAccounts/<email>",
		},
		"deployment name outside the service-account grammar": {
			func(c *cobra.Command) { mustSet(t, c, "deployment-name", "Bad_Name") },
			"--deployment-name",
		},
		"provider type from the other cloud": {
			func(c *cobra.Command) { mustSet(t, c, "provider-type", "aws_rds") },
			"cloud_sql or alloydb",
		},
		"an aws-only flag": {
			func(c *cobra.Command) {
				c.Flags().String("subnets", "", "")
				mustSet(t, c, "subnets", "subnet-a")
			},
			"--subnets applies to --target aws only",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			isolate(t)
			writeTokens(t)
			avail := stubGcpAvailable(t, nil)
			c := gcpCmd(t)
			mustSet(t, c, "api-url", "https://x")
			tc.set(c)
			err := runInstallGCP(c)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if *avail != 0 {
				t.Error("the flag check must run before any Google Cloud call")
			}
		})
	}
}

// A project number is accepted by every API but cannot name the service
// account the template creates.
func TestRunInstallGCP_ProjectNumberIsRefused(t *testing.T) {
	isolate(t)
	writeTokens(t)
	stubGCPOK(t)
	stubGcpDiscover(t, completeGcpTarget(), nil)
	deploys := stubGcpDeploy(t, nil)
	srv := installServer(t, "agent-gcp")
	defer srv.Close()

	c := gcpCmd(t)
	mustSet(t, c, "api-url", srv.URL)
	mustSet(t, c, "yes", "true")
	mustSet(t, c, "project", "123456789012")

	var err error
	capture(t, func() { err = runInstallGCP(c) })
	if err == nil || !strings.Contains(err.Error(), "project number") {
		t.Fatalf("err = %v", err)
	}
	if deploys.count != 0 {
		t.Error("nothing may be deployed under a project number")
	}
}

func TestRunInstallGCP_Auth(t *testing.T) {
	setup := func(t *testing.T, target collector.GcpTarget) (*cobra.Command, *gcpDeployCall) {
		isolate(t)
		writeTokens(t)
		stubGCPOK(t)
		stubGcpDiscover(t, target, nil)
		deploys := stubGcpDeploy(t, nil)
		srv := installServer(t, "agent-gcp")
		t.Cleanup(srv.Close)
		c := gcpCmd(t)
		mustSet(t, c, "api-url", srv.URL)
		mustSet(t, c, "yes", "true")
		return c, deploys
	}

	t.Run("IAM off without a password is refused with the flag to flip", func(t *testing.T) {
		target := completeGcpTarget()
		target.IamEnabled = false
		c, _ := setup(t, target)
		var err error
		capture(t, func() { err = runInstallGCP(c) })
		if err == nil || !strings.Contains(err.Error(), "cloudsql.iam_authentication") || !strings.Contains(err.Error(), "--db-password") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("a password selects password auth with the collector's default user", func(t *testing.T) {
		target := completeGcpTarget()
		target.IamEnabled = false
		c, deploys := setup(t, target)
		mustSet(t, c, "db-password", "s3cret")
		var err error
		out := capture(t, func() { err = runInstallGCP(c) })
		if err != nil {
			t.Fatalf("runInstallGCP: %v\n%s", err, out)
		}
		cfg := decodedConfig(t, deploys.deploy)
		for _, want := range []string{`method = "password"`, `user = "` + collector.DefaultDBUser + `"`, `password = "${` + collector.CloudDBPasswordEnv + `}"`} {
			if !strings.Contains(cfg, want) {
				t.Errorf("config missing %s:\n%s", want, cfg)
			}
		}
		if deploys.secrets.DBPassword != "s3cret" || strings.Contains(cfg, "s3cret") {
			t.Error("the password goes to Secret Manager, never the config")
		}
		if deploys.deploy.Inputs["db_password"] != "" {
			t.Error("no credential may enter the deployment's input values")
		}
		if strings.Contains(out, "Grant the collector") {
			t.Error("password auth needs no IAM grant guidance")
		}
	})

	t.Run("--db-user names the password-auth user, on MySQL too", func(t *testing.T) {
		target := completeGcpTarget()
		target.Engine, target.Port, target.IamEnabled = "mysql", 3306, false
		c, deploys := setup(t, target)
		mustSet(t, c, "db-password", "s3cret")
		mustSet(t, c, "db-user", "dbg_ro")
		var err error
		capture(t, func() { err = runInstallGCP(c) })
		if err != nil {
			t.Fatalf("runInstallGCP: %v", err)
		}
		cfg := decodedConfig(t, deploys.deploy)
		if !strings.Contains(cfg, `user = "dbg_ro"`) || strings.Contains(cfg, `"postgres"`) {
			t.Errorf("MySQL password auth must use the given user, never a postgres default:\n%s", cfg)
		}
	})

	t.Run("IAM on the internal per-instance CA is refused with the ways out", func(t *testing.T) {
		// The collector refuses this by name at discovery; the install must
		// refuse first, where the operator can act.
		target := completeGcpTarget()
		target.ServerCaMode = "GOOGLE_MANAGED_INTERNAL_CA"
		c, _ := setup(t, target)
		var err error
		capture(t, func() { err = runInstallGCP(c) })
		if err == nil || !strings.Contains(err.Error(), "GOOGLE_MANAGED_CAS_CA") ||
			!strings.Contains(err.Error(), "--db-password") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("MySQL without the flag is told the MySQL spelling of the flag", func(t *testing.T) {
		// Dots are illegal in MySQL flag names; the Postgres spelling would
		// send the operator to a flag that cannot exist.
		target := completeGcpTarget()
		target.Engine, target.Port, target.IamEnabled = "mysql", 3306, false
		c, _ := setup(t, target)
		var err error
		capture(t, func() { err = runInstallGCP(c) })
		if err == nil || !strings.Contains(err.Error(), "cloudsql_iam_authentication") ||
			strings.Contains(err.Error(), "cloudsql.iam_authentication") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("MySQL under IAM derives the short username", func(t *testing.T) {
		// mysql+cloud_sql+gcp_iam is a supported triple since the collector
		// registered it (live-tested 2026-09-04): the install proceeds and the
		// IAM user is the local part of the service account.
		target := completeGcpTarget()
		target.Engine, target.Port = "mysql", 3306
		c, deploys := setup(t, target)
		var err error
		capture(t, func() { err = runInstallGCP(c) })
		if err != nil {
			t.Fatalf("runInstallGCP: %v", err)
		}
		if cfg := decodedConfig(t, deploys.deploy); !strings.Contains(cfg, `user = "dbg-test"`) {
			t.Errorf("MySQL IAM user is the local part of the service account:\n%s", cfg)
		}
	})
}

// The PGA preflight warns — and only warns — when the subnetwork cannot reach
// Google APIs privately: a Cloud NAT may still provide the egress, so the
// deploy proceeds, but the operator gets the enable command by name instead
// of an opaque boot timeout.
func TestRunInstallGCP_WarnsWhenPrivateGoogleAccessIsOff(t *testing.T) {
	isolate(t)
	writeTokens(t)
	stubGCPOK(t)
	stubGcpSubnetworkPGA(t, false, nil)
	stubGcpDiscover(t, completeGcpTarget(), nil)
	deploys := stubGcpDeploy(t, nil)
	srv := installServer(t, "agent-gcp")
	defer srv.Close()

	c := gcpCmd(t)
	mustSet(t, c, "api-url", srv.URL)
	mustSet(t, c, "yes", "true")

	var err error
	out := capture(t, func() { err = runInstallGCP(c) })
	if err != nil {
		t.Fatalf("runInstallGCP: %v\n%s", err, out)
	}
	if deploys.count != 1 {
		t.Fatal("the PGA warning must not block the deploy")
	}
	if !strings.Contains(out, "Private Google Access OFF") ||
		!strings.Contains(out, "--enable-private-ip-google-access") {
		t.Errorf("expected the PGA warning with the enable command, got:\n%s", out)
	}
}

// The query-analysis flags apply to gcp exactly as to aws.
func TestRunInstallGCP_CommandsFlags(t *testing.T) {
	run := func(t *testing.T, set func(*cobra.Command)) string {
		isolate(t)
		writeTokens(t)
		stubGCPOK(t)
		stubGcpDiscover(t, completeGcpTarget(), nil)
		deploys := stubGcpDeploy(t, nil)
		srv := installServer(t, "agent-gcp")
		t.Cleanup(srv.Close)
		c := gcpCmd(t)
		mustSet(t, c, "api-url", srv.URL)
		mustSet(t, c, "yes", "true")
		set(c)
		var err error
		capture(t, func() { err = runInstallGCP(c) })
		if err != nil {
			t.Fatalf("runInstallGCP: %v", err)
		}
		return decodedConfig(t, deploys.deploy)
	}

	t.Run("default allows every command the engine supports", func(t *testing.T) {
		cfg := run(t, func(*cobra.Command) {})
		if !strings.Contains(cfg, `enabled = true`) || !strings.Contains(cfg, `commands = ["execute_query", "explain"]`) {
			t.Errorf("config:\n%s", cfg)
		}
	})
	t.Run("--commands narrows the set", func(t *testing.T) {
		cfg := run(t, func(c *cobra.Command) { mustSet(t, c, "commands", "explain") })
		if !strings.Contains(cfg, `commands = ["explain"]`) {
			t.Errorf("config:\n%s", cfg)
		}
	})
	t.Run(`--commands="" turns analysis off`, func(t *testing.T) {
		cfg := run(t, func(c *cobra.Command) { mustSet(t, c, "commands", "") })
		if !strings.Contains(cfg, `enabled = false`) || strings.Contains(cfg, "execute_query") {
			t.Errorf("config:\n%s", cfg)
		}
	})
	t.Run("--enable-commands=false turns analysis off", func(t *testing.T) {
		cfg := run(t, func(c *cobra.Command) { mustSet(t, c, "enable-commands", "false") })
		if !strings.Contains(cfg, `enabled = false`) {
			t.Errorf("config:\n%s", cfg)
		}
	})
}

func TestRunInstallGCP_NetworkComesFromTheDatabaseOrTheFlag(t *testing.T) {
	setup := func(t *testing.T, target collector.GcpTarget) (*cobra.Command, *gcpDeployCall) {
		isolate(t)
		writeTokens(t)
		stubGCPOK(t)
		stubGcpDiscover(t, target, nil)
		deploys := stubGcpDeploy(t, nil)
		srv := installServer(t, "agent-gcp")
		t.Cleanup(srv.Close)
		c := gcpCmd(t)
		mustSet(t, c, "api-url", srv.URL)
		mustSet(t, c, "yes", "true")
		return c, deploys
	}
	t.Run("no private network and no flag is an error naming --network", func(t *testing.T) {
		target := completeGcpTarget()
		target.Network = ""
		c, _ := setup(t, target)
		var err error
		capture(t, func() { err = runInstallGCP(c) })
		if err == nil || !strings.Contains(err.Error(), "--network") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("--network overrides the discovered one", func(t *testing.T) {
		c, deploys := setup(t, completeGcpTarget())
		mustSet(t, c, "network", "projects/acme-prod/global/networks/shared")
		var err error
		capture(t, func() { err = runInstallGCP(c) })
		if err != nil {
			t.Fatalf("runInstallGCP: %v", err)
		}
		if got := deploys.deploy.Inputs["network"]; got != "projects/acme-prod/global/networks/shared" {
			t.Errorf("network = %q", got)
		}
	})
}

func TestRunInstallGCP_Subnetwork(t *testing.T) {
	setup := func(t *testing.T) (*cobra.Command, *gcpDeployCall) {
		isolate(t)
		writeTokens(t)
		stubGCPOK(t)
		stubGcpDiscover(t, completeGcpTarget(), nil)
		deploys := stubGcpDeploy(t, nil)
		srv := installServer(t, "agent-gcp")
		t.Cleanup(srv.Close)
		c := gcpCmd(t)
		mustSet(t, c, "api-url", srv.URL)
		mustSet(t, c, "yes", "true")
		return c, deploys
	}
	t.Run("--subnetwork rides into the template", func(t *testing.T) {
		c, deploys := setup(t)
		mustSet(t, c, "subnetwork", "projects/acme-prod/regions/us-central1/subnetworks/db")
		var err error
		capture(t, func() { err = runInstallGCP(c) })
		if err != nil {
			t.Fatalf("runInstallGCP: %v", err)
		}
		if got := deploys.deploy.Inputs["subnetwork"]; got != "projects/acme-prod/regions/us-central1/subnetworks/db" {
			t.Errorf("subnetwork = %q", got)
		}
	})
	t.Run("otherwise the VPC's subnetwork in the region is resolved", func(t *testing.T) {
		c, deploys := setup(t)
		var gotNetwork, gotRegion string
		orig := resolveGcpSubnetwork
		resolveGcpSubnetwork = func(network, region string) (string, error) {
			gotNetwork, gotRegion = network, region
			return "projects/acme-prod/regions/us-central1/subnetworks/auto", nil
		}
		t.Cleanup(func() { resolveGcpSubnetwork = orig })
		var err error
		capture(t, func() { err = runInstallGCP(c) })
		if err != nil {
			t.Fatalf("runInstallGCP: %v", err)
		}
		if gotNetwork != completeGcpTarget().Network || gotRegion != "us-central1" {
			t.Errorf("resolved for %s/%s", gotNetwork, gotRegion)
		}
		if got := deploys.deploy.Inputs["subnetwork"]; got != "projects/acme-prod/regions/us-central1/subnetworks/auto" {
			t.Errorf("subnetwork = %q", got)
		}
	})
	t.Run("an unresolvable subnetwork stops before anything is minted", func(t *testing.T) {
		c, deploys := setup(t)
		stubResolveGcpSubnetwork(t, "", errors.New("VPC has several subnetworks; pass --subnetwork"))
		var err error
		capture(t, func() { err = runInstallGCP(c) })
		if err == nil || !strings.Contains(err.Error(), "--subnetwork") {
			t.Fatalf("err = %v", err)
		}
		if deploys.count != 0 {
			t.Error("nothing may be deployed")
		}
		if st, _ := collector.LoadState(); st != nil {
			t.Error("no state may be left behind")
		}
	})
}

// With no --db-instance-id and a real terminal, an ambiguous project becomes
// a picker rather than an error.
func TestResolveGcpTarget_AmbiguityBecomesAPicker(t *testing.T) {
	isolate(t)
	setStdin(t, "2\n")
	orig := stdinIsTerminal
	stdinIsTerminal = func() bool { return true }
	t.Cleanup(func() { stdinIsTerminal = orig })

	amb := &collector.AmbiguousTargetError{Choices: []collector.TargetChoice{
		{ID: "prod-pg", ProviderType: "cloud_sql"},
		{ID: "orders/orders-primary", ProviderType: "alloydb"},
	}}
	var picked collector.TargetChoice
	origDiscover := discoverGcpTarget
	discoverGcpTarget = func(id, provider string, into collector.GcpTarget) (collector.GcpTarget, error) {
		if id == "" {
			return into, amb
		}
		picked = collector.TargetChoice{ID: id, ProviderType: provider}
		out := completeGcpTarget()
		out.ProviderType = provider
		return out, nil
	}
	t.Cleanup(func() { discoverGcpTarget = origDiscover })

	var got collector.GcpTarget
	var err error
	out := capture(t, func() { got, err = resolveGcpTarget(gcpCmd(t), "acme-prod") })
	if err != nil {
		t.Fatalf("resolveGcpTarget: %v", err)
	}
	if picked.ID != "orders/orders-primary" || picked.ProviderType != "alloydb" || got.ProviderType != "alloydb" {
		t.Errorf("the second candidate should be discovered with its provider type, got %+v", picked)
	}
	if !strings.Contains(out, "AlloyDB") || !strings.Contains(out, "Cloud SQL") {
		t.Errorf("candidates should be labelled by kind, got: %s", out)
	}
}

func TestResolveGcpTarget_AmbiguousNonInteractiveErrors(t *testing.T) {
	isolate(t)
	amb := &collector.AmbiguousTargetError{Choices: []collector.TargetChoice{
		{ID: "a", ProviderType: "cloud_sql"}, {ID: "b", ProviderType: "cloud_sql"},
	}}
	stubGcpDiscover(t, collector.GcpTarget{}, amb)
	c := gcpCmd(t)
	mustSet(t, c, "yes", "true")
	_, err := resolveGcpTarget(c, "acme-prod")
	if err == nil || !strings.Contains(err.Error(), "--db-instance-id") {
		t.Fatalf("ambiguity must not be resolved by guessing, got %v", err)
	}
}

// --- day 2 -----------------------------------------------------------------

func TestGcpStatus(t *testing.T) {
	isolate(t)
	st := &collector.State{
		AgentID: "agent-gcp", TenantID: "ten", Target: "gcp", TargetName: "prod-pg",
		Image: "img:v1", Project: "acme-prod", Region: "us-central1", DeploymentName: "dbg-test",
	}
	t.Run("reports the deployment state", func(t *testing.T) {
		stubGcpDeploymentStatus(t, "ACTIVE", nil)
		out := capture(t, func() {
			if err := gcpStatus(gcpCmd(t), st); err != nil {
				t.Fatalf("gcpStatus: %v", err)
			}
		})
		for _, want := range []string{"agent-gcp", "Deployment: dbg-test", "ACTIVE", "gcp — prod-pg"} {
			if !strings.Contains(out, want) {
				t.Errorf("output should contain %q, got: %s", want, out)
			}
		}
	})
	t.Run("a missing deployment says so", func(t *testing.T) {
		stubGcpDeploymentStatus(t, "", nil)
		out := capture(t, func() { _ = gcpStatus(gcpCmd(t), st) })
		if !strings.Contains(out, "deployment not found") {
			t.Errorf("out = %s", out)
		}
	})
	t.Run("an unreadable status is not fatal", func(t *testing.T) {
		stubGcpDeploymentStatus(t, "", errors.New("PERMISSION_DENIED"))
		out := capture(t, func() {
			if err := gcpStatus(gcpCmd(t), st); err != nil {
				t.Fatalf("status must not hard-fail, got %v", err)
			}
		})
		if !strings.Contains(out, "status unknown") {
			t.Errorf("out = %s", out)
		}
	})
}

func TestCollectorLifecycle_GCPRoutesToTheInstanceGroup(t *testing.T) {
	saveGCP := func(t *testing.T) {
		isolate(t)
		if err := collector.SaveState(&collector.State{AgentID: "a", Target: "gcp", Project: "acme-prod", Region: "us-central1", DeploymentName: "dbg-test"}); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("start and stop resize", func(t *testing.T) {
		saveGCP(t)
		var sizes []int
		orig := scaleGcpMig
		scaleGcpMig = func(project, region, name string, size int) error {
			if project != "acme-prod" || region != "us-central1" || name != "dbg-test" {
				t.Errorf("addressed %s/%s/%s", project, region, name)
			}
			sizes = append(sizes, size)
			return nil
		}
		t.Cleanup(func() { scaleGcpMig = orig })
		capture(t, func() {
			if err := stopCmd.RunE(stopCmd, nil); err != nil {
				t.Fatalf("stop: %v", err)
			}
			if err := startCmd.RunE(startCmd, nil); err != nil {
				t.Fatalf("start: %v", err)
			}
		})
		if len(sizes) != 2 || sizes[0] != 0 || sizes[1] != 1 {
			t.Errorf("sizes = %v, want [0 1]", sizes)
		}
	})
	t.Run("restart recreates", func(t *testing.T) {
		saveGCP(t)
		called := false
		orig := restartGcpMig
		restartGcpMig = func(string, string, string) error { called = true; return nil }
		t.Cleanup(func() { restartGcpMig = orig })
		capture(t, func() {
			if err := restartCmd.RunE(restartCmd, nil); err != nil {
				t.Fatalf("restart: %v", err)
			}
		})
		if !called {
			t.Error("restart must recreate the instance group's instances")
		}
	})
	t.Run("logs tail Cloud Logging", func(t *testing.T) {
		saveGCP(t)
		var gotProject, gotName string
		orig := tailGcpLogs
		tailGcpLogs = func(project, _, name string, follow bool) error { gotProject, gotName = project, name; return nil }
		t.Cleanup(func() { tailGcpLogs = orig })
		if err := logsCmd.RunE(logsCmd, nil); err != nil {
			t.Fatalf("logs: %v", err)
		}
		if gotProject != "acme-prod" || gotName != "dbg-test" {
			t.Errorf("logs addressed %s/%s", gotProject, gotName)
		}
	})
}

// --- update -------------------------------------------------------------------

func setupGcpUpdate(t *testing.T, spec *collector.GcpDeploymentSpec, discovered collector.GcpTarget) (*cobra.Command, *gcpDeployCall) {
	t.Helper()
	isolate(t)
	writeTokens(t)
	stubGCPOK(t)
	saveGcpState(t, "example.registry/collector@sha256:old")
	stubGcpDeploymentStatus(t, "ACTIVE", nil)
	stubReadGcpDeployment(t, spec, nil)
	stubGcpDiscover(t, discovered, nil)
	deploys := stubGcpDeploy(t, nil)
	srv := installServer(t, "agent-new")
	t.Cleanup(srv.Close)
	c := gcpCmd(t)
	mustSet(t, c, "api-url", srv.URL)
	mustSet(t, c, "yes", "true")
	return c, deploys
}

func TestRunUpdateGCP_Refusals(t *testing.T) {
	iamSpec := func(t *testing.T) *collector.GcpDeploymentSpec {
		return deployedGcpSpec(t, storedGcpConfig(t, installedGcpTarget()), "v1.3")
	}
	cases := []struct {
		name  string
		spec  func(t *testing.T) *collector.GcpDeploymentSpec
		flags map[string]string
		want  string
	}{
		{"networking cannot change in place", iamSpec, map[string]string{"network": "projects/acme-prod/global/networks/other"}, "cannot change an installed collector in place"},
		{"the deploy account cannot change in place", iamSpec, map[string]string{"deploy-service-account": "projects/acme-prod/serviceAccounts/x@acme-prod.iam.gserviceaccount.com"}, "cannot change an installed collector in place"},
		{"the subnetwork cannot change in place", iamSpec, map[string]string{"subnetwork": "projects/acme-prod/regions/us-central1/subnetworks/other"}, "cannot change an installed collector in place"},
		{"another project is another collector", iamSpec, map[string]string{"project": "other-proj"}, "cannot move it in place"},
		{"another name is another collector", iamSpec, map[string]string{"deployment-name": "dbg-other"}, "cannot rename it in place"},
		{"a newer template refuses", func(t *testing.T) *collector.GcpDeploymentSpec {
			return deployedGcpSpec(t, storedGcpConfig(t, installedGcpTarget()), "v9.0")
		}, nil, "update dbg first"},
		{"an instaclustr source is not this path's", func(t *testing.T) *collector.GcpDeploymentSpec {
			cfg, err := collector.Config{
				Dbgorilla: collector.Dbgorilla{AgentID: "agent-old", TenantID: "tenant-old", Secret: "${DBG_SERVER_SECRET}"},
				Component: []collector.Component{{Name: "orders", Engine: "postgres",
					Provider: collector.Provider{Type: "instaclustr", ClusterID: "c-1"},
					Auth:     collector.Auth{Method: "password", User: "monitor", Password: "${DBG_DB_PASSWORD}"},
					Connect:  collector.Connect{Host: "h", Port: 5432, SSLMode: "require"}}},
				Topology: collector.Topology{Interval: "60s"},
			}.Render()
			if err != nil {
				t.Fatal(err)
			}
			return deployedGcpSpec(t, cfg, "v1.3")
		}, nil, "--provider instaclustr"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, deploys := setupGcpUpdate(t, tc.spec(t), completeGcpTarget())
			for k, v := range tc.flags {
				mustSet(t, c, k, v)
			}
			var err error
			capture(t, func() { err = runInstallGCP(c) })
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if deploys.count != 0 {
				t.Error("a refused update deploys nothing")
			}
			if st, _ := collector.LoadState(); st == nil || st.AgentID != "agent-old" {
				t.Errorf("a refused update keeps the record, got %+v", st)
			}
		})
	}
	t.Run("a vanished deployment is not recreated by an update", func(t *testing.T) {
		c, deploys := setupGcpUpdate(t, nil, completeGcpTarget())
		var err error
		capture(t, func() { err = runInstallGCP(c) })
		if err == nil || !strings.Contains(err.Error(), "no longer exists") || deploys.count != 0 {
			t.Fatalf("err = %v, deploys = %d", err, deploys.count)
		}
	})
}

// A password-auth collector keeps its stored password unless told otherwise;
// a new password rotates only that secret; --db-password "" moves to IAM.
func TestRunUpdateGCP_Password(t *testing.T) {
	stored := installedGcpTarget()
	stored.AuthMethod, stored.User = "password", "monitor"
	stored.ServerCaMode = "GOOGLE_MANAGED_INTERNAL_CA"
	noIAM := completeGcpTarget()
	noIAM.IamEnabled = false // IAM would be refused: proves it was not consulted

	t.Run("keeps the stored password", func(t *testing.T) {
		c, deploys := setupGcpUpdate(t, deployedGcpSpec(t, storedGcpConfig(t, stored), "v1.4"), noIAM)
		passwords := stubEnsureGcpDBPassword(t, nil)
		var err error
		out := capture(t, func() { err = runInstallGCP(c) })
		if err != nil {
			t.Fatalf("runInstallGCP: %v\n%s", err, out)
		}
		cfg := decodedConfig(t, deploys.deploy)
		if !strings.Contains(cfg, `method = "password"`) || !strings.Contains(cfg, `user = "monitor"`) {
			t.Errorf("stored password auth must survive the update:\n%s", cfg)
		}
		if len(*passwords) != 0 {
			t.Error("no new password, no secret write")
		}
		if deploys.deploy.TemplateSource != "gs://dbgorilla-collector-templates/collector/gce/v1.4" || strings.Contains(out, "Moving the deployment") {
			t.Errorf("a current deployment keeps its template, got %s", deploys.deploy.TemplateSource)
		}
	})
	t.Run("a new password rotates the secret", func(t *testing.T) {
		c, deploys := setupGcpUpdate(t, deployedGcpSpec(t, storedGcpConfig(t, stored), "v1.4"), noIAM)
		passwords := stubEnsureGcpDBPassword(t, nil)
		mustSet(t, c, "db-password", "new-pw")
		var err error
		out := capture(t, func() { err = runInstallGCP(c) })
		if err != nil {
			t.Fatalf("runInstallGCP: %v\n%s", err, out)
		}
		if len(*passwords) != 1 || (*passwords)[0] != "new-pw" {
			t.Errorf("the new password should be written once, got %v", *passwords)
		}
		if cfg := decodedConfig(t, deploys.deploy); !strings.Contains(cfg, `method = "password"`) || strings.Contains(cfg, "new-pw") {
			t.Errorf("password auth stays, the value stays out of the config:\n%s", cfg)
		}
		if deploys.secretsWritten != 0 {
			t.Error("the server secret must not be rewritten")
		}
	})
	t.Run("an empty --db-password moves to IAM", func(t *testing.T) {
		c, deploys := setupGcpUpdate(t, deployedGcpSpec(t, storedGcpConfig(t, stored), "v1.4"), completeGcpTarget())
		mustSet(t, c, "db-password", "")
		var err error
		out := capture(t, func() { err = runInstallGCP(c) })
		if err != nil {
			t.Fatalf("runInstallGCP: %v\n%s", err, out)
		}
		if cfg := decodedConfig(t, deploys.deploy); !strings.Contains(cfg, `method = "gcp_iam"`) {
			t.Errorf("IAM auth should be settled:\n%s", cfg)
		}
		if !strings.Contains(out, "gcloud sql users create") {
			t.Errorf("a changed auth method needs the grant guidance, got:\n%s", out)
		}
	})
}

// A template under development is applied from where it is, as on install.
func TestRunUpdateGCP_TemplateSourceOverrides(t *testing.T) {
	c, deploys := setupGcpUpdate(t, deployedGcpSpec(t, storedGcpConfig(t, installedGcpTarget()), "v1.3"), completeGcpTarget())
	mustSet(t, c, "template-source", "gs://dev-bucket/collector/gce/next")
	var err error
	out := capture(t, func() { err = runInstallGCP(c) })
	if err != nil {
		t.Fatalf("runInstallGCP: %v\n%s", err, out)
	}
	if deploys.deploy.TemplateSource != "gs://dev-bucket/collector/gce/next" {
		t.Errorf("template source = %q", deploys.deploy.TemplateSource)
	}
}

// A deployment that opted out of the login condition keeps that choice on an
// update unless the flag says otherwise; one from before the condition
// existed gets it.
func TestRunUpdateGCP_LoginScopeCarriesOver(t *testing.T) {
	optedOut := func(t *testing.T) *collector.GcpDeploymentSpec {
		spec := deployedGcpSpec(t, storedGcpConfig(t, installedGcpTarget()), "v1.4")
		delete(spec.Inputs, "database_roles")
		spec.Inputs["cloud_sql_roles"], spec.Inputs["alloydb_roles"], spec.Inputs["login_instances"] = "true", "false", ""
		return spec
	}
	t.Run("an opt-out stays opted out", func(t *testing.T) {
		c, deploys := setupGcpUpdate(t, optedOut(t), completeGcpTarget())
		var err error
		out := capture(t, func() { err = runInstallGCP(c) })
		if err != nil {
			t.Fatalf("runInstallGCP: %v\n%s", err, out)
		}
		if deploys.deploy.Inputs["login_instances"] != "" || !strings.Contains(out, "--allow-project-wide-login") {
			t.Errorf("login_instances = %q; the stored opt-out must carry over and be warned about:\n%s",
				deploys.deploy.Inputs["login_instances"], out)
		}
	})
	t.Run("the flag re-scopes it", func(t *testing.T) {
		c, deploys := setupGcpUpdate(t, optedOut(t), completeGcpTarget())
		mustSet(t, c, "allow-project-wide-login", "false")
		var err error
		out := capture(t, func() { err = runInstallGCP(c) })
		if err != nil {
			t.Fatalf("runInstallGCP: %v\n%s", err, out)
		}
		if deploys.deploy.Inputs["login_instances"] != "prod-pg,prod-pg-replica" {
			t.Errorf("login_instances = %q, want the condition back", deploys.deploy.Inputs["login_instances"])
		}
	})
}

func TestRunUpdateGCP_SwitchesTheTarget(t *testing.T) {
	c, deploys := setupGcpUpdate(t, deployedGcpSpec(t, storedGcpConfig(t, installedGcpTarget()), "v1.4"), completeGcpTarget())
	mustSet(t, c, "db-instance-id", "other-pg")
	var err error
	out := capture(t, func() { err = runInstallGCP(c) })
	if err != nil {
		t.Fatalf("runInstallGCP: %v\n%s", err, out)
	}
	cfg := decodedConfig(t, deploys.deploy)
	if !strings.Contains(cfg, `instance = "other-pg"`) || strings.Contains(cfg, `instance = "prod-pg"`) {
		t.Errorf("the config should name the new target:\n%s", cfg)
	}
	if !strings.HasPrefix(deploys.deploy.Inputs["login_instances"], "other-pg") {
		t.Errorf("the login condition follows the target, got %q", deploys.deploy.Inputs["login_instances"])
	}
	if st, _ := collector.LoadState(); st == nil || st.TargetName != "other-pg" || st.AgentID != "agent-old" {
		t.Errorf("state = %+v", st)
	}
	if !strings.Contains(out, "gcloud sql users create") {
		t.Errorf("a new target needs the grant guidance, got:\n%s", out)
	}
}

func TestRunUpdateGCP_FailuresRollNothingBack(t *testing.T) {
	cases := []struct {
		name    string
		deploy  error
		wantErr string
		wantOut string
	}{
		{"busy waits", collector.ErrDeployBusy, "Wait for it to finish", ""},
		{"failure names what may be running", errors.New("apply failed"), "Nothing was rolled back", ""},
		{"unknown outcome points at status", collector.ErrDeployUnknown, "dbg collector status", ""},
		{"timeout is not an error", collector.ErrDeployTimeout, "", "Still applying"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, deploys := setupGcpUpdate(t, deployedGcpSpec(t, storedGcpConfig(t, installedGcpTarget()), "v1.4"), completeGcpTarget())
			stubGcpDeploy(t, tc.deploy)
			deleted := stubDeleteGcpDeployment(t, nil)
			var err error
			out := capture(t, func() { err = runInstallGCP(c) })
			switch {
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			case tc.wantErr == "" && err != nil:
				t.Fatalf("err = %v, want none\n%s", err, out)
			}
			if tc.wantOut != "" && !strings.Contains(out, tc.wantOut) {
				t.Errorf("want %q in:\n%s", tc.wantOut, out)
			}
			if *deleted || deploys.secretsDeleted != 0 {
				t.Error("an update never tears the deployment or its secrets down")
			}
			if st, _ := collector.LoadState(); st == nil || st.AgentID != "agent-old" {
				t.Errorf("the record must survive, got %+v", st)
			}
		})
	}
}

// --- upgrade ------------------------------------------------------------------

func TestRunUpgradeGCP(t *testing.T) {
	const repo = "dbgorillapublic.azurecr.io/dbg-collector"
	setup := func(t *testing.T, running string) (*cobra.Command, *[]string, *int) {
		t.Helper()
		isolate(t)
		stubGCPOK(t)
		rolled := stubWaitGcpMigStable(t, nil)
		saveGcpState(t, running)
		return gcpCmd(t), stubUpgradeGcpImage(t, nil), rolled
	}
	t.Run("rolls the deployment to the pinned image", func(t *testing.T) {
		c, images, rolled := setup(t, repo+":0.9.0@sha256:old")
		mustSet(t, c, "image", repo+":0.10.1")
		var err error
		out := capture(t, func() { err = runCollectorUpgrade(c, nil) })
		if err != nil {
			t.Fatalf("upgrade: %v\n%s", err, out)
		}
		if len(*images) != 1 || (*images)[0] != repo+":0.10.1@sha256:testdigest" {
			t.Errorf("upgrade should carry the digest-pinned image, got %v", *images)
		}
		if *rolled != 1 || !strings.Contains(out, "Upgrade applied") {
			t.Errorf("the rollout should be awaited and reported, got rolled=%d:\n%s", *rolled, out)
		}
		if st, _ := collector.LoadState(); st == nil || st.Image != repo+":0.10.1@sha256:testdigest" {
			t.Errorf("state should record the new image, got %+v", st)
		}
	})
	t.Run("refuses a downgrade unless allowed", func(t *testing.T) {
		c, images, _ := setup(t, repo+":0.10.1@sha256:old")
		mustSet(t, c, "image", repo+":0.9.0")
		var err error
		capture(t, func() { err = runCollectorUpgrade(c, nil) })
		if err == nil || !strings.Contains(err.Error(), "refusing to downgrade") || len(*images) != 0 {
			t.Fatalf("err = %v, upgrades = %v", err, *images)
		}
		mustSet(t, c, "allow-downgrade", "true")
		capture(t, func() { err = runCollectorUpgrade(c, nil) })
		if err != nil || len(*images) != 1 {
			t.Fatalf("with --allow-downgrade: err = %v, upgrades = %v", err, *images)
		}
	})
	t.Run("already on the image does nothing", func(t *testing.T) {
		c, images, _ := setup(t, repo+":0.10.1@sha256:testdigest")
		mustSet(t, c, "image", repo+":0.10.1")
		var err error
		out := capture(t, func() { err = runCollectorUpgrade(c, nil) })
		if err != nil || len(*images) != 0 || !strings.Contains(out, "nothing to upgrade") {
			t.Fatalf("err = %v, upgrades = %v:\n%s", err, *images, out)
		}
	})
	t.Run("a busy deployment is reported, not rolled back", func(t *testing.T) {
		c, _, _ := setup(t, repo+":0.9.0@sha256:old")
		stubUpgradeGcpImage(t, collector.ErrDeployBusy)
		mustSet(t, c, "image", repo+":0.10.1")
		var err error
		capture(t, func() { err = runCollectorUpgrade(c, nil) })
		if err == nil || !strings.Contains(err.Error(), "Wait for it to finish") {
			t.Fatalf("err = %v", err)
		}
		if st, _ := collector.LoadState(); st == nil || st.Image != repo+":0.9.0@sha256:old" {
			t.Errorf("state must keep the running image, got %+v", st)
		}
	})
}

func TestRunUninstall_GCPDeletesTheDeployment(t *testing.T) {
	isolate(t)
	writeTokens(t)
	srv := statusServer(t, 204, "")
	defer srv.Close()
	if err := collector.SaveState(&collector.State{AgentID: "a1", Target: "gcp", Project: "acme-prod", Region: "us-central1", DeploymentName: "dbg-test"}); err != nil {
		t.Fatal(err)
	}
	deleted := stubDeleteGcpDeployment(t, nil)
	rec := &gcpDeployCall{}
	stubGcpSecrets(t, rec, nil)
	c := uninstallTestCmd()
	mustSet(t, c, "yes", "true")
	mustSet(t, c, "api-url", srv.URL)
	out := capture(t, func() {
		if err := runUninstall(c, nil); err != nil {
			t.Fatalf("uninstall: %v", err)
		}
	})
	if !*deleted {
		t.Error("the deployment must be deleted")
	}
	if rec.secretsDeleted != 1 {
		t.Error("the CLI owns the deployment's secrets and must delete them with it")
	}
	if !strings.Contains(out, "Deployment dbg-test deleted") || !strings.Contains(out, "Identity deprovisioned") {
		t.Errorf("want full teardown:\n%s", out)
	}
	if st, _ := collector.LoadState(); st != nil {
		t.Error("state should be removed after successful deprovision")
	}
}

// Ctrl-C during the delete: the deployment may still be deleting, so the
// identity must not be deprovisioned and the record must stay for a retry.
func TestRunUninstall_GCPInterruptedDeleteKeepsTheIdentity(t *testing.T) {
	isolate(t)
	writeTokens(t)
	deprovisioned := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deprovisioned = true
		}
		w.WriteHeader(http.StatusNoContent)
		_, _ = io.WriteString(w, "")
	}))
	defer srv.Close()
	if err := collector.SaveState(&collector.State{AgentID: "a1", Target: "gcp", Project: "acme-prod", Region: "us-central1", DeploymentName: "dbg-test"}); err != nil {
		t.Fatal(err)
	}
	stubDeleteGcpDeployment(t, fmt.Errorf("%w: program was interrupted", errInterrupted))
	rec := &gcpDeployCall{}
	stubGcpSecrets(t, rec, nil)
	c := uninstallTestCmd()
	mustSet(t, c, "yes", "true")
	mustSet(t, c, "api-url", srv.URL)
	var err error
	capture(t, func() { err = runUninstall(c, nil) })
	if err == nil || !strings.Contains(err.Error(), "uninstall") {
		t.Fatalf("err = %v, want a retry hint", err)
	}
	if deprovisioned {
		t.Error("the identity must not be deprovisioned while the deployment may be alive")
	}
	if st, _ := collector.LoadState(); st == nil {
		t.Error("state must stay for the retry")
	}
	if rec.secretsDeleted != 0 {
		t.Error("secrets must not be deleted while the deployment may still be reading them")
	}
}
