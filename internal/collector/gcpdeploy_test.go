package collector

import (
	"errors"
	"strings"
	"testing"
)

// The Infrastructure Manager lifecycle: create vs update, busy refusal,
// timeout vs failure, delete.

const (
	probePath  = "/tmpl/collector/gce/v1.0/main.tf"
	depPath    = "/v1/projects/p/locations/us-central1/deployments/dbg"
	depsPath   = "/v1/projects/p/locations/us-central1/deployments"
	opPath     = "/v1/projects/p/locations/us-central1/operations/op-1"
	opResource = "projects/p/locations/us-central1/operations/op-1"
)

func testDeploy() GcpDeploy {
	return GcpDeploy{
		Project: "p", Region: "us-central1", DeploymentName: "dbg",
		TemplateSource: "gs://tmpl/collector/gce/v1.0",
		ServiceAccount: "projects/p/serviceAccounts/deployer@p.iam.gserviceaccount.com",
		Inputs:         map[string]string{"collector_image": "img@sha256:abc"},
	}
}

func TestGcpDeploy_CreatesWhenAbsent(t *testing.T) {
	f := newGCPFake(t).
		on("GET", probePath, 200, "# template").
		// Absent before the create; ACTIVE when read back after the operation.
		onSeq("GET", depPath,
			gcpFakeResp{404, gcpNotFoundJSON},
			gcpFakeResp{200, deploymentJSON("ACTIVE", "")}).
		on("POST", depsPath, 200, operationJSON(opResource, false, "")).
		onSeq("GET", opPath,
			gcpFakeResp{200, operationJSON(opResource, false, "")},
			gcpFakeResp{200, operationJSON(opResource, true, "")})
	stubGCP(t, f)

	if err := testDeploy().Run(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if f.called("POST", depsPath) != 1 || f.called("PATCH", depPath) != 0 {
		t.Fatalf("an absent deployment must be created, not patched: %v", f.calls)
	}
	// The id travels as a query parameter; the body carries the actuating
	// service account and every input as an inputValue.
	if c := f.lastCall("POST " + depsPath); !strings.Contains(c, "deploymentId=dbg") {
		t.Errorf("create must name the deployment id, got %s", c)
	}
	body := f.lastBody("POST", depsPath)
	for _, want := range []string{`"serviceAccount":"projects/p/serviceAccounts/deployer@p.iam.gserviceaccount.com"`,
		`"gcsSource":"gs://tmpl/collector/gce/v1.0"`, `"collector_image":{"inputValue":"img@sha256:abc"}`} {
		if !strings.Contains(body, want) {
			t.Errorf("create body missing %s:\n%s", want, body)
		}
	}
	if f.called("GET", opPath) != 2 {
		t.Errorf("the operation should be polled until done, polled %d times", f.called("GET", opPath))
	}
}

func TestGcpDeploy_SettledDeploymentsUpdateInPlace(t *testing.T) {
	for _, state := range []string{"ACTIVE", "FAILED", "SUSPENDED"} {
		t.Run(state, func(t *testing.T) {
			f := newGCPFake(t).
				on("GET", probePath, 200, "# template").
				// The settled state before; ACTIVE once the re-apply lands.
				onSeq("GET", depPath,
					gcpFakeResp{200, deploymentJSON(state, "")},
					gcpFakeResp{200, deploymentJSON("ACTIVE", "")}).
				on("PATCH", depPath, 200, operationJSON(opResource, true, ""))
			stubGCP(t, f)
			if err := testDeploy().Run(); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if f.called("PATCH", depPath) != 1 || f.called("POST", depsPath) != 0 {
				t.Fatalf("a %s deployment must be patched, not created: %v", state, f.calls)
			}
			if c := f.lastCall("PATCH " + depPath); !strings.Contains(c, "updateMask=service_account,terraform_blueprint") {
				t.Errorf("the update must mask to the fields it sends, got %s", c)
			}
		})
	}
}

// An update whose revision fails at terraform apply completes its operation
// with no error payload; the deployment's own state says FAILED.
func TestGcpDeploy_FailedRevisionBehindACleanOperation(t *testing.T) {
	f := newGCPFake(t).
		on("GET", probePath, 200, "# template").
		onSeq("GET", depPath,
			gcpFakeResp{200, deploymentJSON("ACTIVE", "")},
			gcpFakeResp{200, `{"name":"projects/p/locations/us-central1/deployments/dbg","state":"FAILED",` +
				`"stateDetail":"Revision failed: the apply build failed while running: tf-apply.","errorLogs":"gs://logs/dbg/r-2/errors/tf-error.ndjson"}`}).
		on("PATCH", depPath, 200, operationJSON(opResource, true, ""))
	stubGCP(t, f)
	err := testDeploy().Run()
	if err == nil || !strings.Contains(err.Error(), "did not apply cleanly") ||
		!strings.Contains(err.Error(), "tf-apply") || !strings.Contains(err.Error(), "gs://logs/dbg/r-2") {
		t.Fatalf("err = %v, want the failed state with its reason and log", err)
	}
	if errors.Is(err, ErrDeployTimeout) || errors.Is(err, ErrDeployUnknown) || errors.Is(err, ErrDeployBusy) {
		t.Fatalf("a failed apply is a plain failure, got %v", err)
	}
}

func TestGcpDeploy_RefusesWhileAnotherOperationRuns(t *testing.T) {
	for _, state := range []string{"CREATING", "UPDATING", "DELETING"} {
		t.Run(state, func(t *testing.T) {
			f := newGCPFake(t).
				on("GET", probePath, 200, "# template").
				on("GET", depPath, 200, deploymentJSON(state, ""))
			stubGCP(t, f)
			err := testDeploy().Run()
			if err == nil || !strings.Contains(err.Error(), "already in progress") {
				t.Fatalf("err = %v, want the in-progress refusal", err)
			}
			if m := f.mutations(); len(m) != 0 {
				t.Errorf("nothing may be mutated while an operation runs, got %v", m)
			}
		})
	}
}

// The probe runs on every deploy, before anything exists to roll back.
func TestGcpDeploy_UnreachableTemplateStopsBeforeAnyMutation(t *testing.T) {
	f := newGCPFake(t).on("GET", probePath, 404, `<Error><Code>NoSuchKey</Code></Error>`)
	stubGCP(t, f)

	err := testDeploy().Run()
	if err == nil || !strings.Contains(err.Error(), "--template-source") {
		t.Fatalf("err = %v, want the template remediation", err)
	}
	if len(f.calls) != 1 {
		t.Errorf("only the probe may run, got %v", f.calls)
	}
}

func TestGcpDeploy_RejectsANonGCSTemplateSource(t *testing.T) {
	stubGCP(t, newGCPFake(t))
	d := testDeploy()
	d.TemplateSource = "https://example.com/collector-gce"
	if err := d.Run(); err == nil || !strings.Contains(err.Error(), "gs://") {
		t.Fatalf("err = %v, want a gs:// requirement", err)
	}
}

func TestGcpDeploy_DryRunOnlyProbes(t *testing.T) {
	f := newGCPFake(t).on("GET", probePath, 200, "# template")
	stubGCP(t, f)
	d := testDeploy()
	d.DryRun = true
	if err := d.Run(); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if len(f.calls) != 1 {
		t.Errorf("a dry run reads the template and nothing else, got %v", f.calls)
	}
}

// A timeout must be distinguishable from a terminal failure.
func TestGcpDeploy_TimeoutIsTaggedNotFailed(t *testing.T) {
	f := newGCPFake(t).
		on("GET", probePath, 200, "# template").
		on("GET", depPath, 404, gcpNotFoundJSON).
		on("POST", depsPath, 200, operationJSON(opResource, false, "")).
		on("GET", opPath, 200, operationJSON(opResource, false, ""))
	stubGCP(t, f)
	orig := gcpDeployTimeout
	gcpDeployTimeout = 0
	t.Cleanup(func() { gcpDeployTimeout = orig })

	err := testDeploy().Run()
	if !errors.Is(err, ErrDeployTimeout) {
		t.Fatalf("err = %v, want ErrDeployTimeout", err)
	}
	if !strings.Contains(err.Error(), "still applying") {
		t.Errorf("the message should say the deploy is still going, got %v", err)
	}
}

func TestGcpDeploy_FailureCarriesTheDeploymentsReason(t *testing.T) {
	f := newGCPFake(t).
		on("GET", probePath, 200, "# template").
		onSeq("GET", depPath,
			gcpFakeResp{404, gcpNotFoundJSON},
			gcpFakeResp{200, deploymentJSON("FAILED", "quota exceeded for CPUS")}).
		on("POST", depsPath, 200, operationJSON(opResource, true, "terraform apply failed"))
	stubGCP(t, f)

	err := testDeploy().Run()
	if err == nil || errors.Is(err, ErrDeployTimeout) {
		t.Fatalf("err = %v, want a terminal failure", err)
	}
	for _, want := range []string{"terraform apply failed", "quota exceeded for CPUS", "did not apply cleanly"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should carry %q, got: %v", want, err)
		}
	}
}

func TestGcpDeploymentStatus(t *testing.T) {
	t.Run("absent is empty, not an error", func(t *testing.T) {
		stubGCP(t, newGCPFake(t).on("GET", depPath, 404, gcpNotFoundJSON))
		got, err := GcpDeploymentStatus("p", "us-central1", "dbg")
		if err != nil || got != "" {
			t.Fatalf("got (%q, %v), want (\"\", nil)", got, err)
		}
	})
	t.Run("present reports the state", func(t *testing.T) {
		stubGCP(t, newGCPFake(t).on("GET", depPath, 200, deploymentJSON("ACTIVE", "")))
		got, err := GcpDeploymentStatus("p", "us-central1", "dbg")
		if err != nil || got != "ACTIVE" {
			t.Fatalf("got (%q, %v)", got, err)
		}
	})
	t.Run("a denial carries Google's own message", func(t *testing.T) {
		stubGCP(t, newGCPFake(t).on("GET", depPath, 403, gcpDeniedJSON))
		_, err := GcpDeploymentStatus("p", "us-central1", "dbg")
		if err == nil || !strings.Contains(err.Error(), "config.deployments.get denied") {
			t.Fatalf("err = %v, want the API's message", err)
		}
	})
}

func TestDeleteGcpDeployment_DestroysResourcesAndWaits(t *testing.T) {
	f := newGCPFake(t).
		on("DELETE", depPath, 200, operationJSON(opResource, false, "")).
		on("GET", opPath, 200, operationJSON(opResource, true, ""))
	stubGCP(t, f)
	if err := DeleteGcpDeployment("p", "us-central1", "dbg"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	// Abandoning the Terraform-managed resources would leave a billed VM
	// behind an uninstall.
	if c := f.lastCall("DELETE " + depPath); !strings.Contains(c, "deletePolicy=DELETE") {
		t.Errorf("delete must destroy the managed resources, got %s", c)
	}
	if f.called("GET", opPath) != 1 {
		t.Errorf("the delete operation should be waited on, polled %d times", f.called("GET", opPath))
	}
}

// Every GCP entry point must turn a missing credential into the same next step.
func TestGcpCredentialFailuresNameTheFix(t *testing.T) {
	stubGCPConfigError(t, errNoADC)
	calls := map[string]func() error{
		"deploy":   func() error { return testDeploy().Run() },
		"status":   func() error { _, err := GcpDeploymentStatus("p", "r", "d"); return err },
		"delete":   func() error { return DeleteGcpDeployment("p", "r", "d") },
		"scale":    func() error { return ScaleGcpMig("p", "r", "d", 0) },
		"restart":  func() error { return RestartGcpMig("p", "r", "d") },
		"logs":     func() error { return TailGcpLogs("p", "r", "d", false) },
		"discover": func() error { _, err := DiscoverGcpTarget("", "", GcpTarget{Project: "p"}); return err },
		"identity": func() error { _, err := GcpIdentity(); return err },
		"project":  func() error { _, err := GcpProject(); return err },
	}
	for name, call := range calls {
		if err := call(); err == nil || !strings.Contains(err.Error(), "gcloud auth application-default login") {
			t.Errorf("%s: err = %v, want the ADC remediation", name, err)
		}
	}
}

// What an update or upgrade starts from: the deployment as it was applied.
const specJSON = `{"name":"projects/p/locations/us-central1/deployments/dbg","state":"ACTIVE",
  "serviceAccount":"projects/p/serviceAccounts/deployer@p.iam.gserviceaccount.com",
  "terraformBlueprint":{"gcsSource":"gs://tmpl/collector/gce/v1.0","inputValues":{
    "collector_image":{"inputValue":"img@sha256:old"},
    "network":{"inputValue":"projects/p/global/networks/default"},
    "stable_egress":{"inputValue":true},
    "nat_subnet_cidr":{"inputValue":""}}}}`

func TestGetGcpDeploymentSpec_ReadsWhatWasApplied(t *testing.T) {
	stubGCP(t, newGCPFake(t).on("GET", depPath, 200, specJSON))
	spec, err := GetGcpDeploymentSpec("p", "us-central1", "dbg")
	if err != nil || spec == nil {
		t.Fatalf("spec = %+v, err = %v", spec, err)
	}
	if spec.State != "ACTIVE" || spec.TemplateSource != "gs://tmpl/collector/gce/v1.0" ||
		spec.ServiceAccount != "projects/p/serviceAccounts/deployer@p.iam.gserviceaccount.com" {
		t.Errorf("spec = %+v", spec)
	}
	// Values come back as the CLI sends them — strings — even when the
	// deployment carries a typed one.
	if spec.Inputs["collector_image"] != "img@sha256:old" || spec.Inputs["stable_egress"] != "true" || spec.Inputs["nat_subnet_cidr"] != "" {
		t.Errorf("inputs = %v", spec.Inputs)
	}

	stubGCP(t, newGCPFake(t).on("GET", depPath, 404, gcpNotFoundJSON))
	if spec, err := GetGcpDeploymentSpec("p", "us-central1", "dbg"); err != nil || spec != nil {
		t.Fatalf("an absent deployment is (nil, nil), got %+v, %v", spec, err)
	}
}

func TestUpgradeGcpImage_ChangesOnlyTheImage(t *testing.T) {
	f := newGCPFake(t).
		on("GET", depPath, 200, specJSON).
		on("GET", probePath, 200, "# template").
		on("PATCH", depPath, 200, operationJSON(opResource, true, ""))
	stubGCP(t, f)
	if err := UpgradeGcpImage("p", "us-central1", "dbg", "img@sha256:new"); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	body := f.lastBody("PATCH", depPath)
	for _, want := range []string{
		`"gcsSource":"gs://tmpl/collector/gce/v1.0"`, // the deployment's own template, never swapped
		`"serviceAccount":"projects/p/serviceAccounts/deployer@p.iam.gserviceaccount.com"`,
		`"collector_image":{"inputValue":"img@sha256:new"}`,
		`"network":{"inputValue":"projects/p/global/networks/default"}`,
		`"stable_egress":{"inputValue":"true"}`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("update body missing %s:\n%s", want, body)
		}
	}
	if f.called("POST", depsPath) != 0 {
		t.Error("an upgrade never creates a deployment")
	}
}

func TestUpgradeGcpImage_AlreadyOnTheImageTouchesNothing(t *testing.T) {
	f := newGCPFake(t).on("GET", depPath, 200, specJSON)
	stubGCP(t, f)
	err := UpgradeGcpImage("p", "us-central1", "dbg", "img@sha256:old")
	if err == nil || !strings.Contains(err.Error(), "nothing to upgrade") {
		t.Fatalf("err = %v", err)
	}
	if m := f.mutations(); len(m) != 0 {
		t.Errorf("no mutation expected, got %v", m)
	}
}

func TestGcpDeploy_RequireExistingNeverCreates(t *testing.T) {
	f := newGCPFake(t).
		on("GET", probePath, 200, "# template").
		on("GET", depPath, 404, gcpNotFoundJSON)
	stubGCP(t, f)
	d := testDeploy()
	d.RequireExisting = true
	err := d.Run()
	if err == nil || !strings.Contains(err.Error(), "no longer exists") {
		t.Fatalf("err = %v", err)
	}
	if m := f.mutations(); len(m) != 0 {
		t.Errorf("an update of a vanished deployment must not create one, got %v", m)
	}
}
