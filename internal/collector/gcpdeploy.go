package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// The gcp deployment: Infrastructure Manager (managed Terraform) actuating the
// published template. The template is never embedded in this binary.

const infraManagerBase = "https://config.googleapis.com/v1"

// Variables rather than constants so tests can shorten the waits.
var (
	gcpDeployTimeout      = 30 * time.Minute
	gcpDeleteTimeout      = 15 * time.Minute
	gcpPollInterval       = 5 * time.Second
	gcpPollRequestTimeout = 30 * time.Second
)

// GcpDeploy describes one Infrastructure Manager deployment of the collector.
type GcpDeploy struct {
	Project        string
	Region         string
	DeploymentName string
	// TemplateSource is the template's gs:// directory.
	TemplateSource string
	// ServiceAccount is the account Infrastructure Manager actuates Terraform
	// as (projects/{p}/serviceAccounts/{email}).
	ServiceAccount string
	// Inputs are the template's input variables (gcpInputKeys). None carries a
	// credential: secret values go straight to Secret Manager
	// (EnsureGcpSecrets) and never enter the deployment — its input values and
	// Terraform state are readable by config.* read roles.
	Inputs map[string]string
	DryRun bool
	// RequireExisting refuses to create: an update or upgrade of a deployment
	// that has meanwhile vanished must not quietly become a fresh install
	// (the secrets and identity it would need are not this run's to mint).
	RequireExisting bool
}

// Run deploys (create, or update in place) and waits for a terminal state.
func (d GcpDeploy) Run() error { return d.deploy(context.Background()) }

// GcpDeployTimeout exposes the wait budget so the command layer can name it.
func GcpDeployTimeout() time.Duration { return gcpDeployTimeout }

func gcpDeploymentPath(project, region, name string) string {
	return fmt.Sprintf("projects/%s/locations/%s/deployments/%s",
		url.PathEscape(project), url.PathEscape(region), url.PathEscape(name))
}

type gcpDeployment struct {
	Name               string `json:"name"`
	State              string `json:"state"` // CREATING | ACTIVE | UPDATING | DELETING | FAILED | SUSPENDED
	StateDetail        string `json:"stateDetail"`
	ErrorLogs          string `json:"errorLogs"`
	LatestRevision     string `json:"latestRevision"`
	ServiceAccount     string `json:"serviceAccount"`
	TerraformBlueprint struct {
		GcsSource   string `json:"gcsSource"`
		InputValues map[string]struct {
			InputValue any `json:"inputValue"`
		} `json:"inputValues"`
	} `json:"terraformBlueprint"`
}

// GcpDeploymentSpec is what an existing deployment was applied with: the
// template it deploys, the account that actuates it, and its input values.
// An update or upgrade starts from it, so nothing the install chose is
// re-derived.
type GcpDeploymentSpec struct {
	State          string
	TemplateSource string
	ServiceAccount string
	Inputs         map[string]string
}

func (d *gcpDeployment) spec() *GcpDeploymentSpec {
	inputs := make(map[string]string, len(d.TerraformBlueprint.InputValues))
	for k, v := range d.TerraformBlueprint.InputValues {
		inputs[k] = inputValueString(v.InputValue)
	}
	return &GcpDeploymentSpec{
		State:          d.State,
		TemplateSource: d.TerraformBlueprint.GcsSource,
		ServiceAccount: d.ServiceAccount,
		Inputs:         inputs,
	}
}

// inputValueString renders a stored input value the way the CLI sends it: as
// a string. The CLI only ever sends strings, but a deployment applied by hand
// may carry typed values.
func inputValueString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		return strconv.FormatBool(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// GetGcpDeploymentSpec reads what the deployment was applied with; nil when
// it does not exist.
func GetGcpDeploymentSpec(project, region, name string) (*GcpDeploymentSpec, error) {
	ctx := context.Background()
	cfg, err := loadGCPConfig(ctx)
	if err != nil {
		return nil, gcpCredsErr(err)
	}
	dep, err := getGcpDeployment(ctx, cfg, gcpDeploymentPath(project, region, name))
	if err != nil || dep == nil {
		return nil, err
	}
	return dep.spec(), nil
}

// UpgradeGcpImage rolls the deployment to a new collector image, holding
// every other input and the deployment's own template: the monitored
// databases and the networking must not change under an upgrade.
func UpgradeGcpImage(project, region, name, image string) error {
	spec, err := GetGcpDeploymentSpec(project, region, name)
	if err != nil {
		return err
	}
	if spec == nil {
		return fmt.Errorf("deployment %q no longer exists — run `dbg collector install --target gcp` to create one", name)
	}
	if spec.Inputs["collector_image"] == image {
		return fmt.Errorf("already on %s (nothing to upgrade)", image)
	}
	inputs := make(map[string]string, len(spec.Inputs))
	for k, v := range spec.Inputs {
		inputs[k] = v
	}
	inputs["collector_image"] = image
	return GcpDeploy{
		Project: project, Region: region, DeploymentName: name,
		TemplateSource: spec.TemplateSource, ServiceAccount: spec.ServiceAccount,
		Inputs: inputs, RequireExisting: true,
	}.Run()
}

func (d GcpDeploy) body() map[string]any {
	inputs := map[string]any{}
	for k, v := range d.Inputs {
		inputs[k] = map[string]any{"inputValue": v}
	}
	return map[string]any{
		"serviceAccount": d.ServiceAccount,
		"terraformBlueprint": map[string]any{
			"gcsSource":   d.TemplateSource,
			"inputValues": inputs,
		},
	}
}

func (d GcpDeploy) deploy(ctx context.Context) error {
	cfg, err := loadGCPConfig(ctx)
	if err != nil {
		return gcpCredsErr(err)
	}
	// Probed on every path so an unreachable template fails before anything
	// is created.
	if err := probeGcpTemplate(ctx, cfg, d.TemplateSource); err != nil {
		return err
	}
	if d.DryRun {
		// Infrastructure Manager has no validate-only call; the probe is the
		// whole dry run.
		return nil
	}

	path := gcpDeploymentPath(d.Project, d.Region, d.DeploymentName)
	existing, err := getGcpDeployment(ctx, cfg, path)
	if err != nil {
		return err
	}
	if existing != nil {
		if gcpDeploymentInProgress(existing.State) {
			return fmt.Errorf("deployment %q is %s — another operation is already in progress; "+
				"wait for it to finish and re-run: %w", d.DeploymentName, existing.State, ErrDeployBusy)
		}
		// Any settled state (ACTIVE, SUSPENDED, FAILED) re-applies in place.
		return d.mutate(ctx, cfg, http.MethodPatch,
			infraManagerBase+"/"+path+"?updateMask=service_account,terraform_blueprint")
	}
	if d.RequireExisting {
		return fmt.Errorf("deployment %q no longer exists — run `dbg collector install --target gcp` to create one", d.DeploymentName)
	}
	createURL := fmt.Sprintf("%s/projects/%s/locations/%s/deployments?deploymentId=%s",
		infraManagerBase, url.PathEscape(d.Project), url.PathEscape(d.Region),
		url.QueryEscape(d.DeploymentName))
	return d.mutate(ctx, cfg, http.MethodPost, createURL)
}

func (d GcpDeploy) mutate(ctx context.Context, cfg gcpConfig, method, rawURL string) error {
	op, err := startGcpOperation(ctx, cfg, method, rawURL, d.body())
	if err != nil {
		return fmt.Errorf("could not deploy %q: %w", d.DeploymentName, err)
	}
	if err := waitGcpOperation(ctx, cfg, op, gcpDeployTimeout); err != nil {
		switch {
		case errors.Is(err, ErrDeployTimeout):
			return fmt.Errorf("deployment %q is still applying after %s: %w",
				d.DeploymentName, gcpDeployTimeout, err)
		case errors.Is(err, ErrDeployUnknown):
			return fmt.Errorf("deployment %q may still be applying: %w", d.DeploymentName, err)
		}
		path := gcpDeploymentPath(d.Project, d.Region, d.DeploymentName)
		return fmt.Errorf("deployment %q did not apply cleanly: %w%s",
			d.DeploymentName, err, gcpDeploymentFailureReason(ctx, cfg, path))
	}
	return nil
}

func gcpDeploymentInProgress(state string) bool {
	switch state {
	case "CREATING", "UPDATING", "DELETING":
		return true
	}
	return false
}

// GcpDeploymentStatus reports the deployment's state, or "" when it does not
// exist.
func GcpDeploymentStatus(project, region, name string) (string, error) {
	ctx := context.Background()
	cfg, err := loadGCPConfig(ctx)
	if err != nil {
		return "", gcpCredsErr(err)
	}
	dep, err := getGcpDeployment(ctx, cfg, gcpDeploymentPath(project, region, name))
	if err != nil {
		return "", err
	}
	if dep == nil {
		return "", nil
	}
	return dep.State, nil
}

// GcpDeploymentOutput reads one Terraform output off the deployment's latest
// applied revision — how the CLI learns the egress_ip a stable-egress deploy
// reserved, so the firewall allowlist carries the address the database will
// actually see.
func GcpDeploymentOutput(project, region, name, key string) (string, error) {
	ctx := context.Background()
	cfg, err := loadGCPConfig(ctx)
	if err != nil {
		return "", gcpCredsErr(err)
	}
	dep, err := getGcpDeployment(ctx, cfg, gcpDeploymentPath(project, region, name))
	if err != nil {
		return "", err
	}
	if dep == nil {
		return "", fmt.Errorf("deployment %q does not exist", name)
	}
	if dep.LatestRevision == "" {
		return "", fmt.Errorf("deployment %q has no applied revision yet — is it still deploying?", name)
	}
	var rev struct {
		ApplyResults struct {
			Outputs map[string]struct {
				Value any `json:"value"`
			} `json:"outputs"`
		} `json:"applyResults"`
	}
	if err := gcpDo(ctx, cfg, http.MethodGet, infraManagerBase+"/"+dep.LatestRevision, nil, &rev); err != nil {
		return "", fmt.Errorf("could not read deployment %q's latest revision: %w", name, err)
	}
	out, ok := rev.ApplyResults.Outputs[key]
	if !ok {
		return "", fmt.Errorf("deployment %q has no %s output — was it deployed with stable egress enabled?", name, key)
	}
	s, ok := out.Value.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("deployment %q's %s output is empty — was it deployed with stable egress enabled?", name, key)
	}
	return s, nil
}

// DeleteGcpDeployment destroys the deployment and everything Terraform
// created, waiting for the delete. A deployment that does not exist is not an
// error.
func DeleteGcpDeployment(project, region, name string) error {
	ctx := context.Background()
	cfg, err := loadGCPConfig(ctx)
	if err != nil {
		return gcpCredsErr(err)
	}
	op, err := startGcpOperation(ctx, cfg, http.MethodDelete,
		infraManagerBase+"/"+gcpDeploymentPath(project, region, name)+"?force=true&deletePolicy=DELETE", nil)
	if err != nil {
		if errors.Is(err, errGcpNotFound) {
			return nil
		}
		return fmt.Errorf("could not delete deployment %q: %w", name, err)
	}
	if err := waitGcpOperation(ctx, cfg, op, gcpDeleteTimeout); err != nil {
		return fmt.Errorf("deployment %q did not delete cleanly: %w", name, err)
	}
	return nil
}

// gcpDeploymentFailureReason best-effort appends the deployment's error detail.
func gcpDeploymentFailureReason(ctx context.Context, cfg gcpConfig, path string) string {
	dep, err := getGcpDeployment(ctx, cfg, path)
	if err != nil || dep == nil {
		return ""
	}
	detail := dep.StateDetail
	if detail == "" && dep.ErrorLogs != "" {
		detail = "error logs: " + dep.ErrorLogs
	}
	if detail == "" {
		return ""
	}
	return "\n  reason: " + detail
}

// getGcpDeployment fetches a deployment; a 404 is (nil, nil).
func getGcpDeployment(ctx context.Context, cfg gcpConfig, path string) (*gcpDeployment, error) {
	var dep gcpDeployment
	err := gcpDo(ctx, cfg, http.MethodGet, infraManagerBase+"/"+path, nil, &dep)
	if errors.Is(err, errGcpNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &dep, nil
}

// gcpOperation is the long-running operation envelope mutations return.
type gcpOperation struct {
	Name  string `json:"name"`
	Done  bool   `json:"done"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func startGcpOperation(ctx context.Context, cfg gcpConfig, method, rawURL string, body any) (*gcpOperation, error) {
	var op gcpOperation
	if err := gcpDo(ctx, cfg, method, rawURL, body, &op); err != nil {
		return nil, err
	}
	return &op, nil
}

// waitGcpOperation polls the operation until done, error, or the budget runs
// out (ErrDeployTimeout). A few consecutive poll failures are tolerated; past
// that the outcome is ErrDeployUnknown, since the server converges regardless.
func waitGcpOperation(ctx context.Context, cfg gcpConfig, op *gcpOperation, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	const maxConsecutivePollFailures = 4
	pollFailures := 0
	for {
		if op.Done {
			if op.Error != nil {
				return errors.New(op.Error.Message)
			}
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%w: operation %s still running", ErrDeployTimeout, op.Name)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(gcpPollInterval):
		}
		var next gcpOperation
		pollCtx, cancelPoll := context.WithTimeout(ctx, gcpPollRequestTimeout)
		err := gcpDo(pollCtx, cfg, http.MethodGet, infraManagerBase+"/"+op.Name, nil, &next)
		cancelPoll()
		if err != nil {
			pollFailures++
			if pollFailures >= maxConsecutivePollFailures {
				return fmt.Errorf("polling operation %s failed %d times in a row: %v: %w",
					op.Name, pollFailures, err, ErrDeployUnknown)
			}
			continue
		}
		pollFailures = 0
		op = &next
	}
}
