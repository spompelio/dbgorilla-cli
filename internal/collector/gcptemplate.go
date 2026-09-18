package collector

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Where the collector's Terraform template for the gcp target is published.
// The CLI embeds no copy: what a customer reads at this address is exactly
// what their project deploys.
const (
	gcpTemplateBucket = "dbgorilla-collector-templates"
	gcpTemplateBase   = "gs://" + gcpTemplateBucket + "/collector/gce/"
)

// GcpTemplateVersion is the template's own version, bumped when its input
// contract changes; a published version is never rewritten. v1.3 removed the
// secret inputs (the CLI writes them to Secret Manager itself); v1.4 scopes
// the IAM grants per database service and conditions Cloud SQL's login role
// on the monitored instances.
const GcpTemplateVersion = "v1.4"

const gcpTemplateProbeTimeout = 5 * time.Second

// HostedGcpTemplateSource returns the published template directory this build
// deploys.
func HostedGcpTemplateSource() string { return gcpTemplateBase + GcpTemplateVersion }

// probeGcpTemplate confirms the template is reachable before any mutation.
func probeGcpTemplate(ctx context.Context, cfg gcpConfig, source string) error {
	rest, ok := strings.CutPrefix(source, "gs://")
	if !ok {
		return fmt.Errorf("template source %q is not a gs:// address", source)
	}
	probeURL := "https://storage.googleapis.com/" + strings.TrimSuffix(rest, "/") + "/main.tf"

	probeCtx, cancel := context.WithTimeout(ctx, gcpTemplateProbeTimeout)
	defer cancel()
	resp, err := gcpSend(probeCtx, cfg, http.MethodGet, probeURL, "", nil)
	if err != nil {
		return fmt.Errorf("could not reach the published collector template at %s "+
			"(check egress to storage.googleapis.com, or pass --template-source): %w",
			probeURL, err)
	}
	_ = resp.Body.Close()
	return nil
}
