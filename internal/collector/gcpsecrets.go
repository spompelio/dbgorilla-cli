package collector

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// The collector's credentials on the gcp target live in Secret Manager and
// ONLY there: the CLI writes them with the operator's own credentials before
// deploying, the template merely grants the collector's service account read
// access by name, and the instance fetches the values at boot. Secret values
// therefore never reach Infrastructure Manager — neither the deployment's
// input values nor its Terraform state, both of which are readable by
// principals holding config.* read roles (Infrastructure Manager has no
// equivalent of CloudFormation's NoEcho).

const secretManagerBase = "https://secretmanager.googleapis.com/v1"

// gcpSecretSuffixes are the template's secret naming contract (a change is a
// template-version bump): each secret is "<deployment-name>-<suffix>", and the
// boot script fetches all three unconditionally.
var gcpSecretSuffixes = []string{"server-secret", "db-password", "instaclustr-api-key"}

// gcpSecretPlaceholder stands in for an absent credential (IAM-auth installs
// have no db password; cloud_sql installs no Instaclustr key), so the boot
// script never needs to know which credentials this install carries.
const gcpSecretPlaceholder = "unused"

// GcpSecretValues carries the three collector credentials. Empty fields are
// written as the placeholder.
type GcpSecretValues struct {
	ServerSecret   string
	DBPassword     string
	InstaclustrKey string
}

func (v GcpSecretValues) bySuffix() map[string]string {
	return map[string]string{
		"server-secret":       v.ServerSecret,
		"db-password":         v.DBPassword,
		"instaclustr-api-key": v.InstaclustrKey,
	}
}

// GcpSecretIDs lists the Secret Manager secret ids an install writes, in the
// template's naming contract.
func GcpSecretIDs(deploymentName string) []string {
	ids := make([]string, 0, len(gcpSecretSuffixes))
	for _, s := range gcpSecretSuffixes {
		ids = append(ids, deploymentName+"-"+s)
	}
	return ids
}

// EnsureGcpSecrets creates the deployment's three secrets (tolerating ones
// that already exist) and writes each value as a new version, which becomes
// "latest" atomically — a booting instance never observes a gap. Values
// travel only in request bodies, never in a URL or an error.
func EnsureGcpSecrets(project, deploymentName string, values GcpSecretValues) error {
	ctx := context.Background()
	cfg, err := loadGCPConfig(ctx)
	if err != nil {
		return gcpCredsErr(err)
	}
	for suffix, value := range values.bySuffix() {
		if value == "" {
			value = gcpSecretPlaceholder
		}
		if err := ensureGcpSecretVersion(ctx, cfg, project, deploymentName+"-"+suffix, value); err != nil {
			return err
		}
	}
	return nil
}

// EnsureGcpDBPassword writes a new version of the deployment's database
// password only — an update adding or rotating password auth — leaving the
// server secret and the Instaclustr key untouched.
func EnsureGcpDBPassword(project, deploymentName, password string) error {
	ctx := context.Background()
	cfg, err := loadGCPConfig(ctx)
	if err != nil {
		return gcpCredsErr(err)
	}
	return ensureGcpSecretVersion(ctx, cfg, project, deploymentName+"-db-password", password)
}

// ensureGcpSecretVersion creates the secret if absent and adds value as its
// newest version.
func ensureGcpSecretVersion(ctx context.Context, cfg gcpConfig, project, id, value string) error {
	createURL := fmt.Sprintf("%s/projects/%s/secrets?secretId=%s",
		secretManagerBase, url.PathEscape(project), url.QueryEscape(id))
	create := map[string]any{
		"replication": map[string]any{"automatic": map[string]any{}},
		"labels":      map[string]string{"managed-by": "dbgorilla-cli"},
	}
	if err := gcpDo(ctx, cfg, http.MethodPost, createURL, create, nil); err != nil &&
		!errors.Is(err, errGcpConflict) {
		return fmt.Errorf("could not create secret %q: %w", id, err)
	}
	versionURL := fmt.Sprintf("%s/projects/%s/secrets/%s:addVersion",
		secretManagerBase, url.PathEscape(project), url.PathEscape(id))
	payload := map[string]any{
		"payload": map[string]string{"data": base64.StdEncoding.EncodeToString([]byte(value))},
	}
	if err := gcpDo(ctx, cfg, http.MethodPost, versionURL, payload, nil); err != nil {
		return fmt.Errorf("could not write secret %q: %w", id, err)
	}
	return nil
}

// DeleteGcpSecrets removes the deployment's secrets, tolerating ones already
// gone. It is the uninstall/rollback counterpart of EnsureGcpSecrets: the CLI
// owns these secrets, the template only reads them.
func DeleteGcpSecrets(project, deploymentName string) error {
	ctx := context.Background()
	cfg, err := loadGCPConfig(ctx)
	if err != nil {
		return gcpCredsErr(err)
	}
	var errs []error
	for _, id := range GcpSecretIDs(deploymentName) {
		deleteURL := fmt.Sprintf("%s/projects/%s/secrets/%s",
			secretManagerBase, url.PathEscape(project), url.PathEscape(id))
		if err := gcpDo(ctx, cfg, http.MethodDelete, deleteURL, nil, nil); err != nil &&
			!errors.Is(err, errGcpNotFound) {
			errs = append(errs, fmt.Errorf("secret %q: %w", id, err))
		}
	}
	return errors.Join(errs...)
}
