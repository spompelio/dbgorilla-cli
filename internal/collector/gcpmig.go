package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Day-2 operations against the deployment's managed instance group and its
// logs. The template names the group after the deployment.

const (
	computeBase = "https://compute.googleapis.com/compute/v1"
	loggingBase = "https://logging.googleapis.com/v2"
)

// Variables rather than constants so tests can shorten the waits.
var (
	// computeOpTimeout bounds the whole operation, across several blocking
	// /wait cycles — it must be a multiple of computeWaitTimeout, or an
	// operation still RUNNING after the first ~2-minute /wait fails "did not
	// finish in time" while it is progressing (a MIG recreate regularly does).
	// It also bounds WaitGcpMigStable, a rollout being the same recreate.
	computeOpTimeout = 10 * time.Minute
	// computeWaitTimeout bounds one call to the blocking /wait endpoint, which
	// itself returns after about two minutes.
	computeWaitTimeout = 3 * time.Minute
)

// ErrGcpMigRolling marks a rollout still in progress when the wait budget ran
// out; the group converges regardless.
var ErrGcpMigRolling = errors.New("instance group still rolling")

// migSettledReadings is how many consecutive settled readings a rollout must
// show before it counts as done. The group reports stable for a moment
// after Terraform sets its new template and before its updater picks the
// change up (observed live), so one reading proves nothing.
const migSettledReadings = 3

// WaitGcpMigStable waits until the group's instances all run its target
// template and no action is pending — after an update or upgrade, that the
// instance was recreated on the new one. A stopped group (size 0) settles at
// once.
func WaitGcpMigStable(project, region, deploymentName string) error {
	ctx := context.Background()
	cfg, err := loadGCPConfig(ctx)
	if err != nil {
		return gcpCredsErr(err)
	}
	deadline := time.Now().Add(computeOpTimeout)
	settled := 0
	for {
		var mig struct {
			Status struct {
				IsStable      bool `json:"isStable"`
				VersionTarget struct {
					IsReached bool `json:"isReached"`
				} `json:"versionTarget"`
			} `json:"status"`
		}
		if err := gcpDo(ctx, cfg, http.MethodGet, migPath(project, region, deploymentName), nil, &mig); err != nil {
			return fmt.Errorf("could not read collector group %q: %w", deploymentName, err)
		}
		if mig.Status.IsStable && mig.Status.VersionTarget.IsReached {
			if settled++; settled >= migSettledReadings {
				return nil
			}
		} else {
			settled = 0
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%w after %s", ErrGcpMigRolling, computeOpTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(gcpPollInterval):
		}
	}
}

// migPath is the regional instance group manager the template creates.
func migPath(project, region, deploymentName string) string {
	return fmt.Sprintf("%s/projects/%s/regions/%s/instanceGroupManagers/%s", computeBase,
		url.PathEscape(project), url.PathEscape(region), url.PathEscape(deploymentName))
}

// ScaleGcpMig sets the group's target size: 0 stops the collector, 1 resumes
// it.
func ScaleGcpMig(project, region, deploymentName string, size int) error {
	ctx := context.Background()
	cfg, err := loadGCPConfig(ctx)
	if err != nil {
		return gcpCredsErr(err)
	}
	u := fmt.Sprintf("%s/resize?size=%d", migPath(project, region, deploymentName), size)
	op, err := startGcpOperation(ctx, cfg, http.MethodPost, u, nil)
	if err != nil {
		return fmt.Errorf("could not scale collector group %q to %d: %w", deploymentName, size, err)
	}
	return waitComputeOperation(ctx, cfg, project, region, op.Name)
}

// RestartGcpMig recreates the group's instances.
func RestartGcpMig(project, region, deploymentName string) error {
	ctx := context.Background()
	cfg, err := loadGCPConfig(ctx)
	if err != nil {
		return gcpCredsErr(err)
	}
	instances, err := listManagedInstances(ctx, cfg, project, region, deploymentName)
	if err != nil {
		return err
	}
	if len(instances) == 0 {
		return fmt.Errorf("collector group %q has no instances to restart — "+
			"is it stopped? Run: dbg collector start", deploymentName)
	}
	names := make([]string, 0, len(instances))
	for _, mi := range instances {
		names = append(names, mi.Instance)
	}
	u := migPath(project, region, deploymentName) + "/recreateInstances"
	op, err := startGcpOperation(ctx, cfg, http.MethodPost, u, map[string]any{"instances": names})
	if err != nil {
		return fmt.Errorf("could not restart collector group %q: %w", deploymentName, err)
	}
	return waitComputeOperation(ctx, cfg, project, region, op.Name)
}

type managedInstance struct {
	Instance string `json:"instance"` // resource URL
	ID       string `json:"id"`       // numeric instance id, as Cloud Logging labels it
}

func listManagedInstances(ctx context.Context, cfg gcpConfig, project, region, deploymentName string) ([]managedInstance, error) {
	var out struct {
		ManagedInstances []managedInstance `json:"managedInstances"`
	}
	u := migPath(project, region, deploymentName) + "/listManagedInstances"
	if err := gcpDo(ctx, cfg, http.MethodPost, u, nil, &out); err != nil {
		return nil, fmt.Errorf("could not list instances of collector group %q: %w", deploymentName, err)
	}
	instances := make([]managedInstance, 0, len(out.ManagedInstances))
	for _, mi := range out.ManagedInstances {
		if mi.Instance != "" {
			instances = append(instances, mi)
		}
	}
	sort.Slice(instances, func(i, j int) bool { return instances[i].Instance < instances[j].Instance })
	return instances, nil
}

// waitComputeOperation drives a regional compute operation to completion via
// its blocking /wait endpoint.
func waitComputeOperation(ctx context.Context, cfg gcpConfig, project, region, opName string) error {
	if opName == "" {
		return nil
	}
	u := fmt.Sprintf("%s/projects/%s/regions/%s/operations/%s/wait", computeBase,
		url.PathEscape(project), url.PathEscape(region), url.PathEscape(opName))
	deadline := time.Now().Add(computeOpTimeout)
	for {
		var out struct {
			Status string `json:"status"`
			Error  *struct {
				Errors []struct {
					Message string `json:"message"`
				} `json:"errors"`
			} `json:"error"`
		}
		waitCtx, cancel := context.WithTimeout(ctx, computeWaitTimeout)
		err := gcpDo(waitCtx, cfg, http.MethodPost, u, nil, &out)
		cancel()
		if err != nil {
			return err
		}
		if out.Error != nil && len(out.Error.Errors) > 0 {
			return fmt.Errorf("%s", out.Error.Errors[0].Message)
		}
		if out.Status == "DONE" {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("compute operation %s did not finish in time", opName)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// TailGcpLogs prints the collector's container logs from Cloud Logging, scoped
// to the group's current instances. `follow` polls until interrupted.
func TailGcpLogs(project, region, deploymentName string, follow bool) error {
	ctx := context.Background()
	cfg, err := loadGCPConfig(ctx)
	if err != nil {
		return gcpCredsErr(err)
	}
	instances, err := listManagedInstances(ctx, cfg, project, region, deploymentName)
	if err != nil {
		return err
	}
	if len(instances) == 0 {
		return fmt.Errorf("collector group %q has no instances — is it stopped? Run: dbg collector start", deploymentName)
	}
	filter := gcpLogFilter(instances)
	cur := newLogCursor(time.Now().Add(-10 * time.Minute).UnixNano())
	for {
		entries, err := listLogEntries(ctx, cfg, project, filter, time.Unix(0, cur.newest).UTC())
		if err != nil {
			return err
		}
		for _, e := range entries {
			if !cur.accept(e.InsertID, e.Timestamp.UnixNano()) {
				continue
			}
			fmt.Printf("%s %s\n", e.Timestamp.Format(time.RFC3339), e.text())
		}
		if !follow {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

// gcpLogFilter matches the collector container's output on the given
// instances. Container-Optimized OS labels container logs by numeric instance
// id and container name.
func gcpLogFilter(instances []managedInstance) string {
	ids := make([]string, 0, len(instances))
	for _, mi := range instances {
		if mi.ID != "" {
			ids = append(ids, fmt.Sprintf("%q", mi.ID))
		}
	}
	return fmt.Sprintf(`resource.type="gce_instance" AND resource.labels.instance_id=(%s) AND jsonPayload."cos.googleapis.com/container_name"=%q`,
		strings.Join(ids, " OR "), gcpCollectorContainerName)
}

// gcpCollectorContainerName is the container name the template's startup
// script assigns.
const gcpCollectorContainerName = "dbg-collector"

type gcpLogEntry struct {
	InsertID    string         `json:"insertId"`
	Timestamp   time.Time      `json:"timestamp"`
	TextPayload string         `json:"textPayload"`
	JSONPayload map[string]any `json:"jsonPayload"`
}

func (e gcpLogEntry) text() string {
	if e.TextPayload != "" {
		return e.TextPayload
	}
	if msg, ok := e.JSONPayload["message"].(string); ok {
		return msg
	}
	b, _ := json.Marshal(e.JSONPayload)
	return string(b)
}

// listLogEntries reads every entry since `since` (inclusive), following the
// page token.
func listLogEntries(ctx context.Context, cfg gcpConfig, project, filter string, since time.Time) ([]gcpLogEntry, error) {
	var out []gcpLogEntry
	body := map[string]any{
		"resourceNames": []string{"projects/" + project},
		"filter":        fmt.Sprintf(`%s AND timestamp>="%s"`, filter, since.Format(time.RFC3339Nano)),
		"orderBy":       "timestamp asc",
		"pageSize":      1000,
	}
	for {
		var page struct {
			gcpPage
			Entries []gcpLogEntry `json:"entries"`
		}
		if err := gcpDo(ctx, cfg, http.MethodPost, loggingBase+"/entries:list", body, &page); err != nil {
			return nil, fmt.Errorf("could not read logs for project %q: %w", project, err)
		}
		out = append(out, page.Entries...)
		if page.NextPageToken == "" {
			return out, nil
		}
		body["pageToken"] = page.NextPageToken
	}
}
