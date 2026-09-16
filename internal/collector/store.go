package collector

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dbgorilla/dbgorilla-cli/internal/config"
	"github.com/zalando/go-keyring"
)

const (
	stateFile      = "state.json"
	envFile        = "collector.env"
	configFile     = "collector.toml"
	keyringService = "dbgorilla"
)

// Dir returns the per-user collector directory (~/.config/dbgorilla/collector),
// creating it 0700 if needed.
func Dir() (string, error) {
	base, err := config.Dir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "collector")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("cannot create collector directory: %w", err)
	}
	return dir, nil
}

// ConfigPath / EnvPath / statePath are the on-disk artifact locations.
func ConfigPath() (string, error) { return inDir(configFile) }
func EnvPath() (string, error)    { return inDir(envFile) }
func statePath() (string, error)  { return inDir(stateFile) }

func inDir(name string) (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}

// State records the installed collector so status/stop/uninstall work across
// CLI invocations. It holds no secrets. Target selects which runtime the
// management commands drive; older records predate Target and mean docker.
type State struct {
	AgentID    string `json:"agent_id"`
	TenantID   string `json:"tenant_id"`
	Domain     string `json:"domain"`
	Target     string `json:"target,omitempty"` // "docker" (default), "aws", "gcp", or "helm"
	Image      string `json:"image"`
	TargetName string `json:"target_name"`

	// docker target
	ContainerName string `json:"container_name,omitempty"`
	ConfigPath    string `json:"config_path,omitempty"`
	EnvFilePath   string `json:"env_file_path,omitempty"`
	CACertPath    string `json:"ca_cert_path,omitempty"`

	// aws target
	StackName string `json:"stack_name,omitempty"`
	Region    string `json:"region,omitempty"`

	// instaclustr source (any target). ClusterID is what refresh-firewall
	// operates on; FirewallRuleID is the rule the install created for the
	// collector's egress IP (empty when the rule pre-existed, so uninstall
	// never removes an allowlist entry it does not own).
	//
	// UsePrivate records that the install dialled the cluster's private
	// addresses, so refresh-firewall allowlists this machine's address on the
	// cluster's network instead of its public egress address — which would
	// admit the wrong host and then retire the rule the collector is actually
	// connecting through. A private-network cluster is re-derived from
	// discovery, so this field only has to carry the case where
	// --use-private-addresses chose the private side on a public cluster.
	InstaclustrClusterID  string `json:"instaclustr_cluster_id,omitempty"`
	InstaclustrUsername   string `json:"instaclustr_username,omitempty"`
	InstaclustrUsePrivate bool   `json:"instaclustr_use_private,omitempty"`
	FirewallRuleID        string `json:"firewall_rule_id,omitempty"`

	// A VPC-resident collector is allowlisted by security group instead of by
	// address, so there is nothing to re-detect when it redeploys.
	// CollectorSecurityGroupID selects that mode; SecurityGroupRuleID is the
	// rule the install created, empty when the rule pre-existed so uninstall
	// never retires an entry it does not own.
	CollectorSecurityGroupID string `json:"collector_security_group_id,omitempty"`
	SecurityGroupRuleID      string `json:"security_group_rule_id,omitempty"`
	// CollectorSecurityGroupCreated records that the install made the group,
	// so uninstall removes only a group this CLI is responsible for.
	CollectorSecurityGroupCreated bool `json:"collector_security_group_created,omitempty"`

	// gcp target (Region above is shared with aws).
	Project        string `json:"project,omitempty"`
	DeploymentName string `json:"deployment_name,omitempty"`

	// helm target -- the collector runs in-cluster as a Helm release this CLI
	// never started, so there is no container to inspect and no stack to query.
	// The release coordinates are recorded anyway so `status` can say where it
	// lives, and so `uninstall` can print the `helm uninstall` to run.
	ReleaseName      string `json:"release_name,omitempty"`
	ReleaseNamespace string `json:"release_namespace,omitempty"`
	DBNamespace      string `json:"db_namespace,omitempty"`
	DBCluster        string `json:"db_cluster,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

// IsAWS reports whether this collector was deployed to AWS (vs local Docker).
// An empty Target predates the field and means Docker.
func (s *State) IsAWS() bool { return s.Target == "aws" }

// IsGCP reports whether this collector was deployed to Google Cloud.
func (s *State) IsGCP() bool { return s.Target == "gcp" }

// IsHelm reports whether this collector was provisioned for an in-cluster Helm
// install. Recording it is what stops `dbg collector list` showing the collector
// while `dbg collector status` reports none installed -- the two disagreeing is
// read as a broken CLI, which is worse than either answer alone.
func (s *State) IsHelm() bool { return s.Target == "helm" }

// LoadState reads the installed-collector record. A missing file returns
// (nil, nil) — no collector installed.
func LoadState() (*State, error) {
	path, err := statePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read collector state: %w", err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("cannot parse collector state: %w", err)
	}
	return &s, nil
}

// SaveState writes the record atomically (tempfile + rename, 0600).
func SaveState(s *State) error {
	path, err := statePath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot serialize collector state: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("cannot write collector state: %w", err)
	}
	return os.Rename(tmp, path)
}

// RemoveState deletes the state file (best-effort).
func RemoveState() error {
	path, err := statePath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// --- secrets (OS keychain) -----------------------------------------------

func secretKey(agentID string) string { return "collector-secret:" + agentID }
func dbPassKey(agentID string) string { return "collector-dbpass:" + agentID }

// secretsFallbackPath is the 0600 file used when the OS keyring is
// unavailable. Headless Linux, WSL, CI and plain SSH sessions have no Secret
// Service, and those are ordinary hosts for a local collector.
func secretsFallbackPath() (string, error) { return inDir("secrets.json") }

type storedSecrets struct {
	Secret     string `json:"secret"`
	DBPassword string `json:"db_password"`
}

// StoreSecrets persists the collector secret and DB password in the OS
// keychain, keyed by agent id.
//
// A keyring failure falls back to a 0600 file rather than erroring, mirroring
// auth.StoreTokens. Erroring here stranded a collector identity that had
// ALREADY been minted server-side: the install died after provisioning, so the
// user got an orphan they never saw and could not clean up.
func StoreSecrets(agentID, secret, dbPassword string) error {
	secErr := keyring.Set(keyringService, secretKey(agentID), secret)
	if secErr == nil {
		if err := keyring.Set(keyringService, dbPassKey(agentID), dbPassword); err == nil {
			return nil
		}
		// Partial write: drop the half that landed so the two never disagree.
		_ = keyring.Delete(keyringService, secretKey(agentID))
	}

	path, err := secretsFallbackPath()
	if err != nil {
		return fmt.Errorf("cannot store collector secrets (keychain unavailable: %v): %w", secErr, err)
	}
	data, err := json.Marshal(storedSecrets{Secret: secret, DBPassword: dbPassword})
	if err != nil {
		return fmt.Errorf("cannot serialize collector secrets: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("cannot store collector secrets (keychain unavailable: %v): %w", secErr, err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Warning: OS keychain unavailable. Storing collector secrets in %s (0600).\n", path)
	return nil
}

// LoadSecrets reads the collector secret and DB password from the keychain,
// falling back to the 0600 file written when the keychain was unavailable.
func LoadSecrets(agentID string) (secret, dbPassword string, err error) {
	secret, err = keyring.Get(keyringService, secretKey(agentID))
	if err == nil {
		dbPassword, err = keyring.Get(keyringService, dbPassKey(agentID))
		if err == nil {
			return secret, dbPassword, nil
		}
	}
	path, perr := secretsFallbackPath()
	if perr != nil {
		return "", "", fmt.Errorf("cannot read collector secrets: %w", err)
	}
	data, rerr := os.ReadFile(path)
	if rerr != nil {
		return "", "", fmt.Errorf("cannot read collector secrets from keychain or %s: %w", path, err)
	}
	var s storedSecrets
	if jerr := json.Unmarshal(data, &s); jerr != nil {
		return "", "", fmt.Errorf("cannot parse stored collector secrets %s: %w", path, jerr)
	}
	return s.Secret, s.DBPassword, nil
}

// ClearSecrets removes both keychain entries and the fallback file
// (best-effort).
func ClearSecrets(agentID string) {
	_ = keyring.Delete(keyringService, secretKey(agentID))
	_ = keyring.Delete(keyringService, dbPassKey(agentID))
	if path, err := secretsFallbackPath(); err == nil {
		_ = os.Remove(path)
	}
}

// WriteInstaclustrEnvFile is WriteEnvFile plus the collector's read-only
// Instaclustr API key (node discovery). Same file, same 0600 contract.
func WriteInstaclustrEnvFile(path, secret, dbPassword, icReadOnlyKey string) error {
	content := fmt.Sprintf("%s=%s\n%s=%s\n%s=%s\n",
		SecretEnv, secret, DBPasswordEnv, dbPassword, InstaclustrAPIKeyEnv, icReadOnlyKey)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0600); err != nil {
		return fmt.Errorf("cannot write env-file: %w", err)
	}
	return os.Rename(tmp, path)
}

// WriteEnvFile materializes the secrets into a 0600 env-file that `docker run
// --env-file` reads. Called on install and on start; the file is the only
// place plaintext secrets land on disk.
func WriteEnvFile(path, secret, dbPassword string) error {
	content := fmt.Sprintf("%s=%s\n%s=%s\n", SecretEnv, secret, DBPasswordEnv, dbPassword)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0600); err != nil {
		return fmt.Errorf("cannot write env-file: %w", err)
	}
	return os.Rename(tmp, path)
}

// WriteConfig writes the rendered collector.toml atomically. It is 0644 (not
// 0600) because it is bind-mounted into the collector container, which runs as
// a non-root user with a read-only rootfs and must be able to read it. The file
// holds no secrets — only ${ENV} references — so world-readable is safe.
func WriteConfig(path, contents string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(contents), 0644); err != nil {
		return fmt.Errorf("cannot write collector.toml: %w", err)
	}
	if err := os.Chmod(tmp, 0644); err != nil { // WriteFile honors umask on create
		return err
	}
	return os.Rename(tmp, path)
}
