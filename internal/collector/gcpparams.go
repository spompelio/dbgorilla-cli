package collector

import (
	"fmt"
	"strings"
)

// DefaultGcpDeploymentName is the Infrastructure Manager deployment (and, by
// the template's naming contract, the MIG) an install creates by default.
const DefaultGcpDeploymentName = "dbgorilla-collector"

// gceMetadataConfigLimit caps the base64 collector config carried in instance
// metadata (the per-value limit is 256KiB).
const gceMetadataConfigLimit = 245760

// gcpInputKeys is the template's whole input-variable contract;
// TestGcpTemplateContract pins it against variables.tf. No input carries a
// credential: the CLI writes the three secrets to Secret Manager itself
// (EnsureGcpSecrets, by the template's naming contract) and the template only
// grants the collector's service account read access — so the map is
// printable, and nothing secret ever reaches Infrastructure Manager.
var gcpInputKeys = []string{
	"alloydb_roles",
	"cloud_sql_roles",
	"collector_config",
	"collector_image",
	"login_instances",
	"nat_subnet_cidr",
	"network",
	"region",
	"runtime_service_account",
	"stable_egress",
	"subnetwork",
}

// GcpRuntimeServiceAccountFor is the service account the template creates for
// the collector VM. The IAM database user derives from it before it exists.
func GcpRuntimeServiceAccountFor(deploymentName, project string) string {
	return fmt.Sprintf("%s@%s.iam.gserviceaccount.com", deploymentName, project)
}

// GcpDatabaseUserFor is the database-side username for a service account under
// IAM auth: Postgres drops the .gserviceaccount.com suffix, MySQL keeps only
// the part before the @.
func GcpDatabaseUserFor(saEmail, engine string) string {
	if engine == "mysql" {
		local, _, _ := strings.Cut(saEmail, "@")
		return local
	}
	return strings.TrimSuffix(saEmail, ".gserviceaccount.com")
}

// GcpStackInput carries everything GcpDeployInputs needs.
type GcpStackInput struct {
	AgentID   string
	TenantID  string
	Image     string
	Endpoints Endpoints
	Targets   []GcpTarget
	// Network is the VPC the collector instance joins; Subnetwork is empty on
	// an auto-mode VPC.
	Network        string
	Subnetwork     string
	Region         string
	DeploymentName string
	Project        string
	// Credentials never ride the inputs: the CLI writes them to Secret
	// Manager (EnsureGcpSecrets) and the config document references them as
	// $${ENV} placeholders the boot script resolves.
	CommandsEnabled bool
	// Instaclustr source riding the gcp substrate: the pre-rendered
	// components (Targets stays empty — there is no Cloud SQL).
	Components []Component
	// Stable egress (template-owned subnetwork + Cloud NAT + reserved static
	// address): the collector's outbound IP never changes, which
	// IP-allowlist-gated databases require. NatSubnetCidr is the subnetwork's
	// range; Subnetwork is ignored when set, the template picks its own.
	StableEgress  bool
	NatSubnetCidr string
	// AllowProjectWideLogin drops the IAM Condition that scopes the
	// collector's Cloud SQL IAM login to the monitored instances — the
	// --allow-project-wide-login opt-out.
	AllowProjectWideLogin bool
}

// GcpLoginInstances lists the Cloud SQL instances the collector logs in to —
// each cloud_sql target and its read replicas — which is what the template's
// IAM Condition on roles/cloudsql.instanceUser names. AlloyDB targets
// contribute nothing: AlloyDB's login check matches no resource name, so that
// grant cannot be scoped.
func GcpLoginInstances(targets []GcpTarget) []string {
	var out []string
	seen := map[string]bool{}
	for _, t := range targets {
		if t.ProviderType != "cloud_sql" {
			continue
		}
		for _, id := range append([]string{t.InstanceID}, t.Replicas...) {
			if id != "" && !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	return out
}

// GcpDeployInputs renders the template's input variables. The map is
// printable by construction — GcpStackInput carries no credential, so no code
// path can put one here; the secrets travel through EnsureGcpSecrets instead.
func GcpDeployInputs(in GcpStackInput) (inputs map[string]string, err error) {
	var configTOML string
	if len(in.Components) > 0 {
		// Pre-rendered components (the instaclustr source): no Cloud SQL
		// discovery, no per-target render — the caller built the blocks.
		configTOML, err = componentsConfigTOML(in.AgentID, in.TenantID, in.Components, in.Endpoints, in.CommandsEnabled)
	} else {
		configTOML, err = GcpConfigTOML(in.AgentID, in.TenantID, in.Targets, in.Endpoints, in.CommandsEnabled)
	}
	if err != nil {
		return nil, err
	}
	encoded, err := encodeConfigLimited(configTOML, gceMetadataConfigLimit, "a GCE metadata value")
	if err != nil {
		return nil, err
	}
	stableEgress := "false"
	if in.StableEgress {
		stableEgress = "true"
	}
	// Each database service's project-wide roles only when it hosts a
	// target; pre-rendered components (the instaclustr source) monitor
	// something else entirely and get neither set.
	cloudSQLRoles, alloyDBRoles := "false", "false"
	for _, t := range in.Targets {
		switch t.ProviderType {
		case "cloud_sql":
			cloudSQLRoles = "true"
		case "alloydb":
			alloyDBRoles = "true"
		}
	}
	loginInstances := ""
	if !in.AllowProjectWideLogin {
		loginInstances = strings.Join(GcpLoginInstances(in.Targets), ",")
	}
	inputs = map[string]string{
		"alloydb_roles":           alloyDBRoles,
		"cloud_sql_roles":         cloudSQLRoles,
		"collector_config":        encoded,
		"collector_image":         in.Image,
		"login_instances":         loginInstances,
		"nat_subnet_cidr":         in.NatSubnetCidr,
		"network":                 in.Network,
		"region":                  in.Region,
		"runtime_service_account": GcpRuntimeServiceAccountFor(in.DeploymentName, in.Project),
		"stable_egress":           stableEgress,
		"subnetwork":              in.Subnetwork,
	}
	return inputs, nil
}
