package collector

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// The gcp target: Cloud SQL (Postgres/MySQL) and AlloyDB (Postgres), monitored
// by a collector deployed inside the customer's project.

// GcpTarget describes one database the gcp collector will monitor.
type GcpTarget struct {
	ProviderType string // "cloud_sql" | "alloydb"
	Project      string
	Region       string
	InstanceID   string // cloud_sql instance id, or the alloydb PRIMARY instance id
	ClusterID    string // alloydb only

	Engine string // "postgres" | "mysql"
	// Host is the certificate-attested DNS name for Cloud SQL when the instance
	// has one (verbatim, trailing dot included), else the private IP. For
	// alloydb it is informational: connections ride the connector tunnel.
	Host string
	Port int

	ServerCaMode string // Cloud SQL: GOOGLE_MANAGED_INTERNAL_CA (default) | *_CAS_CA
	IamEnabled   bool

	Network string // VPC self-link the collector instance joins

	// Replicas are the Cloud SQL read replicas of InstanceID (short ids),
	// discovered from the primary. The collector logs in to them too, so the
	// IAM Condition scoping its login names them alongside the primary.
	Replicas []string

	Databases  []string
	User       string   // empty means DefaultDBUser
	AuthMethod string   // "gcp_iam" (default) | "password"
	Commands   []string // query-analysis commands allowed; empty means none
}

// DisplayName is the component name: the cluster for alloydb, else the
// instance.
func (t GcpTarget) DisplayName() string {
	if t.ProviderType == "alloydb" {
		return t.ClusterID
	}
	return t.InstanceID
}

// ValidGcpProviderType reports whether a --provider-type value applies to the
// gcp target ("" means auto-detect).
func ValidGcpProviderType(hint string) bool {
	switch hint {
	case "", "cloud_sql", "alloydb":
		return true
	}
	return false
}

// DiscoverGcpTarget completes `into` from the control plane. `id` may be empty
// (solo-select), a Cloud SQL instance id, or an alloydb "cluster" or
// "cluster/instance". `providerHint` forces cloud_sql vs alloydb.
func DiscoverGcpTarget(id, providerHint string, into GcpTarget) (GcpTarget, error) {
	if into.Project == "" {
		return into, errors.New("no project resolved for discovery; pass --project")
	}
	if !ValidGcpProviderType(providerHint) {
		return into, fmt.Errorf("--provider-type %q is not a Google Cloud provider (expected cloud_sql or alloydb)", providerHint)
	}
	if providerHint == "cloud_sql" && strings.Contains(id, "/") {
		return into, fmt.Errorf("--db-instance-id %q names an AlloyDB cluster/instance; "+
			"a Cloud SQL instance id has no '/' (or pass --provider-type alloydb)", id)
	}
	ctx := context.Background()
	cfg, err := loadGCPConfig(ctx)
	if err != nil {
		return into, gcpCredsErr(err)
	}

	location := ""
	if id == "" {
		cands, err := listGcpCandidates(ctx, cfg, into.Project, providerHint)
		if err != nil {
			return into, err
		}
		choice, err := selectSolo(cands.choices, errors.New(
			"no Cloud SQL or AlloyDB databases found in this project; "+
				"pass --db-instance-id (Cloud SQL instance, or alloydb cluster/instance)"))
		if err != nil {
			return into, err
		}
		id, providerHint, location = choice.ID, choice.ProviderType, cands.locations[choice.ID]
	}

	if providerHint == "alloydb" || strings.Contains(id, "/") {
		return discoverAlloyDB(ctx, cfg, into, id, location)
	}
	return discoverCloudSQL(ctx, cfg, into, id)
}

// gcpCandidates is a listing of the supported databases in a stable order
// (Cloud SQL instances, then AlloyDB clusters), plus each AlloyDB choice's
// location so a solo-selected cluster needs no second lookup.
type gcpCandidates struct {
	choices   []TargetChoice
	locations map[string]string
}

// listGcpCandidates enumerates Cloud SQL Postgres/MySQL primaries and AlloyDB
// primary instances ("cluster/primary"). A provider hint narrows the listing
// to one API.
func listGcpCandidates(ctx context.Context, cfg gcpConfig, project, providerHint string) (gcpCandidates, error) {
	out := gcpCandidates{locations: map[string]string{}}
	// With no hint, one disabled API must not hide the other's candidates:
	// AlloyDB's API is off by default, so a Cloud SQL-only project would
	// otherwise fail auto-detection on the common path (and vice versa). The
	// deferred error still surfaces when NOTHING was found, so a
	// permissions problem never reads as an empty project.
	tolerate := providerHint == ""
	var deferred []error
	if providerHint == "" || providerHint == "cloud_sql" {
		sqlInstances, err := listCloudSQLInstances(ctx, cfg, project)
		if err != nil {
			if !tolerate {
				return out, err
			}
			deferred = append(deferred, err)
		}
		var ids []string
		for _, inst := range sqlInstances {
			if inst.MasterInstanceName != "" || !supportedCloudSQLEngine(inst.DatabaseVersion) {
				continue
			}
			ids = append(ids, inst.Name)
		}
		sort.Strings(ids)
		for _, id := range ids {
			out.choices = append(out.choices, TargetChoice{ID: id, ProviderType: "cloud_sql"})
		}
	}
	if providerHint == "" || providerHint == "alloydb" {
		primaries, err := listAlloyDBPrimaries(ctx, cfg, project)
		if err != nil {
			if !tolerate {
				return out, err
			}
			deferred = append(deferred, err)
		}
		sort.Slice(primaries, func(i, j int) bool { return primaries[i].id() < primaries[j].id() })
		for _, p := range primaries {
			out.choices = append(out.choices, TargetChoice{ID: p.id(), ProviderType: "alloydb"})
			out.locations[p.id()] = p.location
		}
	}
	if len(out.choices) == 0 && len(deferred) > 0 {
		return out, errors.Join(deferred...)
	}
	return out, nil
}

func supportedCloudSQLEngine(databaseVersion string) bool {
	return strings.HasPrefix(databaseVersion, "POSTGRES") ||
		strings.HasPrefix(databaseVersion, "MYSQL")
}

// --- Cloud SQL (sqladmin v1) -----------------------------------------------

const sqlAdminBase = "https://sqladmin.googleapis.com/v1"

type sqlInstanceInfo struct {
	Name               string `json:"name"`
	Region             string `json:"region"`
	DatabaseVersion    string `json:"databaseVersion"`
	MasterInstanceName string `json:"masterInstanceName"`
	IPAddresses        []struct {
		Type      string `json:"type"`
		IPAddress string `json:"ipAddress"`
	} `json:"ipAddresses"`
	DNSNames []struct {
		Name           string `json:"name"`
		ConnectionType string `json:"connectionType"`
	} `json:"dnsNames"`
	Settings struct {
		IPConfiguration struct {
			ServerCaMode   string `json:"serverCaMode"`
			PrivateNetwork string `json:"privateNetwork"`
		} `json:"ipConfiguration"`
		DatabaseFlags []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"databaseFlags"`
	} `json:"settings"`
}

type sqlInstancesPage struct {
	gcpPage
	Items []sqlInstanceInfo `json:"items"`
}

func listCloudSQLInstances(ctx context.Context, cfg gcpConfig, project string) ([]sqlInstanceInfo, error) {
	var out []sqlInstanceInfo
	u := fmt.Sprintf("%s/projects/%s/instances", sqlAdminBase, url.PathEscape(project))
	err := gcpListPages(ctx, cfg, u, func(p sqlInstancesPage) { out = append(out, p.Items...) })
	if err != nil {
		return nil, fmt.Errorf("could not list Cloud SQL instances in project %q "+
			"(is the Cloud SQL Admin API enabled, and does this identity hold cloudsql.viewer?): %w",
			project, err)
	}
	return out, nil
}

func getCloudSQLInstance(ctx context.Context, cfg gcpConfig, project, instance string) (*sqlInstanceInfo, error) {
	u := fmt.Sprintf("%s/projects/%s/instances/%s", sqlAdminBase,
		url.PathEscape(project), url.PathEscape(instance))
	var info sqlInstanceInfo
	if err := gcpDo(ctx, cfg, "GET", u, nil, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

func discoverCloudSQL(ctx context.Context, cfg gcpConfig, into GcpTarget, instance string) (GcpTarget, error) {
	info, err := getCloudSQLInstance(ctx, cfg, into.Project, instance)
	if err != nil {
		return into, fmt.Errorf("no Cloud SQL instance named %q found in project %q — "+
			"check the project (--project) and pass an existing --db-instance-id, then re-run "+
			"(for an AlloyDB cluster, pass --provider-type alloydb): %w",
			instance, into.Project, err)
	}
	if info.MasterInstanceName != "" {
		return into, fmt.Errorf("Cloud SQL instance %q is a read replica of %q — "+
			"pass the primary as --db-instance-id; the collector discovers replicas from it",
			instance, replicaPrimary(info.MasterInstanceName))
	}
	if !supportedCloudSQLEngine(info.DatabaseVersion) {
		return into, fmt.Errorf("Cloud SQL instance %q runs %s, which this collector does not support "+
			"(PostgreSQL and MySQL are supported)", instance, info.DatabaseVersion)
	}
	target := mergeCloudSQLInstance(into, info)
	replicas, err := listCloudSQLReplicas(ctx, cfg, into.Project, info.Name)
	if err != nil {
		return into, err
	}
	target.Replicas = replicas
	return target, nil
}

// listCloudSQLReplicas names the read replicas of primary, in a stable order.
func listCloudSQLReplicas(ctx context.Context, cfg gcpConfig, project, primary string) ([]string, error) {
	all, err := listCloudSQLInstances(ctx, cfg, project)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, inst := range all {
		if inst.MasterInstanceName != "" && replicaPrimary(inst.MasterInstanceName) == primary {
			out = append(out, inst.Name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// replicaPrimary reduces a replica's masterInstanceName — the API reports it
// as "project:instance" — to the instance id.
func replicaPrimary(master string) string {
	if _, after, ok := strings.Cut(master, ":"); ok {
		return after
	}
	return master
}

// mergeCloudSQLInstance projects an instances.get response into the target.
func mergeCloudSQLInstance(into GcpTarget, info *sqlInstanceInfo) GcpTarget {
	into.ProviderType = "cloud_sql"
	into.InstanceID = info.Name
	if into.Region == "" {
		into.Region = info.Region
	}
	into.Engine = "postgres"
	into.Port = 5432
	if strings.HasPrefix(info.DatabaseVersion, "MYSQL") {
		into.Engine = "mysql"
		into.Port = 3306
	}
	// Host precedence: the PSA DNS name (the one that resolves over the VPC
	// peering), any DNS name, the private IP, any IP. DNS names are kept
	// verbatim: the certificate carries the trailing dot.
	if into.Host == "" {
		for _, d := range info.DNSNames {
			if d.Name != "" && d.ConnectionType == "PRIVATE_SERVICES_ACCESS" {
				into.Host = d.Name
				break
			}
		}
	}
	if into.Host == "" {
		for _, d := range info.DNSNames {
			if d.Name != "" {
				into.Host = d.Name
				break
			}
		}
	}
	if into.Host == "" {
		for _, ip := range info.IPAddresses {
			if ip.Type == "PRIVATE" && ip.IPAddress != "" {
				into.Host = ip.IPAddress
				break
			}
		}
	}
	if into.Host == "" {
		for _, ip := range info.IPAddresses {
			if ip.IPAddress != "" {
				into.Host = ip.IPAddress
				break
			}
		}
	}
	into.ServerCaMode = info.Settings.IPConfiguration.ServerCaMode
	if into.ServerCaMode == "" {
		into.ServerCaMode = "GOOGLE_MANAGED_INTERNAL_CA"
	}
	into.Network = info.Settings.IPConfiguration.PrivateNetwork
	for _, f := range info.Settings.DatabaseFlags {
		// Postgres spells the flag with a dot, MySQL with an underscore.
		if (f.Name == "cloudsql.iam_authentication" || f.Name == "cloudsql_iam_authentication") &&
			strings.EqualFold(f.Value, "on") {
			into.IamEnabled = true
		}
	}
	return into
}

// --- AlloyDB (alloydb v1) ---------------------------------------------------

const alloydbBase = "https://alloydb.googleapis.com/v1"

type alloydbClusterInfo struct {
	Name    string `json:"name"` // full resource path
	Network string `json:"network"`
}

func (c alloydbClusterInfo) shortID() string  { return lastPathSegment(c.Name) }
func (c alloydbClusterInfo) location() string { return alloydbPathSegment(c.Name, "locations") }

type alloydbInstanceInfo struct {
	Name         string `json:"name"` // full resource path
	InstanceType string `json:"instanceType"`
	State        string `json:"state"`
	IPAddress    string `json:"ipAddress"`
}

func (i alloydbInstanceInfo) shortID() string  { return lastPathSegment(i.Name) }
func (i alloydbInstanceInfo) cluster() string  { return alloydbPathSegment(i.Name, "clusters") }
func (i alloydbInstanceInfo) location() string { return alloydbPathSegment(i.Name, "locations") }

// alloydbPrimary is one cluster's PRIMARY instance and its location.
type alloydbPrimary struct {
	cluster, instance, location string
}

func (p alloydbPrimary) id() string { return p.cluster + "/" + p.instance }

// alloydbPathSegment returns the value following `key` in a resource path.
func alloydbPathSegment(name, key string) string {
	parts := strings.Split(name, "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == key {
			return parts[i+1]
		}
	}
	return ""
}

type alloydbClustersPage struct {
	gcpPage
	Clusters []alloydbClusterInfo `json:"clusters"`
}

type alloydbInstancesPage struct {
	gcpPage
	Instances []alloydbInstanceInfo `json:"instances"`
}

// listAlloyDBClusters lists every cluster across locations.
func listAlloyDBClusters(ctx context.Context, cfg gcpConfig, project string) ([]alloydbClusterInfo, error) {
	var out []alloydbClusterInfo
	u := fmt.Sprintf("%s/projects/%s/locations/-/clusters", alloydbBase, url.PathEscape(project))
	err := gcpListPages(ctx, cfg, u, func(p alloydbClustersPage) { out = append(out, p.Clusters...) })
	if err != nil {
		return nil, fmt.Errorf("could not list AlloyDB clusters in project %q "+
			"(is the AlloyDB API enabled, and does this identity hold alloydb.viewer?): %w",
			project, err)
	}
	return out, nil
}

// listAlloyDBPrimaries returns every cluster's PRIMARY instance from the
// aggregated instance listing.
func listAlloyDBPrimaries(ctx context.Context, cfg gcpConfig, project string) ([]alloydbPrimary, error) {
	var out []alloydbPrimary
	u := fmt.Sprintf("%s/projects/%s/locations/-/clusters/-/instances", alloydbBase, url.PathEscape(project))
	err := gcpListPages(ctx, cfg, u, func(p alloydbInstancesPage) {
		for _, inst := range p.Instances {
			if inst.InstanceType == "PRIMARY" {
				out = append(out, alloydbPrimary{cluster: inst.cluster(), instance: inst.shortID(), location: inst.location()})
			}
		}
	})
	if err != nil {
		return nil, fmt.Errorf("could not list AlloyDB instances in project %q "+
			"(is the AlloyDB API enabled, and does this identity hold alloydb.viewer?): %w",
			project, err)
	}
	return out, nil
}

func listAlloyDBInstances(ctx context.Context, cfg gcpConfig, project, location, cluster string) ([]alloydbInstanceInfo, error) {
	var out []alloydbInstanceInfo
	u := fmt.Sprintf("%s/projects/%s/locations/%s/clusters/%s/instances", alloydbBase,
		url.PathEscape(project), url.PathEscape(location), url.PathEscape(cluster))
	err := gcpListPages(ctx, cfg, u, func(p alloydbInstancesPage) { out = append(out, p.Instances...) })
	if err != nil {
		return nil, fmt.Errorf("could not list instances of AlloyDB cluster %q: %w", cluster, err)
	}
	return out, nil
}

// discoverAlloyDB fills the target from the cluster's instance listing. `id`
// is "cluster" (primary auto-picked) or "cluster/instance".
func discoverAlloyDB(ctx context.Context, cfg gcpConfig, into GcpTarget, id, location string) (GcpTarget, error) {
	clusterID, instanceID, _ := strings.Cut(id, "/")
	if into.Region == "" {
		into.Region = location
	}
	if into.Region == "" {
		region, err := findAlloyDBClusterRegion(ctx, cfg, into.Project, clusterID)
		if err != nil {
			return into, err
		}
		into.Region = region
	}
	if into.Network == "" {
		u := fmt.Sprintf("%s/projects/%s/locations/%s/clusters/%s", alloydbBase,
			url.PathEscape(into.Project), url.PathEscape(into.Region), url.PathEscape(clusterID))
		var cl alloydbClusterInfo
		if err := gcpDo(ctx, cfg, "GET", u, nil, &cl); err == nil {
			into.Network = cl.Network
		}
	}
	instances, err := listAlloyDBInstances(ctx, cfg, into.Project, into.Region, clusterID)
	if err != nil {
		return into, fmt.Errorf("no AlloyDB cluster named %q found in project %q — "+
			"check the project (--project) and pass an existing --db-instance-id "+
			"(cluster or cluster/instance), then re-run: %w", clusterID, into.Project, err)
	}
	var primary *alloydbInstanceInfo
	for i := range instances {
		inst := &instances[i]
		if instanceID != "" && inst.shortID() == instanceID {
			primary = inst
			break
		}
		if instanceID == "" && inst.InstanceType == "PRIMARY" {
			primary = inst
			break
		}
	}
	if primary == nil {
		if instanceID != "" {
			return into, fmt.Errorf("AlloyDB cluster %q has no instance named %q — "+
				"check --db-instance-id (cluster/instance)", clusterID, instanceID)
		}
		return into, fmt.Errorf("AlloyDB cluster %q has no PRIMARY instance to monitor", clusterID)
	}
	if primary.InstanceType != "PRIMARY" {
		return into, fmt.Errorf("AlloyDB instance %q is a %s — name the cluster's PRIMARY; "+
			"the collector discovers read pools from it", primary.shortID(), primary.InstanceType)
	}
	into.ProviderType = "alloydb"
	into.ClusterID = clusterID
	into.InstanceID = primary.shortID()
	into.Engine = "postgres"
	into.Port = 5432
	if into.Host == "" {
		into.Host = primary.IPAddress
	}
	into.IamEnabled = true
	return into, nil
}

// findAlloyDBClusterRegion locates a cluster by id across locations.
func findAlloyDBClusterRegion(ctx context.Context, cfg gcpConfig, project, clusterID string) (string, error) {
	clusters, err := listAlloyDBClusters(ctx, cfg, project)
	if err != nil {
		return "", err
	}
	for _, c := range clusters {
		if c.shortID() == clusterID {
			return c.location(), nil
		}
	}
	return "", fmt.Errorf("no AlloyDB cluster named %q found in project %q — "+
		"check the project (--project) and the cluster id, then re-run", clusterID, project)
}

// --- config rendering --------------------------------------------------------

// gcpComponent lowers one target into its [[component]] block.
func gcpComponent(t GcpTarget) Component {
	provider := Provider{
		Type:     t.ProviderType,
		Project:  t.Project,
		Region:   t.Region,
		Instance: t.InstanceID,
	}
	if t.ProviderType == "alloydb" {
		provider.Cluster = t.ClusterID
	}
	auth := Auth{Method: orDefault(t.AuthMethod, "gcp_iam"), User: orDefault(t.User, DefaultDBUser)}
	if auth.Method == "password" {
		auth.Password = "${" + CloudDBPasswordEnv + "}"
	}
	if auth.Method == "gcp_iam" && t.ProviderType == "alloydb" {
		auth.Scopes = []string{"https://www.googleapis.com/auth/alloydb.login"}
	}
	// verify-full, except password auth on Cloud SQL's per-instance CA, which
	// attests no hostname AND publishes no CA the collector could verify a
	// chain against without a pin: the reworked collector refuses an unpinned
	// verify-ca on every provider (it would chain to the platform store with
	// no name check), and it no longer fetches the per-instance CA at
	// discovery — `require` (encrypted, unverified) is its documented mode
	// for this hosting.
	sslMode := "verify-full"
	if t.ProviderType == "cloud_sql" && auth.Method == "password" && t.ServerCaMode == "GOOGLE_MANAGED_INTERNAL_CA" {
		sslMode = "require"
	}
	// The MySQL engine accepts only its own ssl_mode spellings.
	if t.Engine == "mysql" {
		switch sslMode {
		case "verify-full":
			sslMode = "verify_identity"
		case "verify-ca":
			sslMode = "verify_ca"
		case "require":
			sslMode = "required"
		}
	}
	// AlloyDB is dialed directly, with no connector proxy, and its instance
	// certificates attest nothing a client can verify without pinning: the
	// collector defaults alloydb to `require` (encrypted; the VPC is the
	// boundary) and refuses verify-* unless ca_cert pins the instance
	// certificate. Render the accepted mode.
	if t.ProviderType == "alloydb" {
		sslMode = "require"
	}
	return Component{
		Name:     t.DisplayName(),
		Engine:   t.Engine,
		Commands: t.Commands,
		Provider: provider,
		Auth:     auth,
		Connect: Connect{
			Host:      t.Host,
			Port:      t.Port,
			Databases: t.Databases,
			SSLMode:   sslMode,
		},
	}
}

// GcpConfigTOML renders the collector config for the gcp deployment. Secrets
// stay ${ENV} references.
func GcpConfigTOML(agentID, tenantID string, targets []GcpTarget, eps Endpoints, commandsEnabled bool) (string, error) {
	cfg := baseConfig(agentID, tenantID, eps, commandsEnabled)
	for _, t := range targets {
		cfg.Component = append(cfg.Component, gcpComponent(t))
	}
	return cfg.Render()
}

// GcpGrantStatements is the SQL a database admin runs so the collector's IAM
// database user (registered with gcloud beforehand) can read the database.
func GcpGrantStatements(user string, databases []string) []string {
	u := quoteIdent(user)
	stmts := []string{"GRANT pg_monitor TO " + u + ";"}
	for _, db := range databases {
		stmts = append(stmts, "GRANT CONNECT ON DATABASE "+quoteIdent(db)+" TO "+u+";")
	}
	return append(stmts, "GRANT pg_read_all_data TO "+u+";")
}
