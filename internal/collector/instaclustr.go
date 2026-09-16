package collector

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// InstaclustrMonitorUser is the read-only role the install creates for the
// collector. Created via the cluster's default user (which has CREATEROLE and
// pg_monitor), so no support ticket and no superuser are involved.
const InstaclustrMonitorUser = "dbgorilla_monitor"

// InstaclustrTarget is one managed PostgreSQL cluster as the Cluster
// Management API describes it, flattened across data centres.
type InstaclustrTarget struct {
	ClusterID       string
	Name            string
	Status          string
	PostgresVersion string
	// CloudProvider / Region use Instaclustr's own spellings (AWS_VPC,
	// US_EAST_1) — they ride into the collector config verbatim.
	CloudProvider string
	Region        string
	// DefaultUserPassword is the icpostgresql password the API returns on the
	// cluster-detail call. Used transiently to create the monitoring role;
	// never persisted, never rendered into any config.
	DefaultUserPassword string
	// ProviderAccountName names the cloud account the substrate runs in:
	// literally "INSTACLUSTR" for Instaclustr's own accounts, the customer's
	// provider account name when the account is linked. Read from the primary
	// data centre.
	ProviderAccountName string
	// DataCentreID names the cluster's own AWS security group, which is
	// "ic-<DataCentreID>-<suffix>". That group is where Instaclustr's firewall
	// rules actually land, so it is what a static reachability check reads.
	DataCentreID string
	// VpcID is the cluster's own VPC. Reported only for a linked account, and
	// only once provisioning has created it — empty while the cluster is in
	// GENESIS, which is why it corroborates residency rather than deciding it.
	VpcID string
	// NetworkCIDRs are the primary data centre's network blocks, for
	// reachability preflight and peering.
	NetworkCIDRs []string
	// PrivateNetworkCluster is true when the cluster was created without
	// public addresses. This — not residency — is what forces private
	// addressing, because there is no public address to dial.
	PrivateNetworkCluster bool
	Nodes                 []InstaclustrNode
}

// instaclustrOwnAccount is the provider account name the API reports for a
// cluster running in Instaclustr's own cloud accounts.
const instaclustrOwnAccount = "INSTACLUSTR"

// LinkedAccount reports whether the substrate runs in the customer's own
// cloud account (BYOC) rather than Instaclustr's.
//
// providerAccountName is the signal; the VPC id only corroborates it, and
// stands in while a freshly created cluster has not reported an account name
// yet. Residency says nothing about which addresses to dial: a linked-account
// cluster keeps public addresses unless PrivateNetworkCluster says otherwise,
// which is why the two are read as independent axes.
func (t InstaclustrTarget) LinkedAccount() bool {
	if t.ProviderAccountName != "" {
		return !strings.EqualFold(t.ProviderAccountName, instaclustrOwnAccount)
	}
	return t.VpcID != ""
}

// AddressOn returns the address of whichever node carries host, on the
// requested side.
//
// The operator resolves the primary over the side THIS machine can reach, which
// for a public-address cluster is the public one — but a collector running
// inside the cluster's VPC has to seed from that same node's private address,
// or its first connection leaves the VPC and fails to match a security-group
// allowlist. Empty when no node carries host, or carries no address on the
// requested side.
func (t InstaclustrTarget) AddressOn(host string, private bool) string {
	if host == "" {
		return ""
	}
	for _, n := range t.Nodes {
		if n.PublicAddress == host || n.PrivateAddress == host {
			return n.Host(private)
		}
	}
	return ""
}

// InstaclustrNode is one addressable node.
type InstaclustrNode struct {
	ID             string
	PublicAddress  string
	PrivateAddress string
	Rack           string
}

// Host returns the node address for the chosen network side.
func (n InstaclustrNode) Host(private bool) string {
	if private {
		return n.PrivateAddress
	}
	return n.PublicAddress
}

// icNetworkSettings is a data centre's per-cloud settings block. AWS, GCP and
// Azure each spell the cluster's own network the same way —
// customVirtualNetworkId — populated once provisioning creates it and null
// before that.
type icNetworkSettings struct {
	CustomVirtualNetworkID *string `json:"customVirtualNetworkId"`
}

// customVirtualNetworkID returns the first network id any of the per-cloud
// settings blocks reports. At most one block is ever populated, so the order
// of the arguments carries no preference.
func customVirtualNetworkID(blocks ...[]icNetworkSettings) string {
	for _, block := range blocks {
		for _, s := range block {
			if s.CustomVirtualNetworkID != nil && *s.CustomVirtualNetworkID != "" {
				return *s.CustomVirtualNetworkID
			}
		}
	}
	return ""
}

// instaclustrClusterDetail mirrors the fields this CLI reads from
// GET /cluster-management/v2/resources/applications/postgresql/clusters/v2/{id}.
type instaclustrClusterDetail struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Status              string `json:"status"`
	PostgresqlVersion   string `json:"postgresqlVersion"`
	DefaultUserPassword string `json:"defaultUserPassword"`
	// PrivateNetworkCluster is a cluster-wide property, not a per-DC one.
	PrivateNetworkCluster bool `json:"privateNetworkCluster"`
	DataCentres           []struct {
		// ID names the cluster's own AWS security group, which is
		// "ic-<id>-<suffix>" — the enforcement point the firewall rules
		// materialise into, and so what a reachability preflight has to read.
		ID            string `json:"id"`
		CloudProvider string `json:"cloudProvider"`
		Region        string `json:"region"`
		// ProviderAccountName is "INSTACLUSTR" on their own accounts and the
		// customer's provider account name on a linked one.
		ProviderAccountName *string `json:"providerAccountName"`
		// One settings block per cloud, and the API sends at most one of them.
		// All three are read, or the VPC would be silently empty on every
		// cluster that is not on AWS.
		AwsSettings   []icNetworkSettings `json:"awsSettings"`
		GcpSettings   []icNetworkSettings `json:"gcpSettings"`
		AzureSettings []icNetworkSettings `json:"azureSettings"`
		Networks      []struct {
			CIDR string `json:"cidr"`
		} `json:"networks"`
		// The primary flag lives under the replication block rather than on
		// the data centre itself.
		InterDataCentreReplication []struct {
			IsPrimaryDataCentre bool `json:"isPrimaryDataCentre"`
		} `json:"interDataCentreReplication"`
		Nodes []struct {
			ID             string  `json:"id"`
			PublicAddress  *string `json:"publicAddress"`
			PrivateAddress *string `json:"privateAddress"`
			Rack           *string `json:"rack"`
			DeletionTime   *string `json:"deletionTime"`
		} `json:"nodes"`
	} `json:"dataCentres"`
}

// DiscoverInstaclustrCluster fetches the cluster detail and flattens its
// nodes. Deleted and address-less nodes (mid-provision) are skipped.
func DiscoverInstaclustrCluster(ctx context.Context, creds InstaclustrCreds, clusterID string) (InstaclustrTarget, error) {
	var detail instaclustrClusterDetail
	path := "/cluster-management/v2/resources/applications/postgresql/clusters/v2/" + clusterID
	if err := icGetJSON(ctx, creds, path, &detail); err != nil {
		return InstaclustrTarget{}, err
	}
	t := InstaclustrTarget{
		ClusterID:             detail.ID,
		Name:                  detail.Name,
		Status:                detail.Status,
		PostgresVersion:       detail.PostgresqlVersion,
		DefaultUserPassword:   detail.DefaultUserPassword,
		PrivateNetworkCluster: detail.PrivateNetworkCluster,
	}
	// Cloud, region, residency and networking all describe the PRIMARY data
	// centre: on a multi-region cluster the others hold no writer, and the
	// provider crate reads them the same way. A single-DC cluster may flag no
	// DC at all, so the first one stands in.
	if len(detail.DataCentres) > 0 {
		// FIRST flagged data centre wins. A cluster should flag exactly one, but
		// without the break a second flag would silently decide the cluster's
		// cloud, region and network blocks.
		primary := 0
	flagged:
		for i, dc := range detail.DataCentres {
			for _, r := range dc.InterDataCentreReplication {
				if r.IsPrimaryDataCentre {
					primary = i
					break flagged
				}
			}
		}
		dc := detail.DataCentres[primary]
		t.DataCentreID = dc.ID
		t.CloudProvider = dc.CloudProvider
		t.Region = dc.Region
		if dc.ProviderAccountName != nil {
			t.ProviderAccountName = *dc.ProviderAccountName
		}
		// A data centre still being provisioned can report an empty cloud and
		// region; a sibling that has them is better than rendering a collector
		// config with neither.
		for _, other := range detail.DataCentres {
			if t.CloudProvider != "" {
				break
			}
			t.CloudProvider, t.Region = other.CloudProvider, other.Region
		}
		t.VpcID = customVirtualNetworkID(dc.AwsSettings, dc.GcpSettings, dc.AzureSettings)
		for _, n := range dc.Networks {
			if n.CIDR != "" {
				t.NetworkCIDRs = append(t.NetworkCIDRs, n.CIDR)
			}
		}
	}
	// Nodes are flattened across every data centre, primary or not.
	for _, dc := range detail.DataCentres {
		for _, n := range dc.Nodes {
			if n.DeletionTime != nil && *n.DeletionTime != "" {
				continue
			}
			node := InstaclustrNode{ID: n.ID}
			if n.PublicAddress != nil {
				node.PublicAddress = *n.PublicAddress
			}
			if n.PrivateAddress != nil {
				node.PrivateAddress = *n.PrivateAddress
			}
			if n.Rack != nil {
				node.Rack = *n.Rack
			}
			if node.PublicAddress == "" && node.PrivateAddress == "" {
				continue
			}
			t.Nodes = append(t.Nodes, node)
		}
	}
	if len(t.Nodes) == 0 {
		return t, fmt.Errorf("instaclustr cluster %q has no addressable nodes yet (status %s). "+
			"Wait for the cluster to finish provisioning and re-run", clusterID, t.Status)
	}
	return t, nil
}

// EnsureInstaclustrRole makes the collector's read-only role exist WITH the
// given password, connecting as the cluster's default user (CREATEROLE +
// pg_monitor — no superuser, no support ticket). Convergent on re-runs and
// reinstalls: an existing role gets ALTER ROLE ... PASSWORD, because every
// install generates a fresh password and a skipped CREATE would strand the
// collector with a credential Postgres has never seen. Grants: pg_monitor
// for the stats views, and pg_read_all_data so schema capture (pg_dump) can
// SELECT what it dumps — the latter tolerated as missing on pre-PG14
// servers, where the role and the monitor grant still land.
//
// Error messages never include statement text: the CREATE/ALTER statements
// carry the live password, and these errors reach terminals and CI logs.
func EnsureInstaclustrRole(ctx context.Context, dsn, user, password string) (warnings []string, err error) {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("%w to create the monitoring role: %w", errClusterUnreachable, err)
	}
	defer func() { _ = conn.Close(ctx) }()
	// The role name is quoted as an identifier: every caller passes the
	// constant today, but this signature accepts any string.
	role := pgx.Identifier{user}.Sanitize()
	quoted := strings.ReplaceAll(password, "'", "''")
	if _, err := conn.Exec(ctx, fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s'", role, quoted)); err != nil {
		if !isBenignGrantErr(err) {
			return nil, fmt.Errorf("creating role %s failed: %w", user, redactPassword(err, quoted, password))
		}
		if _, aerr := conn.Exec(ctx, fmt.Sprintf("ALTER ROLE %s WITH LOGIN PASSWORD '%s'", role, quoted)); aerr != nil {
			return nil, fmt.Errorf("updating role %s's password failed: %w", user, redactPassword(aerr, quoted, password))
		}
	}
	if _, err := conn.Exec(ctx, fmt.Sprintf("GRANT pg_monitor TO %s", role)); err != nil && !isBenignGrantErr(err) {
		return nil, fmt.Errorf("granting pg_monitor to %s failed: %w", user, err)
	}
	if _, err := conn.Exec(ctx, fmt.Sprintf("GRANT pg_read_all_data TO %s", role)); err != nil && !isBenignGrantErr(err) {
		warning, fatal := classifyReadAllDataGrant(err, user)
		if fatal {
			return warnings, fmt.Errorf("granting pg_read_all_data to %s failed: %w", user, err)
		}
		warnings = append(warnings, warning)
	}
	return warnings, nil
}

// classifyReadAllDataGrant decides whether a refused pg_read_all_data grant
// ends the install or merely narrows the role, and says what was lost.
//
// Two refusals are legitimate, and neither is a reason to abandon a role that
// is otherwise ready:
//
//	42704 undefined_object       the role predates PostgreSQL 14.
//	42501 insufficient_privilege PG 16+ requires ADMIN OPTION on a role to
//	                             grant it, and Instaclustr's default user holds
//	                             no membership in pg_read_all_data at all. No
//	                             install can clear that, so failing would block
//	                             every install rather than report a reduced one.
//
// Anything else is a real failure.
//
// What the warning must NOT claim is that monitoring is degraded: pg_monitor
// already carries the statistics views, so metrics are unaffected, and naming
// the wrong casualty would send an operator looking for a monitoring fault that
// isn't there. Nor may it claim that everything ELSE is unaffected. The grant
// buys SELECT on user tables, and preflight's CheckTopologyGrants reports the
// pg_dump topology scrape failing without exactly that — so the warning names
// the loss rather than ruling it out, and on the docker path the preflight
// below measures how many tables it actually costs.
func classifyReadAllDataGrant(err error, user string) (warning string, fatal bool) {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return "", true
	}
	const consequence = "Metrics are unaffected — pg_monitor already carries the statistics views. What the " +
		"grant buys is SELECT on user tables, so schema and topology capture, and running a query or an " +
		"EXPLAIN against a table, are what the narrowed role gives up until SELECT is granted directly."
	switch pgErr.Code {
	case "42704":
		return fmt.Sprintf("this server predates the pg_read_all_data role (PostgreSQL 14 introduced it), so %s "+
			"can read statistics but not table contents. %s", user, consequence), false
	case "42501":
		return fmt.Sprintf("the cluster's default user cannot grant pg_read_all_data, so %s can read statistics "+
			"but not table contents. %s", user, consequence), false
	default:
		return "", true
	}
}

// redactPassword scrubs the role password (raw and SQL-quoted forms) from an
// error before it can reach a terminal — some server errors echo statement
// fragments.
func redactPassword(err error, forms ...string) error {
	msg := err.Error()
	for _, f := range forms {
		if f != "" {
			msg = strings.ReplaceAll(msg, f, "[redacted]")
		}
	}
	return errors.New(msg)
}

// errClusterUnreachable tags a connection-establishment failure from
// EnsureInstaclustrRole, so RetriableRoleError recognizes it structurally
// rather than by matching the wrapper's prose.
var errClusterUnreachable = errors.New("cannot connect to the cluster")

// RetriableRoleError reports whether a role-ensure failure is worth another
// attempt: only connection-establishment failures are — a freshly created
// firewall rule takes a moment to pass packets, and the symptom is a dial
// timeout or refusal. SQL-level failures are deterministic; retrying them
// just multiplies the wait before the user sees the real error.
func RetriableRoleError(err error) bool {
	return errors.Is(err, errClusterUnreachable) && retriableConnError(err)
}

// retriableConnError recognizes the shapes a blocked-by-firewall dial takes.
// Shared by the role step and the primary probe, which face the same latency
// for the same reason.
func retriableConnError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "timeout") || strings.Contains(msg, "timed out") ||
		strings.Contains(msg, "connection refused") || strings.Contains(msg, "i/o") ||
		strings.Contains(msg, "unreachable") || strings.Contains(msg, "reset")
}

// GenerateInstaclustrPassword returns a random password safe to embed in a
// single-quoted SQL literal and an env-file line (alphanumeric only).
func GenerateInstaclustrPassword() (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	out := make([]byte, 28)
	for i := range out {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		out[i] = alphabet[n.Int64()]
	}
	return string(out), nil
}

// BuildInstaclustrComponent renders the [component] block for an Instaclustr
// cluster. The api_key is an env reference — the literal key never enters
// the config file, matching how the database password is handled.
// passwordEnv names the password variable of the deploy substrate: the docker
// env-file uses COLLECTOR_DB_PASSWORD; the Fargate task definition names
// DBG_DB_PASSWORD (fed from Secrets Manager).
func BuildInstaclustrComponent(t InstaclustrTarget, seedHost string, port int, databases []string, sslMode, caCert, apiUsername string, usePrivate bool, passwordEnv string) Component {
	if sslMode == "" {
		// `require` (encrypt, no verify): every Instaclustr node negotiates
		// TLS, but its certificate chains to a per-cluster CA that is only
		// distributed for encryption-enabled clusters — and this CLI's docker
		// CA mount replaces the container's system trust store, which the
		// collector's own control-plane TLS needs. verify-full support waits
		// on a CA-bundling story that keeps both trust roots.
		sslMode = "require"
	}
	return Component{
		Name:   t.Name,
		Engine: "postgres",
		Provider: Provider{
			Type:                "instaclustr",
			ClusterID:           t.ClusterID,
			CloudProvider:       t.CloudProvider,
			Region:              t.Region,
			APIUsername:         apiUsername,
			APIKey:              "${" + InstaclustrAPIKeyEnv + "}",
			UsePrivateAddresses: usePrivate,
		},
		Auth: Auth{
			Method:   "password",
			User:     InstaclustrMonitorUser,
			Password: "${" + passwordEnv + "}",
		},
		Connect: Connect{
			Host:      seedHost,
			Port:      port,
			Databases: databases,
			SSLMode:   sslMode,
			CACert:    caCert,
		},
	}
}

// BuildInstaclustr assembles the full collector config for one Instaclustr
// cluster. Kept separate from Build (the self-hosted docker path) so the two
// evolve independently.
func BuildInstaclustr(agentID, tenantID string, comp Component, eps Endpoints) Config {
	return Config{
		Dbgorilla: Dbgorilla{
			AgentID:      agentID,
			TenantID:     tenantID,
			Secret:       "${" + SecretEnv + "}",
			OpampBaseURL: eps.OpampBaseURL,
			OtlpBaseURL:  eps.OtlpBaseURL,
			AuthBaseURL:  eps.AuthBaseURL,
		},
		Component: []Component{comp},
		Topology:  Topology{Interval: "60s"},
		Commands:  Commands{Enabled: false},
	}
}

// InstaclustrAdminDSN is the connection string for the transient
// role-creation step: the cluster's default user against one node.
// sslmode=require always works — Instaclustr nodes negotiate TLS even on
// clusters provisioned without client-to-cluster encryption; connect_timeout
// keeps a firewalled node from hanging the install.
func InstaclustrAdminDSN(host string, port int, password string) string {
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword("icpostgresql", password),
		Host:     fmt.Sprintf("%s:%d", host, port),
		Path:     "/postgres",
		RawQuery: "sslmode=require&connect_timeout=8",
	}
	return u.String()
}

// InstaclustrAdminDSNAs is InstaclustrAdminDSN for an arbitrary user — the
// preflight runs as the monitoring role itself, so what it verifies is what
// the collector will actually experience.
func InstaclustrAdminDSNAs(user, password, host string, port int) string {
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(user, password),
		Host:     fmt.Sprintf("%s:%d", host, port),
		Path:     "/postgres",
		RawQuery: "sslmode=require&connect_timeout=8",
	}
	return u.String()
}

// PrimaryHost picks the cluster's primary out of candidate addresses by
// asking each one pg_is_in_recovery().
//
// The cluster API cannot answer this: every PostgreSQL node reports the same
// nodeRoles, and the listing order carries no meaning, so the first node is a
// standby about as often as not. Setup only works against the primary —
// CREATE ROLE and ALTER ROLE both fail on a standby with SQLSTATE 25006 — so
// the address is settled by protocol, exactly as the collector settles node
// roles during discovery.
//
// A lone candidate is returned unprobed: a single-node cluster is its own
// primary, and probing would only add a round trip to the common case.
// Multi-region clusters need no data-centre preference either, because only
// the primary data centre holds a writer; the probe finds it wherever it is.
func PrimaryHost(ctx context.Context, hosts []string, port int, password string) (string, error) {
	switch len(hosts) {
	case 0:
		return "", errors.New("no addressable node to probe for the cluster primary")
	case 1:
		return hosts[0], nil
	}
	attempts := make([]string, 0, len(hosts))
	unreachable := false
	for _, h := range hosts {
		inRecovery, err := hostInRecovery(ctx, h, port, password)
		if err != nil {
			attempts = append(attempts, fmt.Sprintf("%s: %v", h, err))
			unreachable = unreachable || retriableConnError(err)
			continue
		}
		if !inRecovery {
			return h, nil
		}
		attempts = append(attempts, h+": standby")
	}
	return "", &primaryProbeError{
		msg: fmt.Sprintf("no node answered as the cluster primary — %s. "+
			"The cluster API reports the same role for every node, so the primary is "+
			"identified by pg_is_in_recovery(); a cluster mid-failover briefly has none, "+
			"and re-running is safe", strings.Join(attempts, "; ")),
		unreachable: unreachable,
	}
}

// primaryProbeError carries the aggregate "no primary" failure along with
// whether any candidate was unreachable, so a caller can retry propagation
// delay without retrying an answer that is already final.
type primaryProbeError struct {
	msg         string
	unreachable bool
}

func (e *primaryProbeError) Error() string { return e.msg }

// RetriableProbeError reports whether a PrimaryHost failure is worth another
// attempt. Only an unreachable node is: a firewall rule created seconds ago
// may not pass packets yet, and until it does every node looks unreachable
// rather than simply unelected. A cluster that answered on every node and
// elected none has given a complete answer — retrying it dials every node
// again, at connect_timeout each, before showing an error that was already
// final.
func RetriableProbeError(err error) bool {
	var pe *primaryProbeError
	return errors.As(err, &pe) && pe.unreachable
}

// localSourceFor returns the local address the OS would send from to reach
// addr. A UDP "connection" only performs the route lookup — no packet leaves
// the machine — which makes it a cheap way to ask the routing table a
// question Go's standard library otherwise cannot. A package-level var so
// tests can answer for a machine they are not running on.
var localSourceFor = func(addr string) (net.IP, error) {
	c, err := net.Dial("udp", net.JoinHostPort(addr, "53"))
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, errors.New("could not read the local address for the route")
	}
	return ua.IP, nil
}

// PrivatePathToCluster reports what this machine would use to reach the
// cluster's own network, and whether that route is recognisably a private one.
//
// A private-network cluster has no public address, so the install only works
// from inside the network: on the VPN, in a peered VPC, or on a bastion. Two
// signals recognise that without sending a packet — this machine already
// holding an address inside the cluster's CIDR, or traffic to that CIDR
// leaving from a different source address than traffic to the open internet.
//
// Neither signal is conclusive the other way. A more specific route out the
// SAME interface — an on-prem VPN appliance, a LAN gateway onto a peered
// network — reaches the cluster without changing the source address, and Go
// cannot read the routing table portably to tell that apart from having no
// route at all. So a false result means "not recognised", never "unreachable",
// and callers should warn rather than refuse and let the connection itself
// settle it.
//
// The returned address is the source the OS picked for the cluster network
// whenever a lookup succeeded, recognised or not. On a private-network cluster
// that is the address the cluster sees, which makes it the right thing to
// allowlist — the machine's public egress address would be the wrong host.
func PrivatePathToCluster(cidrs []string) (net.IP, string, bool) {
	defaultSrc, defaultErr := localSourceFor("1.1.1.1")
	var routed net.IP
	for _, c := range cidrs {
		_, network, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		// Probe a host inside the block. Setting the low bit lands on the
		// first host for any prefix that has one, and never walks outside the
		// network the way an increment would on a block ending in .255; a
		// host route (/32) is already the address to probe.
		probe := append(net.IP(nil), network.IP...)
		if ones, bits := network.Mask.Size(); ones < bits {
			probe[len(probe)-1] |= 1
		}
		src, err := localSourceFor(probe.String())
		if err != nil {
			continue
		}
		if routed == nil {
			routed = src
		}
		if network.Contains(src) {
			return src, fmt.Sprintf("this machine holds %s inside the cluster network %s", src, c), true
		}
		if defaultErr == nil && !src.Equal(defaultSrc) {
			return src, fmt.Sprintf("traffic to %s leaves from %s rather than the default route's %s", c, src, defaultSrc), true
		}
	}
	return routed, "", false
}

// hostInRecovery answers pg_is_in_recovery() for one node. A standby says
// true; the primary says false. A package-level var so tests can settle roles
// without a live cluster, the same seam as instaclustrClient.
var hostInRecovery = func(ctx context.Context, host string, port int, password string) (bool, error) {
	conn, err := pgx.Connect(ctx, InstaclustrAdminDSN(host, port, password))
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close(ctx) }()
	var inRecovery bool
	if err := conn.QueryRow(ctx, "SELECT pg_is_in_recovery()").Scan(&inRecovery); err != nil {
		return false, err
	}
	return inRecovery, nil
}

// AllowCIDR normalizes a user-supplied allow address into the single-host
// CIDR the firewall API wants: a bare IP gains /32 (or /128), an existing
// CIDR passes through, anything else is refused with what to pass instead.
func AllowCIDR(s string) (string, error) {
	s = strings.TrimSpace(s)
	if addr, err := netip.ParseAddr(s); err == nil {
		if addr.Is6() {
			return s + "/128", nil
		}
		return s + "/32", nil
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		// A /0 allowlists the entire internet, which defeats the firewall the
		// entry lives in — refused rather than warned, since nothing this CLI
		// sets up needs it (the console is there for a deliberate open rule).
		if p.Bits() == 0 {
			return "", fmt.Errorf("refusing to allowlist %s: it opens the cluster's firewall to the whole "+
				"internet. Pass the collector's actual egress IP, or a CIDR that covers only it", p)
		}
		return p.String(), nil
	}
	return "", fmt.Errorf("%q is not an IP address or CIDR — pass e.g. 203.0.113.10 or 203.0.113.0/24", s)
}

// PublicEgressIP asks a well-known reflector for this machine's public IP —
// the address the Instaclustr firewall must allow for a locally-run
// collector. The response is validated as an address so a captive portal's
// HTML never reaches the firewall API. Seam-shaped for tests.
var PublicEgressIP = func(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://checkip.amazonaws.com", nil)
	if err != nil {
		return "", err
	}
	resp, err := instaclustrClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot determine this machine's public IP: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return "", fmt.Errorf("cannot determine this machine's public IP: %w", err)
	}
	ip := strings.TrimSpace(string(body))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("cannot determine this machine's public IP (HTTP %d). "+
			"Pass --allow-ip explicitly if this machine has no direct internet path", resp.StatusCode)
	}
	if _, err := netip.ParseAddr(ip); err != nil {
		return "", fmt.Errorf("the public-IP check returned something that is not an address "+
			"(a captive portal?). Pass --allow-ip explicitly: %w", err)
	}
	return ip, nil
}
