package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/dbgorilla/dbgorilla-cli/internal/api"
	"github.com/dbgorilla/dbgorilla-cli/internal/collector"
	"github.com/dbgorilla/dbgorilla-cli/internal/style"
	"github.com/spf13/cobra"
)

// The NetApp Instaclustr source: `dbg collector install --provider instaclustr
// --cluster-id <id>` discovers the managed PostgreSQL cluster through the
// Instaclustr Cluster Management API, creates a read-only monitoring role,
// allowlists the collector's egress IP on the cluster firewall, and runs the
// collector — locally in Docker today. A *source* is deliberately not a
// *target*: where the collector runs (--target) stays independent of where
// the database lives, which is why none of the lifecycle commands branch on
// it.
//
// Two API keys with two fates: the provisioning key does the setup from this
// machine (discovery, firewall writes, reading the default user's password to
// create the role) and is never persisted; the read-only key is the only one
// that ships with the collector, for node discovery.

// Env fallbacks, checked when the flags are absent (prompted for last).
const (
	instaclustrUserEnv         = "INSTACLUSTR_USERNAME"
	instaclustrProvisioningEnv = "INSTACLUSTR_PROVISIONING_API_KEY"
	instaclustrReadOnlyEnv     = "INSTACLUSTR_READONLY_API_KEY"
)

// Test seams, one var per side effect (the aws seams' pattern).
var (
	discoverInstaclustr   = collector.DiscoverInstaclustrCluster
	ensureFirewallRule    = collector.EnsureFirewallRule
	deleteFirewallRule    = collector.DeleteInstaclustrFirewallRule
	createInstaclustrRole = collector.EnsureInstaclustrRole
	publicEgressIP        = func(ctx context.Context) (string, error) { return collector.PublicEgressIP(ctx) }
	stackOutput           = collector.StackOutput
	gcpDeploymentOutput   = collector.GcpDeploymentOutput
)

func init() {
	installCmd.Flags().String("provider", "", "Database source: 'instaclustr' for a NetApp Instaclustr managed PostgreSQL cluster (default: the database named by --db-host)")
	installCmd.Flags().String("cluster-id", "", "Instaclustr cluster id (from the console URL or Cluster Details)")
	installCmd.Flags().String("instaclustr-user", "", "Instaclustr console username (or "+instaclustrUserEnv+")")
	installCmd.Flags().String("instaclustr-api-key", "", "Instaclustr provisioning API key, used for setup on this machine only (or "+instaclustrProvisioningEnv+")")
	installCmd.Flags().String("instaclustr-readonly-key", "", "Instaclustr READ-ONLY provisioning API key the collector keeps for discovery (or "+instaclustrReadOnlyEnv+")")
	installCmd.Flags().Bool("use-private-addresses", false, "Dial the cluster's private node addresses (VPC-peered collectors)")
	installCmd.Flags().String("allow-ip", "", "Public IP the firewall should allow for the collector (default: this machine's, auto-detected)")
	installCmd.Flags().Bool("stable-egress", true, "With --provider instaclustr on a cloud target: route the collector's egress through a NAT with a reserved static IP so the firewall rule stays valid (aws: NAT gateway + Elastic IP, ~USD 35-40/month plus data processing; gcp: Cloud NAT + static address, ~USD 3-5/month plus data processing)")
	installCmd.Flags().String("vpc-id", "", "VPC for the stable-egress private subnet (required with --stable-egress on aws)")
	installCmd.Flags().String("nat-subnet-cidr", "", "Unused CIDR in the VPC for the stable-egress subnet, e.g. 10.0.200.0/28 (aws and gcp)")
	installCmd.Flags().String("region", "", "GCP: region for the collector instance (required with --provider instaclustr --target gcp; aws reads AWS_REGION)")

	refreshFirewallCmd.Flags().String("instaclustr-user", "", "Instaclustr console username (or "+instaclustrUserEnv+")")
	refreshFirewallCmd.Flags().String("instaclustr-api-key", "", "Instaclustr provisioning API key (or "+instaclustrProvisioningEnv+")")
	refreshFirewallCmd.Flags().String("allow-ip", "", "Public IP to allowlist (default: this machine's, auto-detected)")
	collectorCmd.AddCommand(refreshFirewallCmd)
}

// instaclustrSource reports whether this install targets an Instaclustr
// cluster. runInstall consults it before its --target dispatch.
func instaclustrSource(cmd *cobra.Command) bool {
	p, _ := cmd.Flags().GetString("provider")
	return strings.EqualFold(p, "instaclustr")
}

// runInstallInstaclustr is the install flow for the instaclustr source,
// dispatching on the deploy substrate: docker (below), aws
// (runInstallInstaclustrAWS), or gcp (runInstallInstaclustrGCP).
func runInstallInstaclustr(cmd *cobra.Command) error {
	// No substrate can carry a cluster CA yet: the docker CA mount replaces
	// the container's system trust store (which the collector's own
	// control-plane TLS relies on), and neither cloud template has a CA-mount
	// mechanism. verify-full waits on a bundling story for all three roots.
	if ca, _ := cmd.Flags().GetString("ca-cert"); ca != "" {
		return errors.New("--ca-cert is not supported with --provider instaclustr yet: neither the " +
			"docker CA mount (it replaces the system trust store the collector's own TLS needs) nor " +
			"the cloud templates can carry a cluster CA. The install uses ssl_mode=require " +
			"(encrypted, unverified) for now")
	}
	switch target, _ := cmd.Flags().GetString("target"); target {
	case "", "docker", "local":
	case "aws", "fargate":
		return runInstallInstaclustrAWS(cmd)
	case "gcp":
		return runInstallInstaclustrGCP(cmd)
	default:
		return fmt.Errorf("unknown --target %q for --provider instaclustr (expected 'docker', 'aws' or 'gcp')", target)
	}
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	apiURL, err := requireAPIURL(cmd)
	if err != nil {
		return err
	}
	if _, err := requireLogin(); err != nil {
		return err
	}
	if st, _ := collector.LoadState(); st != nil {
		return fmt.Errorf("a collector is already installed (agent %s). Run `dbg collector uninstall` first, or `dbg collector status`",
			st.AgentID)
	}
	if !dryRun {
		if err := dockerAvailable(); err != nil {
			return err
		}
	}

	in, err := resolveInstaclustrInstallInputs(cmd, apiURL, dryRun)
	if err != nil {
		return err
	}
	ctx := cmd.Context()

	allowCIDR := ""
	if raw, _ := cmd.Flags().GetString("allow-ip"); raw != "" {
		if allowCIDR, err = collector.AllowCIDR(raw); err != nil {
			return err
		}
	} else {
		// The docker collector runs on this machine, so the rule has to name
		// the address the cluster sees it arrive from. On a private path that
		// is this machine's address on the cluster's network; its public
		// egress address would admit the wrong host and still not connect.
		ip := ""
		if in.privateSrc != nil {
			ip = in.privateSrc.String()
		} else if ip, err = publicEgressIP(ctx); err != nil {
			return err
		}
		if allowCIDR, err = collector.AllowCIDR(ip); err != nil {
			return err
		}
	}

	if dryRun {
		return dryRunInstaclustr(cmd, in.ict, in.seedHost, in.databases, in.sslMode, in.setupCreds.Username, in.usePrivate, allowCIDR)
	}

	// Firewall: the collector runs on THIS machine for the docker target, so
	// one rule covers both the setup connection and the collector. Every
	// failure below that follows a rule WE created rolls the rule back —
	// otherwise a later re-run finds it "pre-existing", never records
	// ownership, and refresh-firewall accumulates stale rules forever.
	rule, created, err := ensureFirewallRule(ctx, in.setupCreds, in.clusterID, allowCIDR)
	if err != nil {
		return err
	}
	rollbackRule := func() {
		if created {
			if derr := deleteFirewallRule(ctx, in.setupCreds, rule.ID); derr != nil {
				fmt.Println(style.Warn(fmt.Sprintf("⚠  could not remove the firewall rule created for %s: %v (remove it from the console)", allowCIDR, derr)))
			}
		}
	}
	if created {
		fmt.Println(style.Success(fmt.Sprintf("✓ Firewall: allowlisted %s on the cluster", allowCIDR)))
	} else {
		fmt.Println(style.Success(fmt.Sprintf("✓ Firewall: %s already allowlisted", allowCIDR)))
	}

	// Ensure the read-only monitoring role via the cluster's default user —
	// ALTERing the password when it already exists, because this run's fresh
	// password is what ships to the collector. The rule may take a moment to
	// pass packets, so connection failures (only) get retries.
	monitorPassword, err := collector.GenerateInstaclustrPassword()
	if err != nil {
		rollbackRule()
		return err
	}
	// Only the primary accepts the role writes below, and the cluster API
	// does not say which node that is.
	if err := resolveSeedPrimary(ctx, in); err != nil {
		rollbackRule()
		return fmt.Errorf("%w\n\nA just-created firewall rule can take ~a minute to apply; re-running is safe", err)
	}
	dsn := collector.InstaclustrAdminDSN(in.seedHost, 5432, in.ict.DefaultUserPassword)
	if err := ensureRoleWithRetry(ctx, dsn, collector.InstaclustrMonitorUser, monitorPassword); err != nil {
		rollbackRule()
		return fmt.Errorf("%w\n\nA just-created firewall rule can take ~a minute to apply; re-running is safe", err)
	}
	fmt.Println(style.Success(fmt.Sprintf("✓ Monitoring role %q ready (pg_monitor + pg_read_all_data)", collector.InstaclustrMonitorUser)))

	// Deep DB preflight with the monitoring role itself — the same gate the
	// local path runs, so a cluster missing pg_stat_statements is a warning
	// before anything is provisioned, not a silent gap after.
	monitorDSN := collector.InstaclustrAdminDSNAs(collector.InstaclustrMonitorUser, monitorPassword, in.seedHost, 5432)
	report := runPreflight(ctx, monitorDSN)
	printPreflight(report)
	if report.Failed() {
		if force, _ := cmd.Flags().GetBool("force"); !force {
			rollbackRule()
			return errors.New("database preflight failed; fix the items above, or rerun with --force")
		}
		fmt.Println(style.Warn("Continuing despite preflight failures (--force)."))
	}

	caCert := "" // refused above; kept as a named value for the Runner below

	fmt.Println(style.Info("Provisioning collector identity..."))
	creds, err := in.client.ProvisionCollector()
	if err != nil {
		rollbackRule()
		return err
	}
	fmt.Println(style.Success(fmt.Sprintf("✓ Collector provisioned (agent %s, tenant %s)", creds.AgentID, creds.TenantID)))

	comp := collector.BuildInstaclustrComponent(in.ict, in.seedHost, 5432, in.databases, in.sslMode, caCert, in.setupCreds.Username, in.usePrivate, collector.DBPasswordEnv)
	cfg := collector.BuildInstaclustr(creds.AgentID, creds.TenantID, comp, endpointsFor(creds, cmd))
	rendered, err := cfg.Render()
	if err != nil {
		rollbackRule()
		return err
	}
	state := &collector.State{
		TargetName:           in.ict.Name,
		InstaclustrClusterID: in.clusterID,
		InstaclustrUsername:  in.setupCreds.Username,
	}
	if created {
		state.FirewallRuleID = rule.ID
	}
	return finishDockerInstall(cmd, in.client, creds, rendered, monitorPassword, caCert,
		func(envPath string) error {
			return collector.WriteInstaclustrEnvFile(envPath, creds.Secret, monitorPassword, in.readOnlyKey)
		},
		state, rollbackRule,
		"  dbg collector status              # check connection\n"+
			"  dbg collector logs -f             # watch it work\n"+
			"  dbg collector refresh-firewall    # re-allowlist after an IP change")
}

// instaclustrInstall is the front matter every instaclustr install resolves
// identically, whatever substrate runs the collector.
type instaclustrInstall struct {
	clusterID  string
	setupCreds collector.InstaclustrCreds
	// readOnlyKey stays empty on a dry run — nothing renders or ships it.
	readOnlyKey string
	client      *api.Client
	ict         collector.InstaclustrTarget
	seedHost    string
	usePrivate  bool
	sslMode     string
	databases   []string
	// privateSrc is the address the cluster sees this machine arrive from
	// when setup runs over a private path (VPN, peering, bastion). Empty on
	// the public path, where the operator's public egress address is used
	// instead.
	privateSrc net.IP
}

// resolveInstaclustrInstallInputs gathers everything the substrates share:
// the cluster id, both API keys (by their two fates), the backend capability
// gate, and cluster discovery down to the seed host.
func resolveInstaclustrInstallInputs(cmd *cobra.Command, apiURL string, dryRun bool) (*instaclustrInstall, error) {
	clusterID, _ := cmd.Flags().GetString("cluster-id")
	if clusterID == "" {
		if !interactiveTerminal() {
			return nil, errors.New("--cluster-id is required with --provider instaclustr. " +
				"Find it in the Instaclustr console URL or Cluster Details")
		}
		clusterID = strings.TrimSpace(prompt("Instaclustr cluster id", ""))
		if clusterID == "" {
			return nil, errors.New("aborted: no cluster id given")
		}
	}
	setupCreds, err := resolveInstaclustrCreds(cmd, "", "instaclustr-api-key", instaclustrProvisioningEnv,
		"Instaclustr provisioning API key (setup only, never stored)")
	if err != nil {
		return nil, err
	}
	readOnlyKey := ""
	if !dryRun {
		if readOnlyKey, err = resolveInstaclustrKey(cmd, "instaclustr-readonly-key", instaclustrReadOnlyEnv,
			"Instaclustr READ-ONLY API key (the collector keeps this one)"); err != nil {
			return nil, err
		}
	}

	client, err := requireCollectorSupport(cmd, apiURL)
	if err != nil {
		return nil, err
	}

	// Discover the cluster through the Cluster Management API (read-only, so
	// the dry-run path shares it).
	ict, err := discoverInstaclustr(cmd.Context(), setupCreds, clusterID)
	if err != nil {
		return nil, err
	}
	usePrivate, _ := cmd.Flags().GetBool("use-private-addresses")
	// A private-network cluster has no public address to dial, so the address
	// side is a property of the cluster rather than a preference. Residency
	// never decides it: a linked (BYOC) cluster with public addresses is
	// dialled publicly from outside its VPC, exactly like any other.
	if ict.PrivateNetworkCluster {
		if cmd.Flags().Changed("use-private-addresses") && !usePrivate {
			return nil, errors.New("--use-private-addresses=false cannot work on this cluster: it was " +
				"created as a private-network cluster, so its nodes have no public addresses. Run the " +
				"collector somewhere with a route to the cluster's network instead")
		}
		usePrivate = true
	}
	seedHost := ""
	for _, n := range ict.Nodes {
		if h := n.Host(usePrivate); h != "" {
			seedHost = h
			break
		}
	}
	if seedHost == "" {
		return nil, errors.New("no node has an address on the selected network side. " +
			"A private-network cluster needs --use-private-addresses; a public one must not set it")
	}
	fmt.Println(style.Success(fmt.Sprintf("✓ Cluster %q: %d node(s), PostgreSQL %s, %s %s",
		ict.Name, len(ict.Nodes), ict.PostgresVersion, ict.CloudProvider, ict.Region)))
	fmt.Println(style.Success("✓ " + describeInstaclustrShape(ict, usePrivate)))

	// Setup connects from THIS machine to create the monitoring role, and on
	// the private path that only works from inside the cluster's network. The
	// route is checked up front so the operator is told what to fix before
	// anything is mutated, rather than reading a bare timeout afterwards.
	//
	// An unrecognised route is not a refusal. A more specific route out the
	// same interface reaches the cluster without changing the source address,
	// and nothing portable tells that apart from having no route at all, so
	// refusing here would block working setups. The connection is the arbiter;
	// the temporary firewall rule is rolled back either way.
	var privateSrc net.IP
	if usePrivate {
		src, how, ok := collector.PrivatePathToCluster(ict.NetworkCIDRs)
		privateSrc = src
		where := "the cluster's network"
		if len(ict.NetworkCIDRs) > 0 {
			where = strings.Join(ict.NetworkCIDRs, ", ")
		}
		if ok {
			fmt.Println(style.Success(fmt.Sprintf("✓ Private path to the cluster: %s", how)))
		} else {
			fmt.Println(style.Warn(fmt.Sprintf("⚠  No route to %s was recognised from this machine, and this "+
				"cluster has no public addresses. Setup connects to %s:5432 to create the %s role, so it has to run "+
				"on that network — on the VPN, from a peered VPC, or a bastion inside the cluster's VPC. Continuing, "+
				"because a route out the same interface looks identical from here; the connection will settle it.",
				where, seedHost, collector.InstaclustrMonitorUser)))
		}
	}

	sslMode := ""
	if cmd.Flags().Changed("ssl-mode") {
		sslMode, _ = cmd.Flags().GetString("ssl-mode")
	}
	dbNames, _ := cmd.Flags().GetString("db-name")
	return &instaclustrInstall{
		clusterID:   clusterID,
		setupCreds:  setupCreds,
		readOnlyKey: readOnlyKey,
		client:      client,
		ict:         ict,
		seedHost:    seedHost,
		usePrivate:  usePrivate,
		sslMode:     sslMode,
		databases:   splitCSV(dbNames),
		privateSrc:  privateSrc,
	}, nil
}

// setupMonitoringRole creates the monitoring role for a cloud install, via a
// temporary allowlist entry for THIS machine (the operator's IP is not the
// collector's). It hands back the rule, whether this run created it, and its
// remover — which every later exit path must call, unless the temporary rule
// turns out to be the collector's own.
func setupMonitoringRole(ctx context.Context, in *instaclustrInstall, monitorPassword string) (opRule collector.FirewallRule, opCreated bool, removeOperatorRule func(), err error) {
	// On a private path the cluster sees this machine arrive on that network,
	// so allowlisting its public egress address would admit the wrong host
	// and still leave setup unable to connect.
	operatorIP := ""
	if in.privateSrc != nil {
		operatorIP = in.privateSrc.String()
	} else if operatorIP, err = publicEgressIP(ctx); err != nil {
		return collector.FirewallRule{}, false, nil, err
	}
	operatorCIDR, err := collector.AllowCIDR(operatorIP)
	if err != nil {
		return collector.FirewallRule{}, false, nil, err
	}
	opRule, opCreated, err = ensureFirewallRule(ctx, in.setupCreds, in.clusterID, operatorCIDR)
	if err != nil {
		return collector.FirewallRule{}, false, nil, err
	}
	removeOperatorRule = func() {
		if opCreated {
			if derr := deleteFirewallRule(ctx, in.setupCreds, opRule.ID); derr != nil {
				fmt.Println(style.Warn(fmt.Sprintf("⚠  could not remove the temporary setup rule %s: %v (remove it from the console)", operatorCIDR, derr)))
			}
		}
	}
	// Only the primary accepts the role writes below, and the cluster API
	// does not say which node that is.
	if err := resolveSeedPrimary(ctx, in); err != nil {
		removeOperatorRule()
		return collector.FirewallRule{}, false, nil,
			fmt.Errorf("%w\n\nA just-created firewall rule can take ~a minute to apply; re-running is safe", err)
	}
	dsn := collector.InstaclustrAdminDSN(in.seedHost, 5432, in.ict.DefaultUserPassword)
	if err := ensureRoleWithRetry(ctx, dsn, collector.InstaclustrMonitorUser, monitorPassword); err != nil {
		removeOperatorRule()
		return collector.FirewallRule{}, false, nil,
			fmt.Errorf("%w\n\nA just-created firewall rule can take ~a minute to apply; re-running is safe", err)
	}
	fmt.Println(style.Success(fmt.Sprintf("✓ Monitoring role %q ready (pg_monitor + pg_read_all_data)", collector.InstaclustrMonitorUser)))
	return opRule, opCreated, removeOperatorRule, nil
}

// allowlistCollectorEgress allowlists the collector's actual egress after a
// cloud deploy — the stable-egress address the deployment reserved (read via
// deployedEgressIP, whose error names the substrate) or the operator-supplied
// one — retires the operator's temporary rule unless it IS the collector's,
// and records rule ownership so refresh-firewall can retire it later.
func allowlistCollectorEgress(ctx context.Context, in *instaclustrInstall, stableEgress bool,
	deployedEgressIP func() (string, error), allowRaw string,
	opRule collector.FirewallRule, opCreated bool, removeOperatorRule func()) error {

	source := allowRaw
	if stableEgress {
		var err error
		if source, err = deployedEgressIP(); err != nil {
			removeOperatorRule()
			return err
		}
	}
	collectorCIDR, err := collector.AllowCIDR(source)
	if err != nil {
		removeOperatorRule()
		return err
	}
	rule, created, err := ensureFirewallRule(ctx, in.setupCreds, in.clusterID, collectorCIDR)
	if err != nil {
		removeOperatorRule()
		return fmt.Errorf("the collector deployed but its firewall entry failed: %w\n\n"+
			"Add %s to the cluster's PostgreSQL allowlist, or re-run `dbg collector refresh-firewall`", err, collectorCIDR)
	}
	fmt.Println(style.Success(fmt.Sprintf("✓ Firewall: allowlisted %s for the collector", collectorCIDR)))
	if opRule.ID != rule.ID {
		removeOperatorRule()
	} else if opCreated {
		// The operator's machine and the collector share an egress address, so
		// the temporary rule IS the collector's rule — this run created it and
		// must own it, or refresh-firewall could never retire it.
		created = true
	}

	if created {
		if st, lerr := collector.LoadState(); lerr == nil && st != nil {
			st.FirewallRuleID = rule.ID
			if serr := collector.SaveState(st); serr != nil {
				fmt.Println(style.Warn(fmt.Sprintf("⚠  could not record the firewall rule id: %v", serr)))
			}
		}
	}
	return nil
}

// dryRunInstaclustr previews the install with zero side effects: the only
// remote call already made is the read-only cluster GET. It prints what the
// real run would do — the firewall rule, the role SQL (with a placeholder
// password), the rendered config, and the container command.
func dryRunInstaclustr(cmd *cobra.Command, ict collector.InstaclustrTarget, seedHost string, databases []string, sslMode, apiUsername string, usePrivate bool, allowCIDR string) error {
	fmt.Println(style.Info("Dry run: nothing will be minted, written, allowlisted, or started."))
	fmt.Println()
	fmt.Printf("Would allowlist on the cluster firewall:  %s (POSTGRESQL)\n", allowCIDR)
	fmt.Printf("Would ensure role via the default user:   %s\n", collector.InstaclustrMonitorUser)
	fmt.Println("  CREATE ROLE " + collector.InstaclustrMonitorUser + " LOGIN PASSWORD '<generated>'")
	fmt.Println("  GRANT pg_monitor TO " + collector.InstaclustrMonitorUser)
	fmt.Println("  GRANT pg_read_all_data TO " + collector.InstaclustrMonitorUser)
	fmt.Println()
	comp := collector.BuildInstaclustrComponent(ict, seedHost, 5432, databases, sslMode, "", apiUsername, usePrivate, collector.DBPasswordEnv)
	// Empty credentials: nothing is minted on a dry run, so the endpoints are
	// whatever the --*-url flags say (or the collector's production defaults).
	cfg := collector.BuildInstaclustr("<agent-id>", "<tenant-id>", comp, endpointsFor(&api.CollectorCredentials{}, cmd))
	rendered, err := cfg.Render()
	if err != nil {
		return err
	}
	fmt.Println("Would write collector.toml:")
	fmt.Println(rendered)
	image, imageSource := resolveImage(cmd, nil)
	runner := collector.Runner{
		Name:  collector.DefaultContainerName,
		Image: image,
	}
	fmt.Printf("Would run (%s): %s\n", imageSource, runner.RunCommandString())
	return nil
}

// ensureRoleWithRetry absorbs firewall-propagation latency: a rule created
// seconds ago may not pass packets yet, and the symptom is a dial timeout or
// refusal. Only connection failures retry — SQL failures are deterministic
// and retrying them just delays the real error.
func ensureRoleWithRetry(ctx context.Context, dsn, user, password string) error {
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(8 * time.Second):
			}
		}
		if err = createInstaclustrRole(ctx, dsn, user, password); err == nil {
			return nil
		}
		if !collector.RetriableRoleError(err) {
			return err
		}
	}
	return err
}

// describeInstaclustrShape says what discovery concluded about the cluster
// and which field drove it, so the address side is visible up front rather
// than inferred from a connection failure later. Residency is reported for
// the operator's benefit; only the network shape and the deploy placement
// decide which addresses get dialled.
func describeInstaclustrShape(ict collector.InstaclustrTarget, usePrivate bool) string {
	residency := "Instaclustr's account"
	if ict.LinkedAccount() {
		residency = "your own cloud account"
		if ict.ProviderAccountName != "" {
			residency = fmt.Sprintf("your own cloud account (%s)", ict.ProviderAccountName)
		}
	}
	network := "public addresses"
	if ict.PrivateNetworkCluster {
		network = "a private network, with no public addresses"
	}
	side := "public"
	if usePrivate {
		side = "private"
	}
	out := fmt.Sprintf("Runs in %s on %s — dialling %s addresses", residency, network, side)
	if ict.VpcID != "" {
		out += fmt.Sprintf("; VPC %s", ict.VpcID)
		if len(ict.NetworkCIDRs) > 0 {
			out += " " + strings.Join(ict.NetworkCIDRs, ", ")
		}
	}
	return out
}

// resolveSeedPrimary repoints in.seedHost at the node that is actually the
// cluster's primary, replacing the arbitrary first-listed node chosen while
// gathering inputs. It has to run after the operator's firewall rule exists,
// because it connects to the cluster to ask.
//
// Retries match ensureRoleWithRetry: a freshly created firewall rule takes a
// moment to pass packets, and until it does every node looks unreachable
// rather than simply unelected.
func resolveSeedPrimary(ctx context.Context, in *instaclustrInstall) error {
	hosts := make([]string, 0, len(in.ict.Nodes))
	for _, n := range in.ict.Nodes {
		if h := n.Host(in.usePrivate); h != "" {
			hosts = append(hosts, h)
		}
	}
	var (
		primary string
		err     error
	)
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(8 * time.Second):
			}
		}
		if primary, err = collector.PrimaryHost(ctx, hosts, 5432, in.ict.DefaultUserPassword); err == nil {
			break
		}
	}
	if err != nil {
		return err
	}
	if primary != in.seedHost {
		fmt.Println(style.Info(fmt.Sprintf("Primary is %s, not %s — the cluster API lists nodes in no meaningful order",
			primary, in.seedHost)))
	}
	in.seedHost = primary
	return nil
}

// resolveInstaclustrCreds gathers the username + one API key: flag, env,
// caller-supplied default (state), then prompt (refused non-interactively,
// so CI fails with an instruction rather than hanging).
func resolveInstaclustrCreds(cmd *cobra.Command, defaultUser, keyFlag, keyEnv, keyLabel string) (collector.InstaclustrCreds, error) {
	user, _ := cmd.Flags().GetString("instaclustr-user")
	if user == "" {
		user = os.Getenv(instaclustrUserEnv)
	}
	if user == "" {
		user = defaultUser
	}
	if user == "" {
		if !interactiveTerminal() {
			return collector.InstaclustrCreds{}, fmt.Errorf("Instaclustr username required: pass --instaclustr-user or set %s", instaclustrUserEnv)
		}
		user = strings.TrimSpace(prompt("Instaclustr console username", ""))
		if user == "" {
			return collector.InstaclustrCreds{}, errors.New("aborted: no Instaclustr username given")
		}
	}
	key, err := resolveInstaclustrKey(cmd, keyFlag, keyEnv, keyLabel)
	if err != nil {
		return collector.InstaclustrCreds{}, err
	}
	return collector.InstaclustrCreds{Username: user, APIKey: key}, nil
}

func resolveInstaclustrKey(cmd *cobra.Command, flag, env, label string) (string, error) {
	key, _ := cmd.Flags().GetString(flag)
	if key == "" {
		key = os.Getenv(env)
	}
	if key == "" {
		if !interactiveTerminal() {
			return "", fmt.Errorf("%s required: pass --%s or set %s", label, flag, env)
		}
		key = strings.TrimSpace(promptPasswordOptional(label))
	}
	if key == "" {
		return "", fmt.Errorf("%s required: pass --%s or set %s", label, flag, env)
	}
	return key, nil
}

// --- refresh-firewall ------------------------------------------------------

var refreshFirewallCmd = &cobra.Command{
	Use:   "refresh-firewall",
	Short: "Re-allowlist the collector's current IP on the Instaclustr cluster firewall",
	Long: `When the collector's public IP changes (a new ISP lease, a redeploy without a
static egress), the Instaclustr cluster's firewall still allows the old one and
the collector's database connections time out. This re-detects the IP,
allowlists it, and removes the stale rule this CLI created earlier.`,
	RunE: runRefreshFirewall,
}

func runRefreshFirewall(cmd *cobra.Command, _ []string) error {
	st, err := requireState()
	if err != nil {
		return err
	}
	if st.InstaclustrClusterID == "" {
		return errors.New("the installed collector does not monitor an Instaclustr cluster. " +
			"refresh-firewall only applies to installs made with --provider instaclustr")
	}
	creds, err := resolveInstaclustrCreds(cmd, st.InstaclustrUsername, "instaclustr-api-key", instaclustrProvisioningEnv,
		"Instaclustr provisioning API key (setup only, never stored)")
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	allowRaw, _ := cmd.Flags().GetString("allow-ip")
	if allowRaw == "" {
		switch {
		case st.IsAWS():
			// The collector's egress is the stack's Elastic IP, not this
			// machine's address. A stack without the output was deployed
			// without stable egress — then only an explicit address makes
			// sense.
			allowRaw, err = stackOutput(st.StackName, st.Region, "EgressIP")
			if err != nil {
				return fmt.Errorf("%w\n\nPass --allow-ip explicitly for a deploy without stable egress", err)
			}
		case st.IsGCP():
			// Same shape on gcp: the deployment's reserved static address.
			allowRaw, err = gcpDeploymentOutput(st.Project, st.Region, st.DeploymentName, "egress_ip")
			if err != nil {
				return fmt.Errorf("%w\n\nPass --allow-ip explicitly for a deploy without stable egress", err)
			}
		default:
			allowRaw, err = publicEgressIP(ctx)
			if err != nil {
				return err
			}
		}
	}
	allowCIDR, err := collector.AllowCIDR(allowRaw)
	if err != nil {
		return err
	}
	rule, created, err := ensureFirewallRule(ctx, creds, st.InstaclustrClusterID, allowCIDR)
	if err != nil {
		return err
	}
	if created {
		fmt.Println(style.Success(fmt.Sprintf("✓ Allowlisted %s", allowCIDR)))
	} else {
		fmt.Println(style.Success(fmt.Sprintf("✓ %s already allowlisted", allowCIDR)))
	}
	// Retire the rule a previous run created for a different IP — but never
	// one this CLI did not create.
	if st.FirewallRuleID != "" && st.FirewallRuleID != rule.ID {
		if err := deleteFirewallRule(ctx, creds, st.FirewallRuleID); err != nil {
			fmt.Println(style.Warn(fmt.Sprintf("⚠  could not remove the stale firewall rule: %v (remove it from the console)", err)))
		} else {
			fmt.Println(style.Success("✓ Removed the stale rule from the previous IP"))
		}
	}
	// Record ownership honestly either way: the new rule's id when this run
	// created it, empty when the current rule pre-existed (the old owned id,
	// if any, was just retired above and must not linger in state).
	newID := ""
	if created {
		newID = rule.ID
	}
	if st.FirewallRuleID != newID {
		st.FirewallRuleID = newID
		if err := collector.SaveState(st); err != nil {
			return err
		}
	}
	return nil
}

// --- the aws substrate ------------------------------------------------------

// runInstallInstaclustrAWS deploys the collector for an Instaclustr cluster
// onto Fargate. Networking is explicit (--subnets/--security-group-id): there
// is no RDS instance to discover it from. By default the task runs behind a
// NAT gateway with an Elastic IP (--stable-egress), so the firewall rule
// created for it stays valid across every task restart; --stable-egress=false
// requires --allow-ip, because a plain Fargate task's public IP is ephemeral
// and unknowable in advance.
func runInstallInstaclustrAWS(cmd *cobra.Command) error {
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	apiURL, err := requireAPIURL(cmd)
	if err != nil {
		return err
	}
	if _, err := requireLogin(); err != nil {
		return err
	}
	if st, _ := collector.LoadState(); st != nil && !dryRun {
		return fmt.Errorf("a collector is already installed (agent %s). Run `dbg collector uninstall` first, or `dbg collector status`",
			st.AgentID)
	}
	if err := awsAvailable(); err != nil {
		return err
	}
	identity, err := awsIdentity()
	if err != nil {
		return err
	}
	region := awsRegion()
	if region == "" {
		return errors.New("no AWS region resolved. Set AWS_REGION or configure a profile region")
	}
	accountID, err := awsAccountID()
	if err != nil {
		return err
	}
	fmt.Println(style.Success(fmt.Sprintf("✓ AWS identity: %s (%s)", identity, region)))

	subnetsCSV, _ := cmd.Flags().GetString("subnets")
	subnets := splitCSV(subnetsCSV)
	sg, _ := cmd.Flags().GetString("security-group-id")
	if len(subnets) == 0 || sg == "" {
		return errors.New("--subnets and --security-group-id are required with --provider instaclustr --target aws: " +
			"there is no RDS instance to discover networking from. The security group needs egress to 443 " +
			"(the Instaclustr and DBGorilla APIs) and 5432 (the cluster)")
	}
	stableEgress, _ := cmd.Flags().GetBool("stable-egress")
	vpcID, _ := cmd.Flags().GetString("vpc-id")
	natCidr, _ := cmd.Flags().GetString("nat-subnet-cidr")
	allowRaw, _ := cmd.Flags().GetString("allow-ip")
	if stableEgress {
		if vpcID == "" || natCidr == "" {
			return errors.New("--vpc-id and --nat-subnet-cidr are required with --stable-egress " +
				"(the stack creates a private subnet routed through a NAT gateway with an Elastic IP; " +
				"the FIRST --subnets entry must be a public subnet for the NAT gateway). " +
				"Pass --stable-egress=false with --allow-ip to skip the NAT at the cost of firewall churn")
		}
		// Validate here rather than letting the deploy fail on it after the
		// role and firewall work is already done.
		if _, _, cerr := net.ParseCIDR(natCidr); cerr != nil {
			return fmt.Errorf("--nat-subnet-cidr %q is not a CIDR (e.g. 10.0.200.0/28)", natCidr)
		}
	} else if allowRaw == "" {
		return errors.New("--stable-egress=false needs --allow-ip: a plain Fargate task's public IP is " +
			"ephemeral, so the firewall entry must be an address you manage (a NAT you already have)")
	}

	in, err := resolveInstaclustrInstallInputs(cmd, apiURL, dryRun)
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	stackName, _ := cmd.Flags().GetString("stack-name")
	templateURL, _ := cmd.Flags().GetString("template-url")

	// The monitor password is generated up front so both the role step and
	// the stack's DbPassword secret carry the same value.
	monitorPassword, err := collector.GenerateInstaclustrPassword()
	if err != nil {
		return err
	}
	assignIP, _ := cmd.Flags().GetString("assign-public-ip")
	if assignIP == "" {
		assignIP = "ENABLED"
	}
	comp := collector.BuildInstaclustrComponent(in.ict, in.seedHost, 5432, in.databases, in.sslMode, "",
		in.setupCreds.Username, in.usePrivate, collector.CloudDBPasswordEnv)
	input := collector.AwsStackInput{
		Region:          region,
		AccountID:       accountID,
		Components:      []collector.Component{comp},
		Subnets:         subnets,
		SecurityGroup:   sg,
		AssignPublicIP:  assignIP,
		CommandsEnabled: false,
		StableEgress:    stableEgress,
		VpcID:           vpcID,
		NatSubnetCidr:   natCidr,
	}

	if dryRun {
		input.AgentID, input.TenantID, input.Image = "<agent-id>", "<tenant-id>", "<image>"
		params, secrets, err := collector.AwsStackParams(input)
		if err != nil {
			return err
		}
		fmt.Printf("\nDry run — validating the template for stack %q (no identity minted, no firewall or role changes):\n", stackName)
		printAwsParams(params, secrets)
		return runFargateDeploy(collector.FargateDeploy{
			StackName: stackName, Params: params, Secrets: secrets, DryRun: true, TemplateURL: templateURL,
		})
	}

	// Role first, through the operator's temporary firewall entry.
	opRule, opCreated, removeOperatorRule, err := setupMonitoringRole(ctx, in, monitorPassword)
	if err != nil {
		return err
	}
	// The component above was rendered against the first-listed node; setup
	// has since resolved the real primary, so render it again on the address
	// the collector should seed from.
	input.Components = []collector.Component{
		collector.BuildInstaclustrComponent(in.ict, in.seedHost, 5432, in.databases, in.sslMode, "",
			in.setupCreds.Username, in.usePrivate, collector.CloudDBPasswordEnv),
	}

	fmt.Println(style.Info("Provisioning collector identity..."))
	creds, err := in.client.ProvisionCollector()
	if err != nil {
		removeOperatorRule()
		return err
	}
	fmt.Println(style.Success(fmt.Sprintf("✓ Collector provisioned (agent %s, tenant %s)", creds.AgentID, creds.TenantID)))

	image, imageSource := resolveImage(cmd, creds)
	image = pinImageOrWarn(image, "task")
	fmt.Println(style.Success(fmt.Sprintf("✓ Collector image: %s (%s)", image, imageSource)))

	input.AgentID, input.TenantID, input.Image = creds.AgentID, creds.TenantID, image
	input.Endpoints = endpointsFor(creds, cmd)
	input.ServerSecret = creds.Secret
	input.DBPassword = monitorPassword
	input.InstaclustrKey = in.readOnlyKey
	params, secrets, err := collector.AwsStackParams(input)
	if err != nil {
		removeOperatorRule()
		return err
	}

	// Save state BEFORE the slow deploy (the aws pattern): an interrupted
	// install leaves a tracked collector, not an orphaned stack + identity.
	saveStateOrWarn(&collector.State{
		AgentID:              creds.AgentID,
		TenantID:             creds.TenantID,
		Domain:               creds.Domain,
		Target:               "aws",
		Image:                image,
		TargetName:           in.ict.Name,
		StackName:            stackName,
		Region:               region,
		InstaclustrClusterID: in.clusterID,
		InstaclustrUsername:  in.setupCreds.Username,
		CreatedAt:            time.Now().UTC(),
	})

	fmt.Printf("Deploying to Fargate (stack %q)...\n", stackName)
	if err := deployStack(collector.FargateDeploy{StackName: stackName, Params: params, Secrets: secrets, TemplateURL: templateURL}, "Deploying to Fargate…"); err != nil {
		// An interrupt, a lost operation, or a timeout must NOT tear down a
		// stack that is most likely still converging server-side;
		// cloudDeployFailed keeps those and rolls back only real failures.
		_, derr := cloudDeployFailed(err, in.client, creds.AgentID, collector.DeployTimeout(), "stack", stackName,
			func() error { return deleteStack(stackName, region) }, nil,
			"   Watch it with: dbg collector status, then re-run `dbg collector refresh-firewall` once it is up "+
				"(the EgressIP output appears only once the stack completes, so the firewall entry waits for it).\n")
		removeOperatorRule()
		return derr
	}

	// Allowlist the collector's actual egress: the EIP the stack allocated
	// (stable egress) or the operator-supplied address.
	if err := allowlistCollectorEgress(ctx, in, stableEgress, func() (string, error) {
		eip, oerr := stackOutput(stackName, region, "EgressIP")
		if oerr != nil {
			return "", fmt.Errorf("the stack deployed but its EgressIP output could not be read: %w", oerr)
		}
		return eip, nil
	}, allowRaw, opRule, opCreated, removeOperatorRule); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("Collector deployed. Next:")
	fmt.Println("  dbg collector status              # stack + connection")
	fmt.Println("  dbg collector logs -f             # CloudWatch logs")
	fmt.Println("  dbg collector refresh-firewall    # re-assert the allowlist entry")
	return nil
}

// --- the gcp substrate ------------------------------------------------------

// runInstallInstaclustrGCP deploys the collector for an Instaclustr cluster
// onto Compute Engine via Infrastructure Manager. Networking is explicit
// (--network/--region): there is no Cloud SQL instance to discover it from.
// By default the instance lives in a template-owned subnetwork routed through
// a Cloud NAT with a reserved static address (--stable-egress), so the
// firewall rule created for it stays valid across instance recreates;
// --stable-egress=false requires --allow-ip, because the instance has no
// public IP of its own and whatever NAT the VPC already has is an address the
// operator, not this CLI, manages.
func runInstallInstaclustrGCP(cmd *cobra.Command) error {
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	apiURL, err := requireInstallSession(cmd)
	if err != nil {
		return err
	}
	if st, _ := collector.LoadState(); st != nil && !dryRun {
		return fmt.Errorf("a collector is already installed (agent %s). Run `dbg collector uninstall` first, or `dbg collector status`",
			st.AgentID)
	}
	// Refused rather than silently ignored (the cloudsql gcp path's rule): an
	// aws command re-run with --target gcp must not keep flags this path
	// never reads. --vpc-id is the aws instaclustr stable-egress flag.
	for _, f := range append([]string{"vpc-id"}, awsOnlyFlags...) {
		if cmd.Flags().Changed(f) {
			return fmt.Errorf("--%s applies to --target aws only", f)
		}
	}
	if err := printCloudIdentity("Google Cloud", gcpAvailable, gcpIdentity); err != nil {
		return err
	}

	project, _ := cmd.Flags().GetString("project")
	if project == "" {
		if project, err = gcpProject(); err != nil {
			return err
		}
	}
	if gcpProjectNumberRe.MatchString(project) {
		return fmt.Errorf("project %q is a project number; pass the project ID (--project), "+
			"which names the collector's service account", project)
	}
	deploymentName, _ := cmd.Flags().GetString("deployment-name")
	if !gcpDeploymentNameRe.MatchString(deploymentName) {
		return fmt.Errorf("--deployment-name %q must be 6-30 chars of [a-z0-9-], starting with a letter and not ending with '-' "+
			"(it names the collector's service account and secrets)", deploymentName)
	}
	deployServiceAccount, _ := cmd.Flags().GetString("deploy-service-account")
	switch {
	case deployServiceAccount == "" && !dryRun:
		return errors.New("pass --deploy-service-account: the account Infrastructure Manager actuates Terraform as " +
			"(it needs roles/config.agent plus permission to create the collector's instance group, service account, " +
			"and — under stable egress — its subnetwork, router and static address)")
	case deployServiceAccount != "" && !gcpServiceAccountRe.MatchString(deployServiceAccount):
		return fmt.Errorf("--deploy-service-account %q must be of the form projects/<project>/serviceAccounts/<email>", deployServiceAccount)
	}
	templateSource, _ := cmd.Flags().GetString("template-source")
	if templateSource == "" {
		templateSource = collector.HostedGcpTemplateSource()
	}
	region, _ := cmd.Flags().GetString("region")
	if region == "" {
		return errors.New("--region is required with --provider instaclustr --target gcp: there is no " +
			"Cloud SQL instance to take it from. Pick the region closest to the cluster")
	}
	network, _ := cmd.Flags().GetString("network")
	if network == "" {
		return errors.New("--network is required with --provider instaclustr --target gcp " +
			"(projects/<project>/global/networks/<name>): there is no Cloud SQL instance to discover it from")
	}
	stableEgress, _ := cmd.Flags().GetBool("stable-egress")
	natCidr, _ := cmd.Flags().GetString("nat-subnet-cidr")
	allowRaw, _ := cmd.Flags().GetString("allow-ip")
	subnetwork := ""
	if stableEgress {
		if natCidr == "" {
			return errors.New("--nat-subnet-cidr is required with --stable-egress (the template creates its own " +
				"subnetwork routed through a Cloud NAT with a reserved static address; the CIDR must be unused " +
				"in the VPC). Pass --stable-egress=false with --allow-ip to use egress you already manage")
		}
		// Validate here rather than letting the deploy fail on it after the
		// role and firewall work is already done.
		if _, _, cerr := net.ParseCIDR(natCidr); cerr != nil {
			return fmt.Errorf("--nat-subnet-cidr %q is not a CIDR (e.g. 10.10.200.0/28)", natCidr)
		}
		// Refuse rather than silently drop: under stable egress the template
		// owns the subnetwork and the allowlisted address.
		if cmd.Flags().Changed("subnetwork") {
			return errors.New("--subnetwork does not apply with --stable-egress: the instance lives in the " +
				"template-owned NAT-routed subnetwork. Pass --stable-egress=false (with --allow-ip) to choose " +
				"the subnetwork yourself")
		}
		if allowRaw != "" {
			return errors.New("--allow-ip does not apply with --stable-egress: the install allowlists the " +
				"deployment's reserved static address. Pass --stable-egress=false to allowlist an address you manage")
		}
	} else {
		if allowRaw == "" {
			return errors.New("--stable-egress=false needs --allow-ip: the instance has no public IP, so its egress " +
				"address belongs to whatever NAT the VPC already has — an address you manage, not this CLI")
		}
		subnetwork, _ = cmd.Flags().GetString("subnetwork")
		if subnetwork == "" {
			if subnetwork, err = resolveGcpSubnetwork(network, region); err != nil {
				return err
			}
		}
		// Preflight, not a gate (the cloudsql path's check): without Private
		// Google Access or NAT coverage the boot script cannot fetch its
		// secrets or the image, and the failure is an opaque 30-minute
		// timeout.
		if pga, subnetPath, perr := gcpSubnetworkPGA(network, subnetwork, region); perr == nil && !pga {
			fmt.Println(style.Warn(fmt.Sprintf(
				"⚠  subnetwork %s has Private Google Access OFF — without it (or NAT coverage of this subnetwork) "+
					"the instance cannot reach Secret Manager or the registry at boot. Enable it with:\n"+
					"   gcloud compute networks subnets update %s --region=%s --enable-private-ip-google-access",
				subnetPath, lastPathSegmentOf(subnetPath), region)))
		}
	}
	if err := requireNoRuntime(dryRun,
		func() (string, error) { return gcpDeploymentStatus(project, region, deploymentName) },
		"deployment", deploymentName, "--deployment-name"); err != nil {
		return err
	}

	in, err := resolveInstaclustrInstallInputs(cmd, apiURL, dryRun)
	if err != nil {
		return err
	}
	ctx := cmd.Context()

	monitorPassword, err := collector.GenerateInstaclustrPassword()
	if err != nil {
		return err
	}
	comp := collector.BuildInstaclustrComponent(in.ict, in.seedHost, 5432, in.databases, in.sslMode, "",
		in.setupCreds.Username, in.usePrivate, collector.CloudDBPasswordEnv)
	input := collector.GcpStackInput{
		Components:      []collector.Component{comp},
		Network:         network,
		Subnetwork:      subnetwork,
		Region:          region,
		DeploymentName:  deploymentName,
		Project:         project,
		CommandsEnabled: false,
		StableEgress:    stableEgress,
		NatSubnetCidr:   natCidr,
	}

	if dryRun {
		input.AgentID, input.TenantID, input.Image = "<agent-id>", "<tenant-id>", "<image>"
		inputs, err := collector.GcpDeployInputs(input)
		if err != nil {
			return err
		}
		fmt.Printf("\nDry run — probing the template for deployment %q (no identity minted, no secrets written, no firewall or role changes):\n", deploymentName)
		printDeployParams(inputs, nil, "collector_config")
		printGcpSecretPlan(deploymentName)
		return runGcpDeploy(collector.GcpDeploy{
			Project: project, Region: region, DeploymentName: deploymentName,
			TemplateSource: templateSource, DryRun: true,
		})
	}

	// Role first, through the operator's temporary firewall entry.
	opRule, opCreated, removeOperatorRule, err := setupMonitoringRole(ctx, in, monitorPassword)
	if err != nil {
		return err
	}
	// The component above was rendered against the first-listed node; setup
	// has since resolved the real primary, so render it again on the address
	// the collector should seed from.
	input.Components = []collector.Component{
		collector.BuildInstaclustrComponent(in.ict, in.seedHost, 5432, in.databases, in.sslMode, "",
			in.setupCreds.Username, in.usePrivate, collector.CloudDBPasswordEnv),
	}

	fmt.Println(style.Info("Provisioning collector identity..."))
	creds, err := in.client.ProvisionCollector()
	if err != nil {
		removeOperatorRule()
		return err
	}
	fmt.Println(style.Success(fmt.Sprintf("✓ Collector provisioned (agent %s, tenant %s)", creds.AgentID, creds.TenantID)))

	image, imageSource := resolveImage(cmd, creds)
	image = pinImageOrWarn(image, "instance")
	fmt.Println(style.Success(fmt.Sprintf("✓ Collector image: %s (%s)", image, imageSource)))

	input.AgentID, input.TenantID, input.Image = creds.AgentID, creds.TenantID, image
	input.Endpoints = endpointsFor(creds, cmd)
	inputs, err := collector.GcpDeployInputs(input)
	if err != nil {
		deprovisionOrWarn(in.client, creds.AgentID)
		removeOperatorRule()
		return err
	}

	// The credentials go straight to Secret Manager, before the deploy: the
	// template only grants access to them, so they never reach Infrastructure
	// Manager (whose input values and state are readable by config.* roles).
	if err := ensureGcpSecrets(project, deploymentName, collector.GcpSecretValues{
		ServerSecret:   creds.Secret,
		DBPassword:     monitorPassword,
		InstaclustrKey: in.readOnlyKey,
	}); err != nil {
		deleteGcpSecretsOrWarn(project, deploymentName)
		deprovisionOrWarn(in.client, creds.AgentID)
		removeOperatorRule()
		return err
	}
	fmt.Println(style.Success("✓ Credentials written to Secret Manager (never sent to Infrastructure Manager)"))

	// Save state BEFORE the slow deploy (the aws pattern): an interrupted
	// install leaves a tracked collector, not an orphaned deployment + identity.
	saveStateOrWarn(&collector.State{
		AgentID:              creds.AgentID,
		TenantID:             creds.TenantID,
		Domain:               creds.Domain,
		Target:               "gcp",
		Image:                image,
		TargetName:           in.ict.Name,
		Project:              project,
		Region:               region,
		DeploymentName:       deploymentName,
		InstaclustrClusterID: in.clusterID,
		InstaclustrUsername:  in.setupCreds.Username,
		CreatedAt:            time.Now().UTC(),
	})

	fmt.Printf("Deploying to Compute Engine (deployment %q)...\n", deploymentName)
	deploy := collector.GcpDeploy{
		Project: project, Region: region, DeploymentName: deploymentName,
		TemplateSource: templateSource, ServiceAccount: deployServiceAccount,
		Inputs: inputs,
	}
	if err := withSpinner("Deploying to Compute Engine…", func() error { return runGcpDeploy(deploy) }); err != nil {
		// An interrupt, a lost operation, or a timeout must NOT tear down a
		// deployment that is most likely still converging server-side;
		// cloudDeployFailed keeps those and rolls back only real failures.
		kept, derr := cloudDeployFailed(err, in.client, creds.AgentID, collector.GcpDeployTimeout(), "deployment", deploymentName,
			func() error {
				if err := deleteGcpDeployment(project, region, deploymentName); err != nil {
					return err
				}
				deleteGcpSecretsOrWarn(project, deploymentName)
				return nil
			},
			func() { deleteGcpSecretsOrWarn(project, deploymentName) },
			"   Watch it with: dbg collector status, then re-run `dbg collector refresh-firewall` once it is up "+
				"(the egress_ip output appears only once the deployment completes, so the firewall entry waits for it).\n")
		removeOperatorRule()
		if !kept && stableEgress {
			derr = fmt.Errorf("%w\n\nIf the failure is creating the Cloud NAT: a NAT gateway configured for ALL "+
				"subnetworks in this region blocks adding a second one. Re-run with --stable-egress=false "+
				"--allow-ip <that NAT's address> instead", derr)
		}
		return derr
	}

	// Allowlist the collector's actual egress: the static address the
	// deployment reserved (stable egress) or the operator-supplied address.
	if err := allowlistCollectorEgress(ctx, in, stableEgress, func() (string, error) {
		eip, oerr := gcpDeploymentOutput(project, region, deploymentName, "egress_ip")
		if oerr != nil {
			return "", fmt.Errorf("the collector deployed but its egress_ip output could not be read: %w", oerr)
		}
		return eip, nil
	}, allowRaw, opRule, opCreated, removeOperatorRule); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("Collector deployed. Next:")
	fmt.Println("  dbg collector status              # deployment + connection")
	fmt.Println("  dbg collector logs -f             # Cloud Logging")
	fmt.Println("  dbg collector refresh-firewall    # re-assert the allowlist entry")
	return nil
}
