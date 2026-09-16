package cmd

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/dbgorilla/dbgorilla-cli/internal/collector"
	"github.com/spf13/cobra"
)

// Fakes for the Instaclustr seams, one per side effect, restored on cleanup.

func stubDiscoverInstaclustr(t *testing.T, target collector.InstaclustrTarget, err error) {
	t.Helper()
	orig := discoverInstaclustr
	discoverInstaclustr = func(_ context.Context, _ collector.InstaclustrCreds, _ string) (collector.InstaclustrTarget, error) {
		return target, err
	}
	t.Cleanup(func() { discoverInstaclustr = orig })
}

func stubEnsureFirewallRule(t *testing.T, rule collector.FirewallRule, created bool, err error) *[]string {
	t.Helper()
	var cidrs []string
	orig := ensureFirewallRule
	ensureFirewallRule = func(_ context.Context, _ collector.InstaclustrCreds, _ string, cidr string) (collector.FirewallRule, bool, error) {
		cidrs = append(cidrs, cidr)
		return rule, created, err
	}
	t.Cleanup(func() { ensureFirewallRule = orig })
	return &cidrs
}

func stubDeleteFirewallRule(t *testing.T, err error) *[]string {
	t.Helper()
	var deleted []string
	orig := deleteFirewallRule
	deleteFirewallRule = func(_ context.Context, _ collector.InstaclustrCreds, ruleID string) error {
		deleted = append(deleted, ruleID)
		return err
	}
	t.Cleanup(func() { deleteFirewallRule = orig })
	return &deleted
}

func stubCreateInstaclustrRole(t *testing.T, err error) *[]string {
	t.Helper()
	var runs []string
	orig := createInstaclustrRole
	createInstaclustrRole = func(_ context.Context, dsn, _, _ string) ([]string, error) {
		runs = append(runs, dsn)
		return nil, err
	}
	t.Cleanup(func() { createInstaclustrRole = orig })
	return &runs
}

func stubPublicEgressIP(t *testing.T, ip string, err error) {
	t.Helper()
	orig := publicEgressIP
	publicEgressIP = func(_ context.Context) (string, error) { return ip, err }
	t.Cleanup(func() { publicEgressIP = orig })
}

func stubPrimaryHost(t *testing.T, host string, err error) *[][]string {
	t.Helper()
	var probed [][]string
	orig := primaryHost
	primaryHost = func(_ context.Context, hosts []string, _ int, _ string) (string, error) {
		probed = append(probed, hosts)
		return host, err
	}
	t.Cleanup(func() { primaryHost = orig })
	return &probed
}

func stubPrivatePathToCluster(t *testing.T, src net.IP, how string, ok bool) {
	t.Helper()
	orig := privatePathToCluster
	privatePathToCluster = func([]string) (net.IP, string, bool) { return src, how, ok }
	t.Cleanup(func() { privatePathToCluster = orig })
}

// icTestPrivateTarget is a private-network cluster: two nodes, no public
// addresses, and the network blocks the route check reads.
func icTestPrivateTarget() collector.InstaclustrTarget {
	return collector.InstaclustrTarget{
		ClusterID: "c-1", Name: "orders", Status: "RUNNING",
		PostgresVersion: "18.4.0", CloudProvider: "AWS_VPC", Region: "US_EAST_1",
		DefaultUserPassword:   "pw-1",
		PrivateNetworkCluster: true,
		NetworkCIDRs:          []string{"10.10.0.0/16"},
		Nodes: []collector.InstaclustrNode{
			{ID: "n1", PrivateAddress: "10.10.3.1"},
			{ID: "n2", PrivateAddress: "10.10.3.2"},
		},
	}
}

func icTestTarget() collector.InstaclustrTarget {
	return collector.InstaclustrTarget{
		ClusterID: "c-1", Name: "orders", Status: "RUNNING",
		PostgresVersion: "18.4.0", CloudProvider: "AWS_VPC", Region: "US_EAST_1",
		DefaultUserPassword: "pw-1",
		Nodes: []collector.InstaclustrNode{
			{ID: "n1", PublicAddress: "203.0.113.10", PrivateAddress: "10.0.0.10"},
		},
	}
}

func icCmd(t *testing.T, apiURL string) *cobra.Command {
	t.Helper()
	cmd := baseCmd()
	cmd.Flags().String("provider", "", "")
	cmd.Flags().String("target", "", "")
	cmd.Flags().String("cluster-id", "", "")
	cmd.Flags().String("instaclustr-user", "", "")
	cmd.Flags().String("instaclustr-api-key", "", "")
	cmd.Flags().String("instaclustr-readonly-key", "", "")
	cmd.Flags().Bool("use-private-addresses", false, "")
	cmd.Flags().String("allow-ip", "", "")
	// Type must match the REAL registration (a plain String, CSV-split) — a
	// StringSlice here once masked a real GetStringSlice-on-String bug.
	cmd.Flags().String("db-name", "", "")
	cmd.Flags().String("ssl-mode", "verify-full", "")
	cmd.Flags().String("ca-cert", "", "")
	cmd.Flags().Bool("dry-run", false, "")
	cmd.Flags().Bool("force", false, "")
	cmd.Flags().String("image", "", "")
	cmd.Flags().String("auth-url", "", "")
	cmd.Flags().String("keycloak-url", "", "")
	cmd.Flags().String("otlp-url", "", "")
	cmd.Flags().String("opamp-url", "", "")
	if apiURL != "" {
		mustSet(t, cmd, "api-url", apiURL)
	}
	mustSet(t, cmd, "provider", "instaclustr")
	return cmd
}

func TestInstallInstaclustrRejectsUnknownTargets(t *testing.T) {
	isolate(t)
	cmd := icCmd(t, "")
	mustSet(t, cmd, "target", "azure")
	err := runInstall(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), `unknown --target "azure"`) {
		t.Fatalf("expected the unknown-target refusal, got %v", err)
	}
}

func TestInstallInstaclustrRequiresClusterIDNonInteractively(t *testing.T) {
	isolate(t)
	writeTokens(t)
	srv := installServer(t, "a-1")
	defer srv.Close()
	setInstallStubs(t, nil, cleanReport(), nil)
	cmd := icCmd(t, srv.URL)
	mustSet(t, cmd, "instaclustr-user", "someone")
	mustSet(t, cmd, "instaclustr-api-key", "key123")
	mustSet(t, cmd, "instaclustr-readonly-key", "key456")
	err := runInstall(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "--cluster-id is required") {
		t.Fatalf("expected cluster-id requirement, got %v", err)
	}
}

func TestInstallInstaclustrRequiresCredsNonInteractively(t *testing.T) {
	isolate(t)
	writeTokens(t)
	srv := installServer(t, "a-1")
	defer srv.Close()
	setInstallStubs(t, nil, cleanReport(), nil)
	cmd := icCmd(t, srv.URL)
	mustSet(t, cmd, "cluster-id", "c-1")
	err := runInstall(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "INSTACLUSTR_USERNAME") {
		t.Fatalf("expected the username requirement naming the env var, got %v", err)
	}
}

func TestInstallInstaclustrHappyPath(t *testing.T) {
	isolate(t)
	writeTokens(t)
	srv := installServer(t, "a-1")
	defer srv.Close()
	setInstallStubs(t, nil, cleanReport(), nil)
	stubDiscoverInstaclustr(t, icTestTarget(), nil)
	stubPublicEgressIP(t, "192.0.2.9", nil)
	cidrs := stubEnsureFirewallRule(t, collector.FirewallRule{ID: "r-1", Network: "192.0.2.9/32"}, true, nil)
	roleRuns := stubCreateInstaclustrRole(t, nil)

	cmd := icCmd(t, srv.URL)
	mustSet(t, cmd, "cluster-id", "c-1")
	mustSet(t, cmd, "instaclustr-user", "someone")
	mustSet(t, cmd, "instaclustr-api-key", "key123")
	mustSet(t, cmd, "instaclustr-readonly-key", "key456")

	if err := runInstall(cmd, nil); err != nil {
		t.Fatal(err)
	}

	if len(*cidrs) != 1 || (*cidrs)[0] != "192.0.2.9/32" {
		t.Fatalf("firewall not ensured for the egress IP: %v", *cidrs)
	}
	if len(*roleRuns) != 1 || !strings.Contains((*roleRuns)[0], "icpostgresql:pw-1@203.0.113.10:5432") {
		t.Fatalf("role creation used the wrong DSN: %v", *roleRuns)
	}

	st, err := collector.LoadState()
	if err != nil || st == nil {
		t.Fatalf("no state saved: %v", err)
	}
	if st.InstaclustrClusterID != "c-1" || st.FirewallRuleID != "r-1" || st.TargetName != "orders" {
		t.Fatalf("state missing instaclustr fields: %+v", st)
	}

	cfg, err := collector.LoadConfig(st.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.Component[0].Provider
	if p.Type != "instaclustr" || p.ClusterID != "c-1" || p.CloudProvider != "AWS_VPC" ||
		p.APIUsername != "someone" || p.APIKey != "${"+collector.InstaclustrAPIKeyEnv+"}" {
		t.Fatalf("rendered provider block wrong: %+v", p)
	}
	if cfg.Component[0].Auth.User != collector.InstaclustrMonitorUser {
		t.Fatalf("auth user should be the monitoring role: %+v", cfg.Component[0].Auth)
	}
	// The env-file must carry the READ-ONLY key under the name the config
	// references — and never the writable setup key.
	env, err := os.ReadFile(st.EnvFilePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(env), collector.InstaclustrAPIKeyEnv+"=key456") {
		t.Fatalf("env-file missing the read-only key: %s", env)
	}
	if strings.Contains(string(env), "key123") {
		t.Fatalf("the writable setup key leaked into the env-file: %s", env)
	}
}

func TestInstallInstaclustrDryRunMutatesNothing(t *testing.T) {
	isolate(t)
	writeTokens(t)
	srv := installServer(t, "a-1")
	defer srv.Close()
	setInstallStubs(t, nil, cleanReport(), nil)
	stubDiscoverInstaclustr(t, icTestTarget(), nil)
	stubPublicEgressIP(t, "192.0.2.9", nil)
	cidrs := stubEnsureFirewallRule(t, collector.FirewallRule{}, false, errors.New("must not be called"))
	roleRuns := stubCreateInstaclustrRole(t, errors.New("must not be called"))

	cmd := icCmd(t, srv.URL)
	mustSet(t, cmd, "cluster-id", "c-1")
	mustSet(t, cmd, "instaclustr-user", "someone")
	mustSet(t, cmd, "instaclustr-api-key", "key123")
	mustSet(t, cmd, "dry-run", "true")
	mustSet(t, cmd, "db-name", "orders,billing")

	out := capture(t, func() {
		if err := runInstall(cmd, nil); err != nil {
			t.Errorf("dry run failed: %v", err)
		}
	})
	if len(*cidrs) != 0 || len(*roleRuns) != 0 {
		t.Fatalf("dry run mutated: firewall=%v role=%v", *cidrs, *roleRuns)
	}
	if st, _ := collector.LoadState(); st != nil {
		t.Fatalf("dry run saved state: %+v", st)
	}
	if !strings.Contains(out, "192.0.2.9/32") || !strings.Contains(out, "type = \"instaclustr\"") {
		t.Fatalf("preview missing the firewall CIDR or rendered config:\n%s", out)
	}
	if !strings.Contains(out, `databases = ["orders", "billing"]`) {
		t.Fatalf("preview lost --db-name (CSV on a plain String flag):\n%s", out)
	}
	if strings.Contains(out, "key123") {
		t.Fatalf("the setup key leaked into the preview:\n%s", out)
	}
}

func TestInstallInstaclustrRollsBackTheRuleWhenTheContainerFails(t *testing.T) {
	isolate(t)
	writeTokens(t)
	srv := installServer(t, "a-1")
	defer srv.Close()
	setInstallStubs(t, nil, cleanReport(), errors.New("docker exploded"))
	stubDiscoverInstaclustr(t, icTestTarget(), nil)
	stubPublicEgressIP(t, "192.0.2.9", nil)
	stubEnsureFirewallRule(t, collector.FirewallRule{ID: "r-1", Network: "192.0.2.9/32"}, true, nil)
	stubCreateInstaclustrRole(t, nil)
	deleted := stubDeleteFirewallRule(t, nil)

	cmd := icCmd(t, srv.URL)
	mustSet(t, cmd, "cluster-id", "c-1")
	mustSet(t, cmd, "instaclustr-user", "someone")
	mustSet(t, cmd, "instaclustr-api-key", "key123")
	mustSet(t, cmd, "instaclustr-readonly-key", "key456")

	if err := runInstall(cmd, nil); err == nil {
		t.Fatal("container failure must fail the install")
	}
	if len(*deleted) != 1 || (*deleted)[0] != "r-1" {
		t.Fatalf("the rule this run created was not rolled back: %v", *deleted)
	}
	if st, _ := collector.LoadState(); st != nil {
		t.Fatalf("state saved despite rollback: %+v", st)
	}
}

func TestInstallInstaclustrRejectsCACert(t *testing.T) {
	isolate(t)
	cmd := icCmd(t, "")
	mustSet(t, cmd, "ca-cert", "/tmp/some-ca.pem")
	err := runInstall(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "--ca-cert is not supported") {
		t.Fatalf("expected the ca-cert refusal, got %v", err)
	}
}

func TestInstallUnknownProviderIsRejected(t *testing.T) {
	isolate(t)
	cmd := icCmd(t, "")
	mustSet(t, cmd, "provider", "aws_rds")
	err := runInstall(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "unknown --provider") {
		t.Fatalf("an unknown provider must not fall through to the docker prompts, got %v", err)
	}
}

func TestInstallInstaclustrDiscoveryErrorSurfaces(t *testing.T) {
	isolate(t)
	writeTokens(t)
	srv := installServer(t, "a-1")
	defer srv.Close()
	setInstallStubs(t, nil, cleanReport(), nil)
	stubDiscoverInstaclustr(t, collector.InstaclustrTarget{}, errors.New("not found (HTTP 404)"))

	cmd := icCmd(t, srv.URL)
	mustSet(t, cmd, "cluster-id", "c-1")
	mustSet(t, cmd, "instaclustr-user", "someone")
	mustSet(t, cmd, "instaclustr-api-key", "key123")
	mustSet(t, cmd, "instaclustr-readonly-key", "key456")

	err := runInstall(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Fatalf("expected the discovery error to surface, got %v", err)
	}
}

func stubStackOutput(t *testing.T, value string, err error) {
	t.Helper()
	orig := stackOutput
	stackOutput = func(_, _, _ string) (string, error) { return value, err }
	t.Cleanup(func() { stackOutput = orig })
}

func icAwsCmd(t *testing.T, apiURL string) *cobra.Command {
	t.Helper()
	cmd := icCmd(t, apiURL)
	cmd.Flags().String("subnets", "", "")
	cmd.Flags().String("security-group-id", "", "")
	cmd.Flags().Bool("stable-egress", true, "")
	cmd.Flags().String("vpc-id", "", "")
	cmd.Flags().String("nat-subnet-cidr", "", "")
	cmd.Flags().String("stack-name", "dbgorilla-collector", "")
	cmd.Flags().String("template-url", "", "")
	mustSet(t, cmd, "target", "aws")
	mustSet(t, cmd, "cluster-id", "c-1")
	mustSet(t, cmd, "instaclustr-user", "someone")
	mustSet(t, cmd, "instaclustr-api-key", "key123")
	mustSet(t, cmd, "instaclustr-readonly-key", "key456")
	return cmd
}

func TestInstallInstaclustrAWSRequiresExplicitNetworking(t *testing.T) {
	isolate(t)
	writeTokens(t)
	srv := installServer(t, "a-1")
	defer srv.Close()
	stubAWSOK(t)
	// The cluster is discovered before the networking is decided, because a
	// BYOC cluster does not need these flags at all. icTestTarget is hosted on
	// Instaclustr's own account, so they stay required.
	stubDiscoverInstaclustr(t, icTestTarget(), nil)
	cmd := icAwsCmd(t, srv.URL)
	err := runInstall(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "--subnets and --security-group-id are required") {
		t.Fatalf("expected the explicit-networking requirement, got %v", err)
	}
}

func TestInstallInstaclustrAWSStableEgressNeedsVpcAndCidr(t *testing.T) {
	isolate(t)
	writeTokens(t)
	srv := installServer(t, "a-1")
	defer srv.Close()
	stubAWSOK(t)
	// The cluster is discovered before the networking is decided, because a
	// BYOC cluster does not need these flags at all. icTestTarget is hosted on
	// Instaclustr's own account, so they stay required.
	stubDiscoverInstaclustr(t, icTestTarget(), nil)
	cmd := icAwsCmd(t, srv.URL)
	mustSet(t, cmd, "subnets", "subnet-1")
	mustSet(t, cmd, "security-group-id", "sg-1")
	err := runInstall(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "--vpc-id and --nat-subnet-cidr are required") {
		t.Fatalf("expected the stable-egress requirement, got %v", err)
	}
}

func TestInstallInstaclustrAWSNoStableEgressNeedsAllowIP(t *testing.T) {
	isolate(t)
	writeTokens(t)
	srv := installServer(t, "a-1")
	defer srv.Close()
	stubAWSOK(t)
	// The cluster is discovered before the networking is decided, because a
	// BYOC cluster does not need these flags at all. icTestTarget is hosted on
	// Instaclustr's own account, so they stay required.
	stubDiscoverInstaclustr(t, icTestTarget(), nil)
	cmd := icAwsCmd(t, srv.URL)
	mustSet(t, cmd, "subnets", "subnet-1")
	mustSet(t, cmd, "security-group-id", "sg-1")
	mustSet(t, cmd, "stable-egress", "false")
	err := runInstall(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "needs --allow-ip") {
		t.Fatalf("expected the allow-ip requirement, got %v", err)
	}
}

func TestInstallInstaclustrAWSHappyPath(t *testing.T) {
	isolate(t)
	writeTokens(t)
	srv := installServer(t, "a-1")
	defer srv.Close()
	stubAWSOK(t)
	stubDiscoverInstaclustr(t, icTestTarget(), nil)
	stubPublicEgressIP(t, "192.0.2.9", nil) // the operator's machine
	rec := stubDeploy(t, nil)
	stubStackOutput(t, "198.51.100.20", nil) // the stack's EIP
	roleRuns := stubCreateInstaclustrRole(t, nil)
	deleted := stubDeleteFirewallRule(t, nil)

	// ensureFirewallRule is called twice: the operator's temp rule (created)
	// and the EIP rule. Return distinct ids so the temp-rule cleanup and the
	// ownership recording are distinguishable.
	var cidrs []string
	origEnsure := ensureFirewallRule
	ensureFirewallRule = func(_ context.Context, _ collector.InstaclustrCreds, _ string, cidr string) (collector.FirewallRule, bool, error) {
		cidrs = append(cidrs, cidr)
		if cidr == "192.0.2.9/32" {
			return collector.FirewallRule{ID: "r-operator", Network: cidr}, true, nil
		}
		return collector.FirewallRule{ID: "r-eip", Network: cidr}, true, nil
	}
	t.Cleanup(func() { ensureFirewallRule = origEnsure })

	cmd := icAwsCmd(t, srv.URL)
	mustSet(t, cmd, "subnets", "subnet-1")
	mustSet(t, cmd, "security-group-id", "sg-1")
	mustSet(t, cmd, "vpc-id", "vpc-1")
	mustSet(t, cmd, "nat-subnet-cidr", "10.0.200.0/28")

	if err := runInstall(cmd, nil); err != nil {
		t.Fatal(err)
	}
	if len(*roleRuns) != 1 {
		t.Fatalf("role not ensured exactly once: %v", *roleRuns)
	}
	if rec.count != 1 || rec.params["StableEgress"] != "ENABLED" || rec.secrets["InstaclustrApiKey"] != "key456" {
		t.Fatalf("deploy params wrong: count=%d %v", rec.count, rec.params)
	}
	if rec.params["InstaclustrApiKey"] != "" {
		t.Fatal("the API key must never enter the printable params map")
	}
	if len(cidrs) != 2 || cidrs[0] != "192.0.2.9/32" || cidrs[1] != "198.51.100.20/32" {
		t.Fatalf("expected operator rule then EIP rule, got %v", cidrs)
	}
	if len(*deleted) != 1 || (*deleted)[0] != "r-operator" {
		t.Fatalf("operator temp rule not cleaned up: %v", *deleted)
	}
	st, err := collector.LoadState()
	if err != nil || st == nil {
		t.Fatalf("no state: %v", err)
	}
	if !st.IsAWS() || st.InstaclustrClusterID != "c-1" || st.FirewallRuleID != "r-eip" {
		t.Fatalf("state wrong: %+v", st)
	}
}

// The whole point of the primary probe: the cluster API lists a standby first
// about as often as not, and BOTH the role writes and the rendered
// collector.toml have to land on the node the probe elected -- not on the one
// the listing happened to put first.
func TestInstallSeedsFromTheProbedPrimaryNotTheFirstListedNode(t *testing.T) {
	isolate(t)
	writeTokens(t)
	srv := installServer(t, "a-1")
	defer srv.Close()
	setInstallStubs(t, nil, cleanReport(), nil)

	target := icTestTarget()
	// Replica first, primary second -- the ordering that broke the install.
	target.Nodes = []collector.InstaclustrNode{
		{ID: "n1", PublicAddress: "203.0.113.10", PrivateAddress: "10.0.0.10"},
		{ID: "n2", PublicAddress: "203.0.113.11", PrivateAddress: "10.0.0.11"},
	}
	stubDiscoverInstaclustr(t, target, nil)
	stubPublicEgressIP(t, "192.0.2.9", nil)
	stubEnsureFirewallRule(t, collector.FirewallRule{ID: "r-1", Network: "192.0.2.9/32"}, true, nil)
	roleRuns := stubCreateInstaclustrRole(t, nil)
	probed := stubPrimaryHost(t, "203.0.113.11", nil)

	cmd := icCmd(t, srv.URL)
	mustSet(t, cmd, "cluster-id", "c-1")
	mustSet(t, cmd, "instaclustr-user", "someone")
	mustSet(t, cmd, "instaclustr-api-key", "key123")
	mustSet(t, cmd, "instaclustr-readonly-key", "key456")

	if err := runInstall(cmd, nil); err != nil {
		t.Fatal(err)
	}

	if len(*probed) != 1 || len((*probed)[0]) != 2 || (*probed)[0][0] != "203.0.113.10" {
		t.Fatalf("every node should have been offered to the probe, got %v", *probed)
	}
	if len(*roleRuns) != 1 || !strings.Contains((*roleRuns)[0], "@203.0.113.11:5432") {
		t.Fatalf("role writes went somewhere other than the elected primary: %v", *roleRuns)
	}
	st, err := collector.LoadState()
	if err != nil || st == nil {
		t.Fatalf("no state saved: %v", err)
	}
	cfg, err := collector.LoadConfig(st.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Component[0].Connect.Host; got != "203.0.113.11" {
		t.Fatalf("collector.toml seeds from %q, not the elected primary 203.0.113.11", got)
	}
}

// A deterministic probe failure -- every node reachable, none of them a writer
// -- must surface immediately. Retrying it re-dials every node at
// connect_timeout each, adding minutes before an answer that was already final.
func TestInstallDoesNotRetryADeterministicPrimaryProbeFailure(t *testing.T) {
	isolate(t)
	writeTokens(t)
	srv := installServer(t, "a-1")
	defer srv.Close()
	setInstallStubs(t, nil, cleanReport(), nil)

	target := icTestTarget()
	target.Nodes = []collector.InstaclustrNode{
		{ID: "n1", PublicAddress: "203.0.113.10"},
		{ID: "n2", PublicAddress: "203.0.113.11"},
	}
	stubDiscoverInstaclustr(t, target, nil)
	stubPublicEgressIP(t, "192.0.2.9", nil)
	stubEnsureFirewallRule(t, collector.FirewallRule{ID: "r-1", Network: "192.0.2.9/32"}, true, nil)
	stubDeleteFirewallRule(t, nil)
	stubCreateInstaclustrRole(t, errors.New("must not be reached"))
	// Not a connection failure: the cluster answered, and answered "standby".
	probed := stubPrimaryHost(t, "", errors.New("no node answered as the cluster primary"))

	cmd := icCmd(t, srv.URL)
	mustSet(t, cmd, "cluster-id", "c-1")
	mustSet(t, cmd, "instaclustr-user", "someone")
	mustSet(t, cmd, "instaclustr-api-key", "key123")
	mustSet(t, cmd, "instaclustr-readonly-key", "key456")

	if err := runInstall(cmd, nil); err == nil {
		t.Fatal("expected the install to fail when no node is the primary")
	}
	if len(*probed) != 1 {
		t.Fatalf("a deterministic probe failure was retried %d times", len(*probed))
	}
}

func TestRefreshFirewallOnAWSUsesTheStackEgressIP(t *testing.T) {
	isolate(t)
	if err := collector.SaveState(&collector.State{
		AgentID: "a-1", Target: "aws", StackName: "s", Region: "us-east-1",
		InstaclustrClusterID: "c-1", InstaclustrUsername: "someone",
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv(instaclustrProvisioningEnv, "key123")
	stubStackOutput(t, "198.51.100.20", nil)
	stubPublicEgressIP(t, "192.0.2.9", errors.New("must not be called for an aws install"))
	cidrs := stubEnsureFirewallRule(t, collector.FirewallRule{ID: "r-eip", Network: "198.51.100.20/32"}, false, nil)

	if err := runRefreshFirewall(refreshFirewallCmd, nil); err != nil {
		t.Fatal(err)
	}
	if len(*cidrs) != 1 || (*cidrs)[0] != "198.51.100.20/32" {
		t.Fatalf("expected the stack EIP, got %v", *cidrs)
	}
}

func TestRefreshFirewallRequiresAnInstaclustrInstall(t *testing.T) {
	isolate(t)
	if err := collector.SaveState(&collector.State{AgentID: "a-1"}); err != nil {
		t.Fatal(err)
	}
	err := runRefreshFirewall(refreshFirewallCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "--provider instaclustr") {
		t.Fatalf("expected the not-an-instaclustr-install refusal, got %v", err)
	}
}

func TestRefreshFirewallRotatesTheRule(t *testing.T) {
	isolate(t)
	if err := collector.SaveState(&collector.State{
		AgentID:              "a-1",
		InstaclustrClusterID: "c-1",
		InstaclustrUsername:  "someone",
		FirewallRuleID:       "r-old",
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv(instaclustrProvisioningEnv, "key123")
	stubDiscoverInstaclustr(t, icTestTarget(), nil)
	stubPublicEgressIP(t, "192.0.2.9", nil)
	cidrs := stubEnsureFirewallRule(t, collector.FirewallRule{ID: "r-new", Network: "192.0.2.9/32"}, true, nil)
	deleted := stubDeleteFirewallRule(t, nil)

	if err := runRefreshFirewall(refreshFirewallCmd, nil); err != nil {
		t.Fatal(err)
	}
	if len(*cidrs) != 1 || (*cidrs)[0] != "192.0.2.9/32" {
		t.Fatalf("wrong CIDR ensured: %v", *cidrs)
	}
	if len(*deleted) != 1 || (*deleted)[0] != "r-old" {
		t.Fatalf("stale rule not rotated out: %v", *deleted)
	}
	st, err := collector.LoadState()
	if err != nil || st.FirewallRuleID != "r-new" {
		t.Fatalf("state not updated with the new rule: %+v err=%v", st, err)
	}
}

func TestRefreshFirewallNeverDeletesARuleItDoesNotOwn(t *testing.T) {
	isolate(t)
	if err := collector.SaveState(&collector.State{
		AgentID:              "a-1",
		InstaclustrClusterID: "c-1",
		InstaclustrUsername:  "someone",
		// No FirewallRuleID: the install found the rule pre-existing.
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv(instaclustrProvisioningEnv, "key123")
	stubDiscoverInstaclustr(t, icTestTarget(), nil)
	stubPublicEgressIP(t, "192.0.2.9", nil)
	stubEnsureFirewallRule(t, collector.FirewallRule{ID: "r-x", Network: "192.0.2.9/32"}, false, nil)
	deleted := stubDeleteFirewallRule(t, errors.New("must not be called"))

	if err := runRefreshFirewall(refreshFirewallCmd, nil); err != nil {
		t.Fatal(err)
	}
	if len(*deleted) != 0 {
		t.Fatalf("deleted a rule the CLI does not own: %v", *deleted)
	}
}

// A private-path install allowlists this machine's address ON THE CLUSTER'S
// NETWORK. refresh-firewall has to reach the same answer, or it allowlists the
// public egress address and then deletes the rule the collector is actually
// connecting through -- taking the collector down rather than keeping it up.
func TestRefreshFirewallOnAPrivateClusterKeepsThePrivateSource(t *testing.T) {
	isolate(t)
	if err := collector.SaveState(&collector.State{
		AgentID:               "a-1",
		InstaclustrClusterID:  "c-1",
		InstaclustrUsername:   "someone",
		InstaclustrUsePrivate: true,
		FirewallRuleID:        "r-private",
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv(instaclustrProvisioningEnv, "key123")
	stubDiscoverInstaclustr(t, icTestPrivateTarget(), nil)
	stubPrivatePathToCluster(t, net.ParseIP("10.10.9.9"), "this machine holds 10.10.9.9 inside 10.10.0.0/16", true)
	stubPublicEgressIP(t, "203.0.113.5", errors.New("must not be called on a private path"))
	cidrs := stubEnsureFirewallRule(t, collector.FirewallRule{ID: "r-private", Network: "10.10.9.9/32"}, false, nil)
	deleted := stubDeleteFirewallRule(t, errors.New("must not retire the collector's own rule"))

	if err := runRefreshFirewall(refreshFirewallCmd, nil); err != nil {
		t.Fatal(err)
	}
	if len(*cidrs) != 1 || (*cidrs)[0] != "10.10.9.9/32" {
		t.Fatalf("expected the private source address, got %v", *cidrs)
	}
	if len(*deleted) != 0 {
		t.Fatalf("refresh deleted the rule the collector connects through: %v", *deleted)
	}
}

// A cluster created private AFTER the install predates the recorded flag, so
// discovery -- not state alone -- has to settle the address side.
func TestRefreshFirewallReadsThePrivateSideFromDiscovery(t *testing.T) {
	isolate(t)
	if err := collector.SaveState(&collector.State{
		AgentID:              "a-1",
		InstaclustrClusterID: "c-1",
		InstaclustrUsername:  "someone",
		// No InstaclustrUsePrivate: this install predates the field.
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv(instaclustrProvisioningEnv, "key123")
	stubDiscoverInstaclustr(t, icTestPrivateTarget(), nil)
	stubPrivatePathToCluster(t, net.ParseIP("10.10.9.9"), "", false)
	stubPublicEgressIP(t, "203.0.113.5", errors.New("must not be called for a private-network cluster"))
	cidrs := stubEnsureFirewallRule(t, collector.FirewallRule{ID: "r-1", Network: "10.10.9.9/32"}, false, nil)

	if err := runRefreshFirewall(refreshFirewallCmd, nil); err != nil {
		t.Fatal(err)
	}
	if len(*cidrs) != 1 || (*cidrs)[0] != "10.10.9.9/32" {
		t.Fatalf("expected the private source address, got %v", *cidrs)
	}
}

// Discovery is an improvement to refresh-firewall, not a new requirement: a
// public install whose cluster cannot be described right now still refreshes.
func TestRefreshFirewallFallsBackToPublicEgressWhenDiscoveryFails(t *testing.T) {
	isolate(t)
	if err := collector.SaveState(&collector.State{
		AgentID:              "a-1",
		InstaclustrClusterID: "c-1",
		InstaclustrUsername:  "someone",
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv(instaclustrProvisioningEnv, "key123")
	stubDiscoverInstaclustr(t, collector.InstaclustrTarget{}, errors.New("cluster management API unavailable"))
	stubPublicEgressIP(t, "192.0.2.9", nil)
	cidrs := stubEnsureFirewallRule(t, collector.FirewallRule{ID: "r-1", Network: "192.0.2.9/32"}, false, nil)

	if err := runRefreshFirewall(refreshFirewallCmd, nil); err != nil {
		t.Fatal(err)
	}
	if len(*cidrs) != 1 || (*cidrs)[0] != "192.0.2.9/32" {
		t.Fatalf("expected the public egress address, got %v", *cidrs)
	}
}

// ...but a collector KNOWN to dial privately must not be handed the public
// address as a guess: that allowlists the wrong host and retires the right rule.
func TestRefreshFirewallRefusesToGuessWhenAPrivateClusterCannotBeDescribed(t *testing.T) {
	isolate(t)
	if err := collector.SaveState(&collector.State{
		AgentID:               "a-1",
		InstaclustrClusterID:  "c-1",
		InstaclustrUsername:   "someone",
		InstaclustrUsePrivate: true,
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv(instaclustrProvisioningEnv, "key123")
	stubDiscoverInstaclustr(t, collector.InstaclustrTarget{}, errors.New("cluster management API unavailable"))
	stubPublicEgressIP(t, "203.0.113.5", errors.New("must not be called"))
	stubEnsureFirewallRule(t, collector.FirewallRule{}, false, errors.New("must not be reached"))

	err := runRefreshFirewall(refreshFirewallCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "--allow-ip") {
		t.Fatalf("expected a refusal naming --allow-ip, got %v", err)
	}
}

// --- the gcp substrate ------------------------------------------------------

func stubGcpDeploymentOutput(t *testing.T, value string, err error) {
	t.Helper()
	orig := gcpDeploymentOutput
	gcpDeploymentOutput = func(string, string, string, string) (string, error) { return value, err }
	t.Cleanup(func() { gcpDeploymentOutput = orig })
}

// icGcpCmd mirrors the REAL flag registrations for the gcp substrate (types
// must match — see icCmd's db-name note).
func icGcpCmd(t *testing.T, apiURL string) *cobra.Command {
	t.Helper()
	cmd := icCmd(t, apiURL)
	cmd.Flags().String("project", "", "")
	cmd.Flags().String("deployment-name", collector.DefaultGcpDeploymentName, "")
	cmd.Flags().String("template-source", "", "")
	cmd.Flags().String("deploy-service-account", "", "")
	cmd.Flags().String("network", "", "")
	cmd.Flags().String("subnetwork", "", "")
	cmd.Flags().Bool("stable-egress", true, "")
	cmd.Flags().String("nat-subnet-cidr", "", "")
	cmd.Flags().String("region", "", "")
	mustSet(t, cmd, "target", "gcp")
	mustSet(t, cmd, "cluster-id", "c-1")
	mustSet(t, cmd, "instaclustr-user", "someone")
	mustSet(t, cmd, "instaclustr-api-key", "key123")
	mustSet(t, cmd, "instaclustr-readonly-key", "key456")
	mustSet(t, cmd, "deploy-service-account", "projects/acme-prod/serviceAccounts/deployer@acme-prod.iam.gserviceaccount.com")
	return cmd
}

func stubGCPOKForInstaclustr(t *testing.T) {
	t.Helper()
	stubGcpAvailable(t, nil)
	stubGcpIdentity(t, "dev@example.com", nil)
	stubGcpProject(t, "acme-prod", nil)
	stubGcpDeploymentStatus(t, "", nil)
	stubGcpSubnetworkPGA(t, true, nil)
	stubRemoteDigest(t, nil)
}

func TestInstallInstaclustrGCPStableEgressRefusesSubnetworkAndAllowIP(t *testing.T) {
	isolate(t)
	writeTokens(t)
	stubGCPOKForInstaclustr(t)
	cmd := icGcpCmd(t, "")
	mustSet(t, cmd, "region", "us-central1")
	mustSet(t, cmd, "network", "projects/acme-prod/global/networks/default")
	mustSet(t, cmd, "nat-subnet-cidr", "10.10.200.0/28")
	mustSet(t, cmd, "subnetwork", "projects/acme-prod/regions/us-central1/subnetworks/mine")
	err := runInstall(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "--subnetwork does not apply") {
		t.Fatalf("expected the subnetwork refusal, got %v", err)
	}

	cmd = icGcpCmd(t, "")
	mustSet(t, cmd, "region", "us-central1")
	mustSet(t, cmd, "network", "projects/acme-prod/global/networks/default")
	mustSet(t, cmd, "nat-subnet-cidr", "10.10.200.0/28")
	mustSet(t, cmd, "allow-ip", "203.0.113.7")
	err = runInstall(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "--allow-ip does not apply") {
		t.Fatalf("expected the allow-ip refusal, got %v", err)
	}
}

func TestInstallInstaclustrGCPRequiresRegionAndNetwork(t *testing.T) {
	isolate(t)
	writeTokens(t)
	stubGCPOKForInstaclustr(t)
	cmd := icGcpCmd(t, "")
	err := runInstall(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "--region is required") {
		t.Fatalf("expected the region requirement, got %v", err)
	}
	mustSet(t, cmd, "region", "us-central1")
	err = runInstall(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "--network is required") {
		t.Fatalf("expected the network requirement, got %v", err)
	}
}

func TestInstallInstaclustrGCPStableEgressNeedsCidr(t *testing.T) {
	isolate(t)
	writeTokens(t)
	stubGCPOKForInstaclustr(t)
	cmd := icGcpCmd(t, "")
	mustSet(t, cmd, "region", "us-central1")
	mustSet(t, cmd, "network", "projects/acme-prod/global/networks/default")
	err := runInstall(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "--nat-subnet-cidr is required") {
		t.Fatalf("expected the stable-egress requirement, got %v", err)
	}
}

func TestInstallInstaclustrGCPNoStableEgressNeedsAllowIP(t *testing.T) {
	isolate(t)
	writeTokens(t)
	stubGCPOKForInstaclustr(t)
	cmd := icGcpCmd(t, "")
	mustSet(t, cmd, "region", "us-central1")
	mustSet(t, cmd, "network", "projects/acme-prod/global/networks/default")
	mustSet(t, cmd, "stable-egress", "false")
	err := runInstall(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "needs --allow-ip") {
		t.Fatalf("expected the allow-ip requirement, got %v", err)
	}
}

func TestInstallInstaclustrGCPHappyPath(t *testing.T) {
	isolate(t)
	writeTokens(t)
	srv := installServer(t, "a-1")
	defer srv.Close()
	stubGCPOKForInstaclustr(t)
	stubDiscoverInstaclustr(t, icTestTarget(), nil)
	stubPublicEgressIP(t, "192.0.2.9", nil) // the operator's machine
	rec := stubGcpDeploy(t, nil)
	stubGcpDeploymentOutput(t, "198.51.100.20", nil) // the reserved static address
	roleRuns := stubCreateInstaclustrRole(t, nil)
	deleted := stubDeleteFirewallRule(t, nil)

	// ensureFirewallRule is called twice: the operator's temp rule (created)
	// and the egress-address rule. Distinct ids so the temp-rule cleanup and
	// the ownership recording are distinguishable.
	var cidrs []string
	origEnsure := ensureFirewallRule
	ensureFirewallRule = func(_ context.Context, _ collector.InstaclustrCreds, _ string, cidr string) (collector.FirewallRule, bool, error) {
		cidrs = append(cidrs, cidr)
		if cidr == "192.0.2.9/32" {
			return collector.FirewallRule{ID: "r-operator", Network: cidr}, true, nil
		}
		return collector.FirewallRule{ID: "r-egress", Network: cidr}, true, nil
	}
	t.Cleanup(func() { ensureFirewallRule = origEnsure })

	cmd := icGcpCmd(t, srv.URL)
	mustSet(t, cmd, "region", "us-central1")
	mustSet(t, cmd, "network", "projects/acme-prod/global/networks/default")
	mustSet(t, cmd, "nat-subnet-cidr", "10.10.200.0/28")

	if err := runInstall(cmd, nil); err != nil {
		t.Fatal(err)
	}
	if len(*roleRuns) != 1 {
		t.Fatalf("role not ensured exactly once: %v", *roleRuns)
	}
	if rec.count != 1 || rec.deploy.Inputs["stable_egress"] != "true" ||
		rec.deploy.Inputs["nat_subnet_cidr"] != "10.10.200.0/28" {
		t.Fatalf("deploy inputs wrong: count=%d inputs=%v", rec.count, rec.deploy.Inputs)
	}
	if rec.secretsWritten != 1 || rec.secrets.InstaclustrKey != "key456" || rec.secrets.DBPassword == "" {
		t.Fatalf("the credentials must be written to Secret Manager before the deploy: %+v", rec.secrets)
	}
	if rec.deploy.Inputs["instaclustr_api_key"] != "" {
		t.Fatal("the API key must never enter the deployment's input values")
	}
	if len(cidrs) != 2 || cidrs[0] != "192.0.2.9/32" || cidrs[1] != "198.51.100.20/32" {
		t.Fatalf("expected operator rule then egress rule, got %v", cidrs)
	}
	if len(*deleted) != 1 || (*deleted)[0] != "r-operator" {
		t.Fatalf("operator temp rule not cleaned up: %v", *deleted)
	}
	st, err := collector.LoadState()
	if err != nil || st == nil {
		t.Fatalf("no state: %v", err)
	}
	if !st.IsGCP() || st.InstaclustrClusterID != "c-1" || st.FirewallRuleID != "r-egress" ||
		st.Project != "acme-prod" || st.DeploymentName != collector.DefaultGcpDeploymentName {
		t.Fatalf("state wrong: %+v", st)
	}
}

func TestInstallInstaclustrGCPDryRunMutatesNothing(t *testing.T) {
	isolate(t)
	writeTokens(t)
	srv := installServer(t, "a-1")
	defer srv.Close()
	stubGCPOKForInstaclustr(t)
	stubDiscoverInstaclustr(t, icTestTarget(), nil)
	rec := stubGcpDeploy(t, nil)
	cidrs := stubEnsureFirewallRule(t, collector.FirewallRule{}, false, errors.New("must not be called"))
	roleRuns := stubCreateInstaclustrRole(t, errors.New("must not be called"))

	cmd := icGcpCmd(t, srv.URL)
	mustSet(t, cmd, "region", "us-central1")
	mustSet(t, cmd, "network", "projects/acme-prod/global/networks/default")
	mustSet(t, cmd, "nat-subnet-cidr", "10.10.200.0/28")
	mustSet(t, cmd, "dry-run", "true")

	out := capture(t, func() {
		if err := runInstall(cmd, nil); err != nil {
			t.Errorf("dry run failed: %v", err)
		}
	})
	if len(*cidrs) != 0 || len(*roleRuns) != 0 {
		t.Fatalf("dry run mutated: firewall=%v role=%v", *cidrs, *roleRuns)
	}
	if st, _ := collector.LoadState(); st != nil {
		t.Fatalf("dry run saved state: %+v", st)
	}
	if rec.count != 1 || !rec.deploy.DryRun {
		t.Fatalf("expected exactly one dry-run deploy probe, got count=%d dryRun=%v", rec.count, rec.deploy.DryRun)
	}
	if strings.Contains(out, "key123") || strings.Contains(out, "key456") {
		t.Fatalf("a credential leaked into the dry-run output:\n%s", out)
	}
}

func TestRefreshFirewallOnGCPUsesTheDeploymentEgressIP(t *testing.T) {
	isolate(t)
	if err := collector.SaveState(&collector.State{
		AgentID: "a-1", Target: "gcp", Project: "acme-prod", Region: "us-central1",
		DeploymentName:       "dbgorilla-collector",
		InstaclustrClusterID: "c-1", InstaclustrUsername: "someone",
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv(instaclustrProvisioningEnv, "key123")
	stubGcpDeploymentOutput(t, "198.51.100.20", nil)
	stubPublicEgressIP(t, "192.0.2.9", errors.New("must not be called for a gcp install"))
	cidrs := stubEnsureFirewallRule(t, collector.FirewallRule{ID: "r-egress", Network: "198.51.100.20/32"}, false, nil)

	if err := runRefreshFirewall(refreshFirewallCmd, nil); err != nil {
		t.Fatal(err)
	}
	if len(*cidrs) != 1 || (*cidrs)[0] != "198.51.100.20/32" {
		t.Fatalf("expected the deployment's static address, got %v", *cidrs)
	}
}
