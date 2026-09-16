package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/dbgorilla/dbgorilla-cli/internal/collector"
)

// stubEnsureSGRule records the security groups the command asked to allowlist.
func stubEnsureSGRule(t *testing.T, rule collector.SecurityGroupRule, created bool, err error) *[]string {
	t.Helper()
	var groups []string
	orig := ensureSGRule
	ensureSGRule = func(_ context.Context, _ collector.InstaclustrCreds, _ string, sg string) (collector.SecurityGroupRule, bool, error) {
		groups = append(groups, sg)
		return rule, created, err
	}
	t.Cleanup(func() { ensureSGRule = orig })
	return &groups
}

func sgState(t *testing.T, ruleID string) {
	t.Helper()
	if err := collector.SaveState(&collector.State{
		AgentID: "a-1", Target: "aws", StackName: "s", Region: "us-east-1",
		InstaclustrClusterID:     "c-1",
		InstaclustrUsername:      "someone",
		CollectorSecurityGroupID: "sg-collector",
		SecurityGroupRuleID:      ruleID,
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv(instaclustrProvisioningEnv, "key123")
}

// The security-group primitive exists so a redeploy costs nothing: the entry
// names a group, not an address, so nothing has to be re-detected.
func TestRefreshFirewallWithSecurityGroupDetectsNoIP(t *testing.T) {
	isolate(t)
	sgState(t, "r-1")
	stubPublicEgressIP(t, "192.0.2.9", errors.New("must not detect an IP for a security-group allowlist"))
	stubStackOutput(t, "", errors.New("must not read the stack egress IP for a security-group allowlist"))
	cidrs := stubEnsureFirewallRule(t, collector.FirewallRule{}, false, errors.New("must not touch the CIDR allowlist"))
	groups := stubEnsureSGRule(t, collector.SecurityGroupRule{ID: "r-1", SecurityGroupID: "sg-collector"}, false, nil)

	if err := runRefreshFirewall(refreshFirewallCmd, nil); err != nil {
		t.Fatalf("runRefreshFirewall: %v", err)
	}
	if len(*groups) != 1 || (*groups)[0] != "sg-collector" {
		t.Fatalf("expected the collector security group, got %v", *groups)
	}
	if len(*cidrs) != 0 {
		t.Fatalf("the CIDR path must not run, got %v", *cidrs)
	}
}

// Re-asserting a rule we already own returns created=false. Keying ownership
// off that alone would forget the rule and orphan it at uninstall.
func TestRefreshFirewallKeepsSecurityGroupRuleOwnership(t *testing.T) {
	isolate(t)
	sgState(t, "r-1")
	stubEnsureSGRule(t, collector.SecurityGroupRule{ID: "r-1", SecurityGroupID: "sg-collector"}, false, nil)

	if err := runRefreshFirewall(refreshFirewallCmd, nil); err != nil {
		t.Fatalf("runRefreshFirewall: %v", err)
	}
	st, err := collector.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if st.SecurityGroupRuleID != "r-1" {
		t.Errorf("ownership of r-1 was dropped on a no-op refresh, state has %q", st.SecurityGroupRuleID)
	}
}

// A rule that is present under an id we never recorded belongs to somebody
// else, and must not be claimed.
func TestRefreshFirewallDoesNotClaimAForeignSecurityGroupRule(t *testing.T) {
	isolate(t)
	sgState(t, "")
	stubEnsureSGRule(t, collector.SecurityGroupRule{ID: "r-theirs", SecurityGroupID: "sg-collector"}, false, nil)

	if err := runRefreshFirewall(refreshFirewallCmd, nil); err != nil {
		t.Fatalf("runRefreshFirewall: %v", err)
	}
	st, err := collector.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if st.SecurityGroupRuleID != "" {
		t.Errorf("claimed a rule the CLI did not create: %q", st.SecurityGroupRuleID)
	}
}

func TestRefreshFirewallRecordsANewlyCreatedSecurityGroupRule(t *testing.T) {
	isolate(t)
	sgState(t, "")
	stubEnsureSGRule(t, collector.SecurityGroupRule{ID: "r-new", SecurityGroupID: "sg-collector"}, true, nil)

	if err := runRefreshFirewall(refreshFirewallCmd, nil); err != nil {
		t.Fatalf("runRefreshFirewall: %v", err)
	}
	st, err := collector.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if st.SecurityGroupRuleID != "r-new" {
		t.Errorf("SecurityGroupRuleID = %q, want r-new", st.SecurityGroupRuleID)
	}
}

// --allow-ip has no meaning once the allowlist keys on a security group, and
// silently ignoring it would leave the operator believing they pinned an
// address.
func TestRefreshFirewallRefusesAllowIPWithASecurityGroup(t *testing.T) {
	isolate(t)
	sgState(t, "r-1")
	if err := refreshFirewallCmd.Flags().Set("allow-ip", "192.0.2.9"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = refreshFirewallCmd.Flags().Set("allow-ip", "") })

	err := runRefreshFirewall(refreshFirewallCmd, nil)
	if err == nil {
		t.Fatal("expected --allow-ip to be refused for a security-group allowlist")
	}
	if !strings.Contains(err.Error(), "sg-collector") {
		t.Errorf("the refusal should name the security group, got: %v", err)
	}
}

// The CIDR path has the same ownership hazard: a refresh where the address has
// not changed re-asserts the rule we already own and gets created=false back.
// Ownership must survive that, or uninstall stops naming the rule it created.
func TestRefreshFirewallKeepsCIDRRuleOwnershipOnANoOpRefresh(t *testing.T) {
	isolate(t)
	if err := collector.SaveState(&collector.State{
		AgentID: "a-1", InstaclustrClusterID: "c-1", InstaclustrUsername: "someone",
		FirewallRuleID: "r-ours",
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv(instaclustrProvisioningEnv, "key123")
	stubPublicEgressIP(t, "192.0.2.9", nil)
	// Same address as last time, so the rule already exists: created=false.
	stubEnsureFirewallRule(t, collector.FirewallRule{ID: "r-ours", Network: "192.0.2.9/32"}, false, nil)
	deleted := stubDeleteFirewallRule(t, nil)

	if err := runRefreshFirewall(refreshFirewallCmd, nil); err != nil {
		t.Fatalf("runRefreshFirewall: %v", err)
	}
	if len(*deleted) != 0 {
		t.Errorf("nothing should have been retired, deleted %v", *deleted)
	}
	st, err := collector.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if st.FirewallRuleID != "r-ours" {
		t.Errorf("ownership of r-ours was dropped on a no-op refresh, state has %q", st.FirewallRuleID)
	}
}
