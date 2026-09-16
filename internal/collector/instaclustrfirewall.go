package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// firewallRuleTypePostgreSQL is the allowlist entry kind the collector needs.
// Instaclustr's FirewallRuleTypesV2 also carries PGBOUNCER, which nothing here
// opens.
const firewallRuleTypePostgreSQL = "POSTGRESQL"

// FirewallRule is one entry on a cluster's PostgreSQL allowlist.
type FirewallRule struct {
	ID        string `json:"id"`
	ClusterID string `json:"clusterId"`
	Network   string `json:"network"`
	Type      string `json:"type"`
	Status    string `json:"status"`
}

// ListInstaclustrFirewallRules returns the cluster's current allowlist.
func ListInstaclustrFirewallRules(ctx context.Context, creds InstaclustrCreds, clusterID string) ([]FirewallRule, error) {
	var out []struct {
		FirewallRules []FirewallRule `json:"firewallRules"`
	}
	path := "/cluster-management/v2/data-sources/cluster/" + clusterID + "/network-firewall-rules/v2"
	if err := icGetJSON(ctx, creds, path, &out); err != nil {
		return nil, err
	}
	var rules []FirewallRule
	for _, entry := range out {
		rules = append(rules, entry.FirewallRules...)
	}
	return rules, nil
}

// AddInstaclustrFirewallRule allowlists one CIDR for PostgreSQL. A duplicate
// (their API answers 409) converges by re-listing to find the real rule —
// callers record rule IDs for ownership, and a synthetic empty-ID rule would
// silently break refresh-firewall's rotation later.
func AddInstaclustrFirewallRule(ctx context.Context, creds InstaclustrCreds, clusterID, cidr string) (FirewallRule, error) {
	body := fmt.Sprintf(`{"clusterId":%q,"network":%q,"type":%q}`, clusterID, cidr, firewallRuleTypePostgreSQL)
	data, err := icSend(ctx, creds, http.MethodPost, "/cluster-management/v2/resources/network-firewall-rules/v2/", strings.NewReader(body))
	if err != nil {
		if icStatus(err) == http.StatusConflict {
			return findFirewallRule(ctx, creds, clusterID, cidr)
		}
		return FirewallRule{}, err
	}
	var rule FirewallRule
	if jerr := json.Unmarshal(data, &rule); jerr != nil || rule.ID == "" {
		return findFirewallRule(ctx, creds, clusterID, cidr)
	}
	return rule, nil
}

// findFirewallRule re-lists and returns the rule matching cidr — the
// convergence path for duplicate creates and unparseable create responses.
func findFirewallRule(ctx context.Context, creds InstaclustrCreds, clusterID, cidr string) (FirewallRule, error) {
	rules, err := ListInstaclustrFirewallRules(ctx, creds, clusterID)
	if err != nil {
		return FirewallRule{}, err
	}
	for _, r := range rules {
		if r.Type == firewallRuleTypePostgreSQL && r.Network == cidr {
			return r, nil
		}
	}
	return FirewallRule{}, fmt.Errorf("firewall rule for %s exists per the API but was not found on re-list — "+
		"check the cluster's Firewall Rules page", cidr)
}

// DeleteInstaclustrFirewallRule removes one rule by id.
func DeleteInstaclustrFirewallRule(ctx context.Context, creds InstaclustrCreds, ruleID string) error {
	_, err := icSend(ctx, creds, http.MethodDelete, "/cluster-management/v2/resources/network-firewall-rules/v2/"+ruleID, nil)
	if errors.Is(err, errICNotFound) {
		return nil // already gone — converged
	}
	return err
}

// EnsureFirewallRule makes sure cidr is allowlisted, returning the rule and
// whether this call created it (so a temporary operator rule can be removed
// afterwards without touching one that pre-existed).
func EnsureFirewallRule(ctx context.Context, creds InstaclustrCreds, clusterID, cidr string) (FirewallRule, bool, error) {
	rules, err := ListInstaclustrFirewallRules(ctx, creds, clusterID)
	if err != nil {
		return FirewallRule{}, false, err
	}
	for _, r := range rules {
		if r.Type == firewallRuleTypePostgreSQL && r.Network == cidr {
			return r, false, nil
		}
	}
	rule, err := AddInstaclustrFirewallRule(ctx, creds, clusterID, cidr)
	if err != nil {
		return FirewallRule{}, false, err
	}
	return rule, true, nil
}
