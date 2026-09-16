package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// SecurityGroupRule is one entry on a cluster's security-group allowlist.
//
// A security-group rule allowlists traffic by its *source security group*
// rather than by address. AWS matches those against the source's private
// address only — never a public or Elastic IP — so a collector allowlisted
// this way has to dial the cluster's private node addresses.
type SecurityGroupRule struct {
	ID              string `json:"id,omitempty"`
	SecurityGroupID string `json:"securityGroupId"`
	Type            string `json:"type"`
}

// clusterSecurityGroupRules is the cluster-scoped resource. Its rule set is
// read and written whole: there is no per-rule endpoint that is not deprecated.
type clusterSecurityGroupRules struct {
	ClusterID     string              `json:"clusterId"`
	FirewallRules []SecurityGroupRule `json:"firewallRules"`
}

// securityGroupRulesPath is the non-deprecated, cluster-scoped resource.
//
// Only GET, PUT and DELETE exist here. POST is *not* an add: it answers 202 and
// silently does nothing, echoing the unchanged resource rather than a created
// rule — it does so even for a malformed security group id, or for a body with
// no security group at all. Treating that 202 as success is the trap this path
// exists to avoid.
func securityGroupRulesPath(clusterID string) string {
	return "/cluster-management/v2/resources/providers/aws/cluster-security-group-firewall-rules/v2/" + clusterID
}

// ListInstaclustrSecurityGroupRules returns the cluster's security-group
// allowlist. A cluster that has never had one answers with an empty set, not a
// 404.
func ListInstaclustrSecurityGroupRules(ctx context.Context, creds InstaclustrCreds, clusterID string) ([]SecurityGroupRule, error) {
	var out clusterSecurityGroupRules
	if err := icGetJSON(ctx, creds, securityGroupRulesPath(clusterID), &out); err != nil {
		return nil, err
	}
	return out.FirewallRules, nil
}

// putSecurityGroupRules replaces the cluster's entire security-group rule set
// and returns the set the API reports afterwards, which carries the id assigned
// to any newly created rule.
//
// Every caller must pass the rules it wants to survive, not just the one it is
// changing — this endpoint is a replacement, so an omitted rule is a deleted
// rule. That is why nothing outside this file calls it directly.
func putSecurityGroupRules(ctx context.Context, creds InstaclustrCreds, clusterID string, rules []SecurityGroupRule) ([]SecurityGroupRule, error) {
	if rules == nil {
		rules = []SecurityGroupRule{}
	}
	body, err := json.Marshal(clusterSecurityGroupRules{ClusterID: clusterID, FirewallRules: rules})
	if err != nil {
		return nil, fmt.Errorf("cannot encode security-group rule set: %w", err)
	}
	data, err := icSend(ctx, creds, http.MethodPut, securityGroupRulesPath(clusterID), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	var out clusterSecurityGroupRules
	if jerr := json.Unmarshal(data, &out); jerr != nil {
		// The write was accepted; only the echo was unreadable. Re-read rather
		// than reporting a failure the caller would roll back.
		return ListInstaclustrSecurityGroupRules(ctx, creds, clusterID)
	}
	return out.FirewallRules, nil
}

// EnsureSecurityGroupRule makes sure securityGroupID is allowlisted for
// PostgreSQL, returning the rule and whether this call created it (so a
// temporary rule can be retired later without touching one that pre-existed).
//
// Rules belonging to anyone else are carried through untouched.
func EnsureSecurityGroupRule(ctx context.Context, creds InstaclustrCreds, clusterID, securityGroupID string) (SecurityGroupRule, bool, error) {
	existing, err := ListInstaclustrSecurityGroupRules(ctx, creds, clusterID)
	if err != nil {
		return SecurityGroupRule{}, false, err
	}
	for _, r := range existing {
		if r.Type == firewallRuleTypePostgreSQL && r.SecurityGroupID == securityGroupID {
			return r, false, nil
		}
	}

	want := SecurityGroupRule{SecurityGroupID: securityGroupID, Type: firewallRuleTypePostgreSQL}
	after, err := putSecurityGroupRules(ctx, creds, clusterID, append(cloneRules(existing), want))
	if err != nil {
		return SecurityGroupRule{}, false, err
	}
	for _, r := range after {
		if r.Type == firewallRuleTypePostgreSQL && r.SecurityGroupID == securityGroupID {
			return r, true, nil
		}
	}
	// The PUT reported success but our rule is absent. Silent no-ops are the
	// documented failure mode of this API family, so say so rather than
	// returning an id-less rule that refresh-firewall could never reconcile.
	return SecurityGroupRule{}, false, fmt.Errorf(
		"instaclustr accepted the security-group rule for %s but it is not present on read-back — "+
			"check the cluster's Firewall Rules page", securityGroupID)
}

// RemoveSecurityGroupRule retires one rule by id, preserving every other rule
// on the cluster.
//
// It deliberately does not use the cluster-level DELETE, which removes *all*
// security-group rules including ones this CLI never created.
func RemoveSecurityGroupRule(ctx context.Context, creds InstaclustrCreds, clusterID, ruleID string) error {
	existing, err := ListInstaclustrSecurityGroupRules(ctx, creds, clusterID)
	if err != nil {
		return err
	}
	keep := make([]SecurityGroupRule, 0, len(existing))
	found := false
	for _, r := range existing {
		if r.ID == ruleID {
			found = true
			continue
		}
		keep = append(keep, r)
	}
	if !found {
		return nil // already gone — converged
	}
	_, err = putSecurityGroupRules(ctx, creds, clusterID, keep)
	return err
}

// cloneRules copies a rule set so appending to it cannot write through to the
// caller's slice.
func cloneRules(in []SecurityGroupRule) []SecurityGroupRule {
	out := make([]SecurityGroupRule, len(in))
	copy(out, in)
	return out
}
