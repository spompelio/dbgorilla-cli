package collector

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const sgPath = "/cluster-management/v2/resources/providers/aws/cluster-security-group-firewall-rules/v2/c-1"

var sgCreds = InstaclustrCreds{Username: "u", APIKey: "key123"}

// sgSet renders the cluster-scoped resource the API returns.
func sgSet(rules ...string) string {
	var b strings.Builder
	b.WriteString(`{"clusterId":"c-1","id":"c-1","status":"RUNNING","firewallRules":[`)
	b.WriteString(strings.Join(rules, ","))
	b.WriteString(`]}`)
	return b.String()
}

func sgRule(id, sg string) string {
	return `{"id":"` + id + `","securityGroupId":"` + sg + `","type":"POSTGRESQL"}`
}

// putBody decodes the single PUT the test expects to have been sent.
func putBody(t *testing.T, fake *icFake) clusterSecurityGroupRules {
	t.Helper()
	if len(fake.bodies) != 1 {
		t.Fatalf("expected exactly one write, got %d: %v", len(fake.bodies), fake.calls)
	}
	var got clusterSecurityGroupRules
	if err := json.Unmarshal([]byte(fake.bodies[0]), &got); err != nil {
		t.Fatalf("PUT body is not valid JSON: %v\n%s", err, fake.bodies[0])
	}
	return got
}

func sgIDs(rules []SecurityGroupRule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.SecurityGroupID)
	}
	return out
}

func TestEnsureSecurityGroupRuleAddsToEmptySet(t *testing.T) {
	fake := stubInstaclustr(t, map[string]icResp{
		"GET " + sgPath: {http.StatusOK, sgSet()},
		"PUT " + sgPath: {http.StatusAccepted, sgSet(sgRule("r-1", "sg-aaa"))},
	})

	rule, created, err := EnsureSecurityGroupRule(context.Background(), sgCreds, "c-1", "sg-aaa")
	if err != nil {
		t.Fatalf("EnsureSecurityGroupRule: %v", err)
	}
	if !created {
		t.Error("expected created=true for a rule that did not exist")
	}
	if rule.ID != "r-1" {
		t.Errorf("rule id = %q, want r-1 (an id-less rule cannot be reconciled later)", rule.ID)
	}
	if got := sgIDs(putBody(t, fake).FirewallRules); len(got) != 1 || got[0] != "sg-aaa" {
		t.Errorf("PUT sent %v, want [sg-aaa]", got)
	}
}

// The endpoint replaces the whole set, so anything omitted is deleted. Rules
// this CLI does not own must survive.
func TestEnsureSecurityGroupRulePreservesOtherRules(t *testing.T) {
	fake := stubInstaclustr(t, map[string]icResp{
		"GET " + sgPath: {http.StatusOK, sgSet(sgRule("r-9", "sg-theirs"), sgRule("r-8", "sg-alsotheirs"))},
		"PUT " + sgPath: {http.StatusAccepted, sgSet(
			sgRule("r-9", "sg-theirs"), sgRule("r-8", "sg-alsotheirs"), sgRule("r-1", "sg-ours"))},
	})

	if _, _, err := EnsureSecurityGroupRule(context.Background(), sgCreds, "c-1", "sg-ours"); err != nil {
		t.Fatalf("EnsureSecurityGroupRule: %v", err)
	}
	got := sgIDs(putBody(t, fake).FirewallRules)
	for _, want := range []string{"sg-theirs", "sg-alsotheirs", "sg-ours"} {
		if !contains(got, want) {
			t.Errorf("PUT dropped %s; sent %v", want, got)
		}
	}
	if len(got) != 3 {
		t.Errorf("PUT sent %d rules, want 3: %v", len(got), got)
	}
}

func TestEnsureSecurityGroupRuleIsIdempotent(t *testing.T) {
	fake := stubInstaclustr(t, map[string]icResp{
		"GET " + sgPath: {http.StatusOK, sgSet(sgRule("r-1", "sg-ours"))},
	})

	rule, created, err := EnsureSecurityGroupRule(context.Background(), sgCreds, "c-1", "sg-ours")
	if err != nil {
		t.Fatalf("EnsureSecurityGroupRule: %v", err)
	}
	if created {
		t.Error("expected created=false when the rule already exists")
	}
	if rule.ID != "r-1" {
		t.Errorf("rule id = %q, want the existing r-1", rule.ID)
	}
	if m := fake.mutations(); len(m) != 0 {
		t.Errorf("an already-present rule must not write: %v", m)
	}
}

// A PUT that reports success without our rule is this API family's documented
// silent no-op. It must surface, not return an id-less rule.
func TestEnsureSecurityGroupRuleRejectsSilentNoOp(t *testing.T) {
	stubInstaclustr(t, map[string]icResp{
		"GET " + sgPath: {http.StatusOK, sgSet()},
		"PUT " + sgPath: {http.StatusAccepted, sgSet()}, // accepted, changed nothing
	})

	_, _, err := EnsureSecurityGroupRule(context.Background(), sgCreds, "c-1", "sg-ours")
	if err == nil {
		t.Fatal("expected an error when the rule is absent on read-back")
	}
	if !strings.Contains(err.Error(), "sg-ours") {
		t.Errorf("error should name the security group, got: %v", err)
	}
}

func TestRemoveSecurityGroupRuleKeepsTheRest(t *testing.T) {
	fake := stubInstaclustr(t, map[string]icResp{
		"GET " + sgPath: {http.StatusOK, sgSet(sgRule("r-9", "sg-theirs"), sgRule("r-1", "sg-ours"))},
		"PUT " + sgPath: {http.StatusAccepted, sgSet(sgRule("r-9", "sg-theirs"))},
	})

	if err := RemoveSecurityGroupRule(context.Background(), sgCreds, "c-1", "r-1"); err != nil {
		t.Fatalf("RemoveSecurityGroupRule: %v", err)
	}
	got := sgIDs(putBody(t, fake).FirewallRules)
	if len(got) != 1 || got[0] != "sg-theirs" {
		t.Errorf("PUT sent %v, want [sg-theirs]", got)
	}
	// The cluster-level DELETE removes every rule on the cluster, including
	// ones other actors created.
	for _, c := range fake.calls {
		if strings.HasPrefix(c, "DELETE ") {
			t.Errorf("must never call the cluster-level DELETE, saw %q", c)
		}
	}
}

func TestRemoveSecurityGroupRuleConvergesWhenAlreadyGone(t *testing.T) {
	fake := stubInstaclustr(t, map[string]icResp{
		"GET " + sgPath: {http.StatusOK, sgSet(sgRule("r-9", "sg-theirs"))},
	})

	if err := RemoveSecurityGroupRule(context.Background(), sgCreds, "c-1", "r-gone"); err != nil {
		t.Fatalf("removing an absent rule should converge, got: %v", err)
	}
	if m := fake.mutations(); len(m) != 0 {
		t.Errorf("removing an absent rule must not write: %v", m)
	}
}

// POST on this resource answers 202 and does nothing, so the client must never
// reach for it.
func TestSecurityGroupRulesNeverPost(t *testing.T) {
	fake := stubInstaclustr(t, map[string]icResp{
		"GET " + sgPath: {http.StatusOK, sgSet()},
		"PUT " + sgPath: {http.StatusAccepted, sgSet(sgRule("r-1", "sg-ours"))},
	})

	if _, _, err := EnsureSecurityGroupRule(context.Background(), sgCreds, "c-1", "sg-ours"); err != nil {
		t.Fatalf("EnsureSecurityGroupRule: %v", err)
	}
	for _, c := range fake.calls {
		if strings.HasPrefix(c, "POST ") {
			t.Errorf("POST is a silent no-op on this resource, saw %q", c)
		}
	}
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
