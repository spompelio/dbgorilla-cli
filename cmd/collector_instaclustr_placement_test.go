package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/dbgorilla/dbgorilla-cli/internal/collector"
)

// byocTarget is icTestTarget in the customer's own account, with a VPC
// reported — the shape that makes VPC-resident placement possible.
func byocTarget() collector.InstaclustrTarget {
	t := icTestTarget()
	t.ProviderAccountName = "dbgorilla-byoc"
	t.VpcID = "vpc-1"
	t.DataCentreID = "dc-1"
	return t
}

func stubVPCPlacement(t *testing.T, p collector.VPCPlacement, problems []collector.PlacementProblem, err error) {
	t.Helper()
	orig := discoverVPCPlacement
	discoverVPCPlacement = func(_ context.Context, _, _ string, _ []string) (collector.VPCPlacement, []collector.PlacementProblem, error) {
		return p, problems, err
	}
	t.Cleanup(func() { discoverVPCPlacement = orig })
}

func fixtureVPCPlacement() collector.VPCPlacement {
	return collector.VPCPlacement{
		VpcID: "vpc-1",
		Subnets: []collector.CollectorSubnet{
			{ID: "subnet-a", CIDR: "10.10.0.0/18", AZ: "us-east-1a", VpcID: "vpc-1",
				InternetRoute: "igw-1", NeedsPublicIP: true},
			{ID: "subnet-b", CIDR: "10.10.64.0/18", AZ: "us-east-1b", VpcID: "vpc-1",
				InternetRoute: "igw-1", NeedsPublicIP: true},
		},
	}
}

// A BYOC cluster needs no networking flags: the VPC comes from the cluster.
func TestResolveAWSPlacementDiscoversTheClusterVPC(t *testing.T) {
	isolate(t)
	stubVPCPlacement(t, fixtureVPCPlacement(), nil, nil)
	cmd := icAwsCmd(t, "")

	p, err := resolveAWSPlacement(context.Background(), cmd, byocTarget(), "us-east-1", "stack", true)
	if err != nil {
		t.Fatalf("resolveAWSPlacement: %v", err)
	}
	if !p.vpcResident() {
		t.Fatal("a BYOC cluster with a VPC should place the collector inside it")
	}
	if len(p.subnets) != 2 {
		t.Errorf("subnets = %v, want both discovered", p.subnets)
	}
	if !p.collectorUsePrivate {
		t.Error("a collector inside the VPC must dial private addresses, or its SG rule cannot match")
	}
	if p.stableEgress {
		t.Error("stable egress buys nothing when the allowlist names a security group")
	}
	// An internet-gateway subnet blackholes a task with no public address, and
	// the task still has to pull its image and reach DBGorilla.
	if p.assignPublicIP != "ENABLED" {
		t.Errorf("assignPublicIP = %q, want ENABLED for an IGW-routed subnet", p.assignPublicIP)
	}
}

// Explicit networking keeps the peered shape and every existing install working.
func TestResolveAWSPlacementHonoursExplicitNetworking(t *testing.T) {
	isolate(t)
	stubVPCPlacement(t, collector.VPCPlacement{}, nil,
		errTestDiscoveryMustNotRun)
	cmd := icAwsCmd(t, "")
	mustSet(t, cmd, "subnets", "subnet-mine")
	mustSet(t, cmd, "security-group-id", "sg-mine")
	mustSet(t, cmd, "stable-egress", "false")
	mustSet(t, cmd, "allow-ip", "192.0.2.9")

	p, err := resolveAWSPlacement(context.Background(), cmd, byocTarget(), "us-east-1", "stack", true)
	if err != nil {
		t.Fatalf("resolveAWSPlacement: %v", err)
	}
	if p.vpcResident() {
		t.Fatal("explicit subnets must win over discovery")
	}
	if p.subnets[0] != "subnet-mine" || p.securityGroup != "sg-mine" {
		t.Errorf("got %v / %q", p.subnets, p.securityGroup)
	}
}

var errTestDiscoveryMustNotRun = &collector.PlacementProblem{
	Kind: "test", Detail: "discovery must not run when networking is explicit",
}

// The two flags that contradict VPC-resident placement are refused with the
// reason, not silently ignored.
func TestResolveAWSPlacementRefusesContradictoryFlags(t *testing.T) {
	t.Run("stable egress", func(t *testing.T) {
		isolate(t)
		stubVPCPlacement(t, fixtureVPCPlacement(), nil, nil)
		cmd := icAwsCmd(t, "")
		mustSet(t, cmd, "stable-egress", "true")

		_, err := resolveAWSPlacement(context.Background(), cmd, byocTarget(), "us-east-1", "stack", true)
		if err == nil || !strings.Contains(err.Error(), "--stable-egress does not apply") {
			t.Fatalf("expected the stable-egress refusal, got %v", err)
		}
	})

	t.Run("public addressing", func(t *testing.T) {
		isolate(t)
		stubVPCPlacement(t, fixtureVPCPlacement(), nil, nil)
		cmd := icAwsCmd(t, "")
		mustSet(t, cmd, "use-private-addresses", "false")

		_, err := resolveAWSPlacement(context.Background(), cmd, byocTarget(), "us-east-1", "stack", true)
		if err == nil {
			t.Fatal("expected --use-private-addresses=false to be refused")
		}
		// The reason matters: an operator who does not know about the hairpin
		// will just retry with the same flag.
		if !strings.Contains(err.Error(), "internet gateway") {
			t.Errorf("the refusal should explain the hairpin, got: %v", err)
		}
	})
}

// A placement that cannot work is refused with every problem and its fix, so a
// second failure is not discovered by re-running.
func TestResolveAWSPlacementReportsPreflightProblems(t *testing.T) {
	isolate(t)
	stubVPCPlacement(t, fixtureVPCPlacement(), []collector.PlacementProblem{
		{Kind: collector.SubnetHasNoEgress, Detail: "subnet-a has no default route", Fix: "add a route"},
		{Kind: collector.SubnetOutsideClusterVPC, Detail: "subnet-z is elsewhere", Fix: "use vpc-1"},
	}, nil)
	cmd := icAwsCmd(t, "")

	_, err := resolveAWSPlacement(context.Background(), cmd, byocTarget(), "us-east-1", "stack", true)
	if err == nil {
		t.Fatal("expected the placement to be refused")
	}
	for _, want := range []string{"subnet-a has no default route", "add a route", "subnet-z is elsewhere", "use vpc-1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal should carry %q, got:\n%v", want, err)
		}
	}
}

// An Instaclustr-hosted cluster has no VPC of ours to discover.
func TestResolveAWSPlacementStillRequiresFlagsForHostedClusters(t *testing.T) {
	isolate(t)
	cmd := icAwsCmd(t, "")
	_, err := resolveAWSPlacement(context.Background(), cmd, icTestTarget(), "us-east-1", "stack", true)
	if err == nil || !strings.Contains(err.Error(), "--subnets and --security-group-id are required") {
		t.Fatalf("expected the explicit-networking requirement, got %v", err)
	}
}

// A BYOC cluster still provisioning has no VPC yet; say so rather than
// reporting it as an Instaclustr-hosted cluster.
func TestResolveAWSPlacementExplainsAMissingVPC(t *testing.T) {
	isolate(t)
	cmd := icAwsCmd(t, "")
	target := byocTarget()
	target.VpcID = ""
	_, err := resolveAWSPlacement(context.Background(), cmd, target, "us-east-1", "stack", true)
	if err == nil || !strings.Contains(err.Error(), "has not reported its VPC yet") {
		t.Fatalf("expected the still-provisioning explanation, got %v", err)
	}
}

// The operator resolves the primary on the side THIS machine can reach; the
// collector has to seed from the same node's private address.
func TestCollectorAddressMapsToThePrivateSide(t *testing.T) {
	in := &instaclustrInstall{ict: byocTarget(), seedHost: "203.0.113.10", usePrivate: false}

	in.collectorPrivate = true
	host, private := in.collectorAddress()
	if host != "10.0.0.10" || !private {
		t.Errorf("got (%q,%v), want the same node's private address 10.0.0.10", host, private)
	}

	// Outside the VPC nothing is remapped.
	in.collectorPrivate = false
	if host, private := in.collectorAddress(); host != "203.0.113.10" || private {
		t.Errorf("got (%q,%v), want the operator's host unchanged", host, private)
	}

	// A node with no private address keeps the operator's host: a wrong address
	// is worse than a suboptimal one.
	bare := &instaclustrInstall{
		ict: collector.InstaclustrTarget{Nodes: []collector.InstaclustrNode{
			{ID: "n1", PublicAddress: "203.0.113.10"},
		}},
		seedHost: "203.0.113.10", collectorPrivate: true,
	}
	if host, _ := bare.collectorAddress(); host != "203.0.113.10" {
		t.Errorf("got %q, want the operator's host when there is no private address", host)
	}
}

func stubReleaseCollectorSG(t *testing.T, err error) *[]string {
	t.Helper()
	var released []string
	orig := releaseCollectorSG
	releaseCollectorSG = func(_ context.Context, _, groupID string) error {
		released = append(released, groupID)
		return err
	}
	t.Cleanup(func() { releaseCollectorSG = orig })
	return &released
}

// Uninstall hands back the group the install created, and leaves alone one that
// already existed.
func TestUninstallReleasesOnlyASecurityGroupItCreated(t *testing.T) {
	t.Run("created by the install", func(t *testing.T) {
		isolate(t)
		released := stubReleaseCollectorSG(t, nil)
		releaseCollectorSecurityGroup(context.Background(), &collector.State{
			Target: "aws", Region: "us-east-1",
			CollectorSecurityGroupID:      "sg-ours",
			CollectorSecurityGroupCreated: true,
		})
		if len(*released) != 1 || (*released)[0] != "sg-ours" {
			t.Errorf("released %v, want [sg-ours]", *released)
		}
	})

	t.Run("pre-existing", func(t *testing.T) {
		isolate(t)
		released := stubReleaseCollectorSG(t, nil)
		releaseCollectorSecurityGroup(context.Background(), &collector.State{
			Target: "aws", Region: "us-east-1",
			CollectorSecurityGroupID:      "sg-theirs",
			CollectorSecurityGroupCreated: false,
		})
		if len(*released) != 0 {
			t.Errorf("removed a group the install did not create: %v", *released)
		}
	})

	t.Run("no security group at all", func(t *testing.T) {
		isolate(t)
		released := stubReleaseCollectorSG(t, nil)
		releaseCollectorSecurityGroup(context.Background(), &collector.State{Target: "aws", Region: "us-east-1"})
		if len(*released) != 0 {
			t.Errorf("nothing to release, got %v", *released)
		}
	})

	// The task's interface usually still holds the group when uninstall runs,
	// so this is the ordinary case rather than an edge one. It must report,
	// not block or claim success.
	t.Run("still in use is reported", func(t *testing.T) {
		isolate(t)
		released := stubReleaseCollectorSG(t, errors.New("DependencyViolation: resource sg-ours has a dependent object"))
		releaseCollectorSecurityGroup(context.Background(), &collector.State{
			Target: "aws", Region: "us-east-1",
			CollectorSecurityGroupID:      "sg-ours",
			CollectorSecurityGroupCreated: true,
		})
		if len(*released) != 1 {
			t.Errorf("the delete should still have been attempted, got %v", *released)
		}
	})
}

// The fallback: a cluster that will not take a security-group rule still has to
// admit the collector, by the networks its task can land in.
func TestInstallFallsBackToSubnetCIDRs(t *testing.T) {
	isolate(t)
	if err := collector.SaveState(&collector.State{AgentID: "a-1", Target: "aws"}); err != nil {
		t.Fatal(err)
	}
	// The cluster refuses the security-group entry.
	origSG := ensureSGRule
	ensureSGRule = func(_ context.Context, _ collector.InstaclustrCreds, _, _ string) (collector.SecurityGroupRule, bool, error) {
		return collector.SecurityGroupRule{}, false, errors.New("security group rules are not available here")
	}
	t.Cleanup(func() { ensureSGRule = origSG })

	var seen []string
	origCIDR := ensureFirewallRule
	ensureFirewallRule = func(_ context.Context, _ collector.InstaclustrCreds, _, cidr string) (collector.FirewallRule, bool, error) {
		seen = append(seen, cidr)
		return collector.FirewallRule{ID: "r-" + cidr, Network: cidr}, true, nil
	}
	t.Cleanup(func() { ensureFirewallRule = origCIDR })

	removed := false
	p := &awsPlacement{securityGroup: "sg-ours", vpc: &collector.VPCPlacement{
		VpcID: "vpc-1", SecurityGroupCreated: true,
		Subnets: []collector.CollectorSubnet{
			{ID: "subnet-a", CIDR: "10.10.0.0/18"},
			{ID: "subnet-b", CIDR: "10.10.64.0/18"},
		},
	}}
	in := &instaclustrInstall{clusterID: "c-1"}

	if err := allowlistCollectorSecurityGroup(context.Background(), in, p, false, func() { removed = true }); err != nil {
		t.Fatalf("the fallback should have admitted the collector: %v", err)
	}
	// Every candidate subnet, because the scheduler picks which one.
	if len(seen) != 2 || seen[0] != "10.10.0.0/18" || seen[1] != "10.10.64.0/18" {
		t.Errorf("allowlisted %v, want both subnet CIDRs", seen)
	}
	if !removed {
		t.Error("the operator's temporary rule must still be retired")
	}

	st, err := collector.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.CollectorSubnetCIDRs) != 2 {
		t.Errorf("CollectorSubnetCIDRs = %v, want both recorded", st.CollectorSubnetCIDRs)
	}
	if len(st.CollectorFirewallRuleIDs) != 2 {
		t.Errorf("CollectorFirewallRuleIDs = %v, want both recorded", st.CollectorFirewallRuleIDs)
	}
	// Which kind was used decides how refresh-firewall reconciles: leaving the
	// security-group id set would send it down the wrong path.
	if st.CollectorSecurityGroupID != "" {
		t.Errorf("CollectorSecurityGroupID = %q, want empty on the fallback path", st.CollectorSecurityGroupID)
	}
	// The group still exists and the task still uses it for egress, so
	// uninstall must still clean it up.
	if !st.CollectorSecurityGroupCreated {
		t.Error("the security group this run created must still be released at uninstall")
	}
}

// Subnets reporting no network leave nothing to fall back to, and that has to
// be said rather than silently leaving the collector unable to connect.
func TestFallbackRefusesWhenThereIsNoNetwork(t *testing.T) {
	isolate(t)
	origSG := ensureSGRule
	ensureSGRule = func(_ context.Context, _ collector.InstaclustrCreds, _, _ string) (collector.SecurityGroupRule, bool, error) {
		return collector.SecurityGroupRule{}, false, errors.New("refused")
	}
	t.Cleanup(func() { ensureSGRule = origSG })

	p := &awsPlacement{securityGroup: "sg-ours", vpc: &collector.VPCPlacement{VpcID: "vpc-1"}}
	err := allowlistCollectorSecurityGroup(context.Background(), &instaclustrInstall{clusterID: "c-1"}, p, false, func() {})
	if err == nil || !strings.Contains(err.Error(), "no") {
		t.Fatalf("expected a refusal naming the missing network, got %v", err)
	}
}
