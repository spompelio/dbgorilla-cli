package collector

import (
	"context"
	"strings"
	"testing"
)

func kinds(in []PlacementProblem) []PlacementProblemKind {
	out := make([]PlacementProblemKind, 0, len(in))
	for _, p := range in {
		out = append(out, p.Kind)
	}
	return out
}

func hasKind(in []PlacementProblem, want PlacementProblemKind) bool {
	for _, p := range in {
		if p.Kind == want {
			return true
		}
	}
	return false
}

func TestPreflightPlacementAcceptsTheFixtureShape(t *testing.T) {
	got := PreflightPlacement("vpc-1", []CollectorSubnet{
		{ID: "subnet-a", VpcID: "vpc-1", InternetRoute: "igw-1", NeedsPublicIP: true},
		{ID: "subnet-b", VpcID: "vpc-1", InternetRoute: "igw-1", NeedsPublicIP: true},
	})
	if len(got) != 0 {
		t.Fatalf("expected no problems, got %v", kinds(got))
	}
}

// The three failures have completely different fixes, so they must not collapse
// into one "cannot reach the cluster".
func TestPreflightPlacementDistinguishesItsFailures(t *testing.T) {
	t.Run("subnet has no way out", func(t *testing.T) {
		got := PreflightPlacement("vpc-1", []CollectorSubnet{{ID: "subnet-a", VpcID: "vpc-1"}})
		if !hasKind(got, SubnetHasNoEgress) {
			t.Fatalf("got %v, want SubnetHasNoEgress", kinds(got))
		}
		if !strings.Contains(got[0].Detail, "subnet-a") {
			t.Errorf("the detail should name the subnet, got %q", got[0].Detail)
		}
		if got[0].Fix == "" {
			t.Error("a problem with no fix leaves the operator stuck")
		}
	})

	t.Run("subnet is in another VPC", func(t *testing.T) {
		got := PreflightPlacement("vpc-1", []CollectorSubnet{
			{ID: "subnet-x", VpcID: "vpc-other", InternetRoute: "igw-9"},
		})
		if !hasKind(got, SubnetOutsideClusterVPC) {
			t.Fatalf("got %v, want SubnetOutsideClusterVPC", kinds(got))
		}
		if hasKind(got, SubnetHasNoEgress) {
			t.Error("a routed subnet in the wrong VPC is not an egress problem")
		}
	})

	t.Run("both at once are reported separately", func(t *testing.T) {
		got := PreflightPlacement("vpc-1", []CollectorSubnet{
			{ID: "subnet-a", VpcID: "vpc-1"},
			{ID: "subnet-x", VpcID: "vpc-other", InternetRoute: "igw-9"},
		})
		if !hasKind(got, SubnetHasNoEgress) || !hasKind(got, SubnetOutsideClusterVPC) {
			t.Fatalf("got %v, want both kinds", kinds(got))
		}
	})
}

// Several foreign subnets share one cause and one fix, so they are one problem.
func TestPreflightPlacementGroupsForeignSubnets(t *testing.T) {
	got := PreflightPlacement("vpc-1", []CollectorSubnet{
		{ID: "subnet-x", VpcID: "vpc-other", InternetRoute: "igw-9"},
		{ID: "subnet-y", VpcID: "vpc-other", InternetRoute: "igw-9"},
	})
	if len(got) != 1 {
		t.Fatalf("expected one grouped problem, got %v", kinds(got))
	}
	for _, id := range []string{"subnet-x", "subnet-y"} {
		if !strings.Contains(got[0].Detail, id) {
			t.Errorf("the detail should name %s, got %q", id, got[0].Detail)
		}
	}
}

func TestVerifyClusterAdmitsCollectorBySecurityGroup(t *testing.T) {
	stubAWS(t, newAWSFake(t).on("DescribeSecurityGroups",
		securityGroupsXML("sg-cluster", 5432, 5432, "sg-collector", "")))

	problem, err := VerifyClusterAdmitsCollector(context.Background(), ec2Client(t),
		"dc-1", "sg-collector", nil, 5432)
	if err != nil {
		t.Fatalf("VerifyClusterAdmitsCollector: %v", err)
	}
	if problem != nil {
		t.Fatalf("a group reference on the port should admit the collector, got %v", problem.Detail)
	}
}

// The CIDR fallback: an ingress rule wide enough to cover the collector's
// subnet admits it, even with no group reference.
func TestVerifyClusterAdmitsCollectorByCIDR(t *testing.T) {
	stubAWS(t, newAWSFake(t).on("DescribeSecurityGroups",
		securityGroupsXML("sg-cluster", 5432, 5432, "", "10.10.0.0/16")))

	problem, err := VerifyClusterAdmitsCollector(context.Background(), ec2Client(t),
		"dc-1", "", []string{"10.10.0.0/18"}, 5432)
	if err != nil {
		t.Fatalf("VerifyClusterAdmitsCollector: %v", err)
	}
	if problem != nil {
		t.Fatalf("10.10.0.0/16 covers 10.10.0.0/18, got %v", problem.Detail)
	}
}

// A rule more specific than the collector's subnet does not cover it, even
// though it shares a base address.
func TestVerifyClusterAdmitsCollectorRejectsANarrowerCIDR(t *testing.T) {
	stubAWS(t, newAWSFake(t).on("DescribeSecurityGroups",
		securityGroupsXML("sg-cluster", 5432, 5432, "", "10.10.0.0/24")))

	problem, err := VerifyClusterAdmitsCollector(context.Background(), ec2Client(t),
		"dc-1", "", []string{"10.10.0.0/18"}, 5432)
	if err != nil {
		t.Fatalf("VerifyClusterAdmitsCollector: %v", err)
	}
	if problem == nil {
		t.Fatal("a /24 does not admit a task anywhere in a /18")
	}
}

// The failure that matters most: Instaclustr accepted the rule but never
// applied it, so nothing on the cluster references the collector.
func TestVerifyClusterAdmitsCollectorCatchesAnUnappliedRule(t *testing.T) {
	stubAWS(t, newAWSFake(t).on("DescribeSecurityGroups",
		securityGroupsXML("sg-cluster", 5432, 5432, "sg-somebodyelse", "")))

	problem, err := VerifyClusterAdmitsCollector(context.Background(), ec2Client(t),
		"dc-1", "sg-collector", nil, 5432)
	if err != nil {
		t.Fatalf("VerifyClusterAdmitsCollector: %v", err)
	}
	if problem == nil {
		t.Fatal("expected the collector to be reported as not admitted")
	}
	if problem.Kind != ClusterDoesNotAdmitCollector {
		t.Errorf("kind = %q", problem.Kind)
	}
	if !strings.Contains(problem.Fix, "refresh-firewall") {
		t.Errorf("the fix should name the command that re-asserts the rule, got %q", problem.Fix)
	}
}

func TestVerifyClusterAdmitsCollectorIgnoresOtherPorts(t *testing.T) {
	stubAWS(t, newAWSFake(t).on("DescribeSecurityGroups",
		securityGroupsXML("sg-cluster", 443, 443, "sg-collector", "")))

	problem, err := VerifyClusterAdmitsCollector(context.Background(), ec2Client(t),
		"dc-1", "sg-collector", nil, 5432)
	if err != nil {
		t.Fatalf("VerifyClusterAdmitsCollector: %v", err)
	}
	if problem == nil {
		t.Fatal("a rule for 443 does not admit the collector on 5432")
	}
}

// Not finding the cluster's group is unknown, not blocked — reporting a refusal
// would send an operator chasing a firewall that is fine.
func TestVerifyClusterAdmitsCollectorTreatsAMissingGroupAsUnknown(t *testing.T) {
	stubAWS(t, newAWSFake(t).on("DescribeSecurityGroups", noSecurityGroupsXML))

	problem, err := VerifyClusterAdmitsCollector(context.Background(), ec2Client(t),
		"dc-1", "sg-collector", nil, 5432)
	if err != nil {
		t.Fatalf("VerifyClusterAdmitsCollector: %v", err)
	}
	if problem != nil {
		t.Fatalf("a group we cannot find is unknown, not blocked: %v", problem.Detail)
	}

	// Likewise with nothing to look the group up by.
	if p, err := VerifyClusterAdmitsCollector(context.Background(), ec2Client(t),
		"", "sg-collector", nil, 5432); err != nil || p != nil {
		t.Fatalf("an unknown data centre id is not a refusal, got (%v,%v)", p, err)
	}
}

func TestClusterSecurityGroupNameMatchesInstaclustrsPattern(t *testing.T) {
	// Observed live: data centre 69bba2c5-… owns group
	// ic-69bba2c5-4bd7-47e7-9b78-76e3434d2d31-1831614699.
	got := ClusterSecurityGroupName("69bba2c5-4bd7-47e7-9b78-76e3434d2d31")
	if got != "ic-69bba2c5-4bd7-47e7-9b78-76e3434d2d31-*" {
		t.Errorf("got %q", got)
	}
}
