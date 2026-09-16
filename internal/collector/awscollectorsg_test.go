package collector

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func ec2ErrorXML(code, message string) string {
	return `<Response><Errors><Error><Code>` + code + `</Code><Message>` + message +
		`</Message></Error></Errors><RequestID>req-1</RequestID></Response>`
}

const (
	createSGXML = `<CreateSecurityGroupResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <groupId>sg-new</groupId><return>true</return>
</CreateSecurityGroupResponse>`
	authorizeEgressXML = `<AuthorizeSecurityGroupEgressResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <return>true</return>
</AuthorizeSecurityGroupEgressResponse>`
	revokeEgressXML = `<RevokeSecurityGroupEgressResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <return>true</return>
</RevokeSecurityGroupEgressResponse>`
	deleteSGXML = `<DeleteSecurityGroupResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <return>true</return>
</DeleteSecurityGroupResponse>`
	noSecurityGroupsXML = `<DescribeSecurityGroupsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <securityGroupInfo></securityGroupInfo>
</DescribeSecurityGroupsResponse>`
)

func oneSecurityGroupXML(id string) string {
	return `<DescribeSecurityGroupsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <securityGroupInfo><item><groupId>` + id + `</groupId></item></securityGroupInfo>
</DescribeSecurityGroupsResponse>`
}

func called(f *awsFake, action string) bool {
	for _, c := range f.calls {
		if c == action {
			return true
		}
	}
	return false
}

func TestEnsureCollectorSecurityGroupCreatesAndNarrowsEgress(t *testing.T) {
	fake := newAWSFake(t).
		on("DescribeSecurityGroups", noSecurityGroupsXML).
		on("CreateSecurityGroup", createSGXML).
		on("AuthorizeSecurityGroupEgress", authorizeEgressXML).
		on("RevokeSecurityGroupEgress", revokeEgressXML)
	stubAWS(t, fake)

	id, created, err := EnsureCollectorSecurityGroup(context.Background(), ec2Client(t), "vpc-1", "dbg-collector")
	if err != nil {
		t.Fatalf("EnsureCollectorSecurityGroup: %v", err)
	}
	if id != "sg-new" || !created {
		t.Fatalf("got (%q,%v), want (sg-new,true)", id, created)
	}
	// EC2 attaches allow-all egress to every new group; leaving it makes the
	// narrowing cosmetic.
	if !called(fake, "RevokeSecurityGroupEgress") {
		t.Error("the default allow-all egress was never revoked")
	}
	body := strings.Join(fake.bodies, "\n")
	for _, port := range []string{"443", "5432"} {
		if !strings.Contains(body, port) {
			t.Errorf("egress for port %s was never authorized", port)
		}
	}
	if strings.Contains(body, "AuthorizeSecurityGroupIngress") {
		t.Error("the collector accepts no inbound connections, so it must open no ingress")
	}
}

func TestEnsureCollectorSecurityGroupReusesAnExistingGroup(t *testing.T) {
	fake := newAWSFake(t).on("DescribeSecurityGroups", oneSecurityGroupXML("sg-existing"))
	stubAWS(t, fake)

	id, created, err := EnsureCollectorSecurityGroup(context.Background(), ec2Client(t), "vpc-1", "dbg-collector")
	if err != nil {
		t.Fatalf("EnsureCollectorSecurityGroup: %v", err)
	}
	if id != "sg-existing" || created {
		t.Fatalf("got (%q,%v), want (sg-existing,false)", id, created)
	}
	if called(fake, "CreateSecurityGroup") {
		t.Error("an existing group must be adopted, not recreated")
	}
}

// Losing a create race is not a failure: the other install made the same group.
func TestEnsureCollectorSecurityGroupAdoptsOnADuplicateRace(t *testing.T) {
	fake := newAWSFake(t).
		onSeq("DescribeSecurityGroups", noSecurityGroupsXML, oneSecurityGroupXML("sg-theirs")).
		fail("CreateSecurityGroup", http.StatusBadRequest,
			ec2ErrorXML("InvalidGroup.Duplicate", "already exists"))
	stubAWS(t, fake)

	id, created, err := EnsureCollectorSecurityGroup(context.Background(), ec2Client(t), "vpc-1", "dbg-collector")
	if err != nil {
		t.Fatalf("a duplicate should be adopted, got %v", err)
	}
	if id != "sg-theirs" || created {
		t.Fatalf("got (%q,%v), want (sg-theirs,false)", id, created)
	}
}

// A group that exists but never got its egress narrowed would allow everything
// under a name claiming otherwise, so it must not be left behind.
func TestEnsureCollectorSecurityGroupCleansUpAHalfMadeGroup(t *testing.T) {
	fake := newAWSFake(t).
		on("DescribeSecurityGroups", noSecurityGroupsXML).
		on("CreateSecurityGroup", createSGXML).
		fail("AuthorizeSecurityGroupEgress", http.StatusForbidden,
			ec2ErrorXML("UnauthorizedOperation", "not authorized")).
		on("DeleteSecurityGroup", deleteSGXML)
	stubAWS(t, fake)

	if _, _, err := EnsureCollectorSecurityGroup(context.Background(), ec2Client(t), "vpc-1", "dbg-collector"); err == nil {
		t.Fatal("expected the authorize failure to surface")
	}
	if !called(fake, "DeleteSecurityGroup") {
		t.Error("the half-configured group was left behind with allow-all egress")
	}
}

// A group created without the allow-all rule is already in the desired state.
func TestEnsureCollectorSecurityGroupToleratesAMissingDefaultRule(t *testing.T) {
	stubAWS(t, newAWSFake(t).
		on("DescribeSecurityGroups", noSecurityGroupsXML).
		on("CreateSecurityGroup", createSGXML).
		on("AuthorizeSecurityGroupEgress", authorizeEgressXML).
		fail("RevokeSecurityGroupEgress", http.StatusBadRequest,
			ec2ErrorXML("InvalidPermission.NotFound", "rule does not exist")))

	if _, _, err := EnsureCollectorSecurityGroup(context.Background(), ec2Client(t), "vpc-1", "dbg-collector"); err != nil {
		t.Fatalf("an absent allow-all rule is not a failure, got %v", err)
	}
}

func TestEnsureCollectorSecurityGroupRefusesWithoutAVPC(t *testing.T) {
	if _, _, err := EnsureCollectorSecurityGroup(context.Background(), ec2Client(t), "", "dbg-collector"); err == nil {
		t.Fatal("expected a refusal without a VPC id")
	}
}

func TestDeleteCollectorSecurityGroupIsIdempotent(t *testing.T) {
	stubAWS(t, newAWSFake(t).fail("DeleteSecurityGroup", http.StatusBadRequest,
		ec2ErrorXML("InvalidGroup.NotFound", "does not exist")))
	if err := DeleteCollectorSecurityGroup(context.Background(), ec2Client(t), "sg-gone"); err != nil {
		t.Fatalf("deleting an absent group should converge, got %v", err)
	}
	if err := DeleteCollectorSecurityGroup(context.Background(), ec2Client(t), ""); err != nil {
		t.Fatalf("an empty id is a no-op, got %v", err)
	}
}

// While the task's network interface still references the group, EC2 refuses.
// Reporting success there would tell the operator a group was removed when it
// was not.
func TestDeleteCollectorSecurityGroupSurfacesADependencyViolation(t *testing.T) {
	stubAWS(t, newAWSFake(t).fail("DeleteSecurityGroup", http.StatusBadRequest,
		ec2ErrorXML("DependencyViolation", "resource sg-1 has a dependent object")))

	err := DeleteCollectorSecurityGroup(context.Background(), ec2Client(t), "sg-1")
	if err == nil {
		t.Fatal("a dependency violation must not be swallowed")
	}
	if !strings.Contains(err.Error(), "still in use") {
		t.Errorf("the error should explain the interface has not been released, got: %v", err)
	}
}

func TestCollectorSecurityGroupNameFallsBackWhenUnnamed(t *testing.T) {
	if got := CollectorSecurityGroupName("my-stack"); got != "my-stack-egress" {
		t.Errorf("got %q, want my-stack-egress", got)
	}
	if got := CollectorSecurityGroupName(""); got != "dbgorilla-collector-egress" {
		t.Errorf("got %q, want the default name", got)
	}
}
