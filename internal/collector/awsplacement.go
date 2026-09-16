package collector

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// Placement preflight for a VPC-resident collector.
//
// The CLI runs outside the VPC and cannot dial the cluster to find out whether
// a placement would work, so the answer is read out of the VPC's own
// configuration instead. Everything here is a describe call: nothing is
// created, so it is safe to run before the install mutates anything.

// PlacementProblemKind distinguishes the failures, because the fix for each is
// completely different and a single "cannot reach the cluster" would send an
// operator looking in the wrong place.
type PlacementProblemKind string

const (
	// SubnetOutsideClusterVPC: the subnet is not in the cluster's VPC at all.
	SubnetOutsideClusterVPC PlacementProblemKind = "subnet-outside-cluster-vpc"
	// SubnetHasNoEgress: the subnet has no default route, so a task there
	// cannot pull its image or reach DBGorilla — regardless of the database.
	SubnetHasNoEgress PlacementProblemKind = "subnet-has-no-egress"
	// ClusterDoesNotAdmitCollector: the cluster's own security group has no
	// ingress rule covering the collector on the database port.
	ClusterDoesNotAdmitCollector PlacementProblemKind = "cluster-does-not-admit-collector"
)

// PlacementProblem is one reason a placement will not work, with the fix.
type PlacementProblem struct {
	Kind   PlacementProblemKind
	Detail string
	Fix    string
}

func (p PlacementProblem) Error() string { return p.Detail }

// PreflightPlacement checks a proposed placement statically, before anything is
// created.
//
// It deliberately does not check whether the cluster admits the collector: on a
// fresh install nothing has been allowlisted yet, so that check could only ever
// fail. Confirming the allowlist landed is VerifyClusterAdmitsCollector's job,
// after the rule is asserted.
func PreflightPlacement(clusterVpcID string, chosen []CollectorSubnet) []PlacementProblem {
	var problems []PlacementProblem
	for _, s := range chosen {
		if !s.RoutesOffVPC() {
			problems = append(problems, PlacementProblem{
				Kind:   SubnetHasNoEgress,
				Detail: fmt.Sprintf("subnet %s has no default route out of the VPC", s.ID),
				Fix: "the collector must reach the container registry, DBGorilla and the Instaclustr API. " +
					"Give the subnet's route table a default route to an internet gateway or a NAT gateway, " +
					"or choose another subnet with --subnets",
			})
		}
	}
	// A subnet from another VPC is reported once rather than per subnet: the
	// cause is the same flag and one message is enough to act on.
	var foreign []string
	for _, s := range chosen {
		if s.VpcID != "" && clusterVpcID != "" && s.VpcID != clusterVpcID {
			foreign = append(foreign, s.ID)
		}
	}
	if len(foreign) > 0 {
		problems = append(problems, PlacementProblem{
			Kind: SubnetOutsideClusterVPC,
			Detail: fmt.Sprintf("subnet(s) %s are not in the cluster's VPC %s",
				strings.Join(foreign, ", "), clusterVpcID),
			Fix: "a collector placed outside the cluster's VPC reaches it over the public internet, " +
				"which needs an address-based firewall rule instead. Either pass subnets from " +
				clusterVpcID + ", or install without VPC placement",
		})
	}
	return problems
}

// ClusterSecurityGroupName is the name prefix of the security group Instaclustr
// creates for a data centre. Its firewall rules materialise as that group's
// ingress, which is what makes it readable as ground truth.
func ClusterSecurityGroupName(dataCentreID string) string {
	return "ic-" + dataCentreID + "-*"
}

// VerifyClusterAdmitsCollector reads the cluster's own security group and
// reports whether the collector would be admitted on port — by a reference to
// its security group, or by a CIDR covering its subnets.
//
// This runs after the allowlist is asserted, and catches the case the
// Instaclustr API makes easy to miss: a rule request accepted but never
// applied. A cluster group we cannot find is reported as unknown rather than as
// a refusal, since a wrong "blocked" would send an operator chasing a firewall
// that is fine.
func VerifyClusterAdmitsCollector(
	ctx context.Context, client *ec2.Client,
	dataCentreID, collectorSGID string, collectorCIDRs []string, port int32,
) (*PlacementProblem, error) {
	if dataCentreID == "" {
		return nil, nil // nothing to look up; not a refusal
	}
	out, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: []ec2types.Filter{{
			Name:   aws.String("group-name"),
			Values: []string{ClusterSecurityGroupName(dataCentreID)},
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("cannot read the cluster's security group for data centre %s: %w", dataCentreID, err)
	}
	if len(out.SecurityGroups) == 0 {
		return nil, nil // not found — unknown, not blocked
	}

	nets := parseCIDRs(collectorCIDRs)
	for _, g := range out.SecurityGroups {
		for _, p := range g.IpPermissions {
			if !permissionCoversPort(p, port) {
				continue
			}
			for _, pair := range p.UserIdGroupPairs {
				if collectorSGID != "" && aws.ToString(pair.GroupId) == collectorSGID {
					return nil, nil
				}
			}
			for _, r := range p.IpRanges {
				_, allowed, perr := net.ParseCIDR(aws.ToString(r.CidrIp))
				if perr == nil && cidrCoversAny(allowed, nets) {
					return nil, nil
				}
			}
		}
	}
	return &PlacementProblem{
		Kind:   ClusterDoesNotAdmitCollector,
		Detail: fmt.Sprintf("the cluster's security group does not admit the collector on port %d", port),
		Fix: "the Instaclustr firewall rule for the collector has not taken effect. Re-run " +
			"`dbg collector refresh-firewall`, and check the cluster's Firewall Rules page — " +
			"their API can accept a rule request without applying it",
	}, nil
}

// permissionCoversPort reports whether an ingress rule covers port. An
// all-protocols rule ("-1") carries no port range and covers everything.
func permissionCoversPort(p ec2types.IpPermission, port int32) bool {
	if aws.ToString(p.IpProtocol) == "-1" {
		return true
	}
	from, to := aws.ToInt32(p.FromPort), aws.ToInt32(p.ToPort)
	return from <= port && port <= to
}

func parseCIDRs(in []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(in))
	for _, c := range in {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// --- resolving a placement ---------------------------------------------------

// VPCPlacement is the networking a collector will run with inside the cluster's
// own VPC.
type VPCPlacement struct {
	VpcID   string
	Subnets []CollectorSubnet
	// SecurityGroupID is empty until EnsureSecurityGroup runs: discovery is
	// read-only by construction, so the preflight can refuse a placement before
	// anything exists to clean up.
	SecurityGroupID      string
	SecurityGroupCreated bool
}

// SubnetIDs is the id list the CloudFormation template takes.
func (p VPCPlacement) SubnetIDs() []string { return SubnetIDs(p.Subnets) }

// CIDRs are the collector's possible task addresses, used as the fallback when
// the cluster allowlists a network rather than a security group.
func (p VPCPlacement) CIDRs() []string {
	out := make([]string, 0, len(p.Subnets))
	for _, s := range p.Subnets {
		if s.CIDR != "" {
			out = append(out, s.CIDR)
		}
	}
	return out
}

// AssignPublicIP reports what the task needs to reach the internet.
//
// Any chosen subnet that only routes through an internet gateway forces
// ENABLED: such a subnet blackholes a task with no public address, and the task
// still has to pull its image and hold the DBGorilla connection even when the
// database leg is private. The allowlist keys on the security group, so the
// address being ephemeral costs nothing.
func (p VPCPlacement) AssignPublicIP() string {
	for _, s := range p.Subnets {
		if s.NeedsPublicIP {
			return "ENABLED"
		}
	}
	return "DISABLED"
}

// DiscoverVPCPlacement finds where the collector can run inside vpcID and
// checks it. It creates nothing — every call is a describe — so a refusal here
// leaves the account untouched.
func DiscoverVPCPlacement(ctx context.Context, region, vpcID string) (VPCPlacement, []PlacementProblem, error) {
	cfg, err := loadAWSConfig(ctx, region)
	if err != nil {
		return VPCPlacement{}, nil, err
	}
	client := ec2.NewFromConfig(cfg)

	all, err := DiscoverCollectorSubnets(ctx, client, vpcID)
	if err != nil {
		return VPCPlacement{}, nil, err
	}
	usable := RoutableSubnets(all)
	if len(usable) == 0 {
		// Report against everything found, so the problem names the subnets the
		// operator can actually see in the console.
		return VPCPlacement{VpcID: vpcID, Subnets: all}, PreflightPlacement(vpcID, all), nil
	}
	p := VPCPlacement{VpcID: vpcID, Subnets: usable}
	return p, PreflightPlacement(vpcID, usable), nil
}

// EnsureSecurityGroup creates the collector's security group in the placement's
// VPC. This is the first thing in the placement flow that writes.
func (p *VPCPlacement) EnsureSecurityGroup(ctx context.Context, region, stackName string) error {
	cfg, err := loadAWSConfig(ctx, region)
	if err != nil {
		return err
	}
	id, created, err := EnsureCollectorSecurityGroup(ctx, ec2.NewFromConfig(cfg), p.VpcID, stackName)
	if err != nil {
		return err
	}
	p.SecurityGroupID, p.SecurityGroupCreated = id, created
	return nil
}

// ReleaseSecurityGroup removes the security group if this run created it,
// leaving one that already existed alone.
func (p VPCPlacement) ReleaseSecurityGroup(ctx context.Context, region string) error {
	if !p.SecurityGroupCreated || p.SecurityGroupID == "" {
		return nil
	}
	cfg, err := loadAWSConfig(ctx, region)
	if err != nil {
		return err
	}
	return DeleteCollectorSecurityGroup(ctx, ec2.NewFromConfig(cfg), p.SecurityGroupID)
}
