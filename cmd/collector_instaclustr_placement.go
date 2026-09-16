package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dbgorilla/dbgorilla-cli/internal/collector"
	"github.com/dbgorilla/dbgorilla-cli/internal/style"
)

// Where the AWS collector runs, and what that implies.
//
// Two address sides are in play and they are not the same decision. The
// OPERATOR dials the cluster once, from this machine, to create the monitoring
// role — that has to be an address this machine can reach, which for a
// public-address cluster means the public one. The COLLECTOR dials it
// continuously from wherever it ends up running, and once that is inside the
// cluster's VPC it should use the private address: a security-group allowlist
// matches on the source's private IP and never on its public one, so a
// VPC-resident collector dialling the public address would hairpin out through
// the internet gateway and fail to match its own rule.
//
// Conflating the two is why this is a separate type rather than one flag.

// awsPlacement is the resolved networking for an Instaclustr AWS install.
type awsPlacement struct {
	subnets        []string
	securityGroup  string
	assignPublicIP string
	stableEgress   bool
	vpcID          string
	natSubnetCidr  string

	// collectorUsePrivate is the address side the COLLECTOR dials, which is
	// not necessarily the side the operator used to set the role up.
	collectorUsePrivate bool

	// vpc is set only when the collector runs inside the cluster's own VPC,
	// and carries what uninstall and rollback need.
	vpc *collector.VPCPlacement
}

// vpcResident reports whether the collector runs inside the cluster's VPC,
// which is what makes security-group allowlisting possible.
func (p awsPlacement) vpcResident() bool { return p.vpc != nil }

// resolveAWSPlacement decides where the collector runs.
//
// Explicit --subnets/--security-group-id always win, which keeps the peered-VPC
// shape and every existing install working unchanged. Otherwise a BYOC cluster
// is placed inside its own VPC, discovered from the cluster rather than
// supplied. A cluster on Instaclustr's own account has no VPC of ours to place
// into, so the flags remain required there.
//
// Nothing is created until the placement has been checked.
func resolveAWSPlacement(
	ctx context.Context, cmd *cobra.Command, ict collector.InstaclustrTarget,
	region, stackName string, dryRun bool,
) (*awsPlacement, error) {
	subnets := splitCSV(mustString(cmd, "subnets"))
	sg := mustString(cmd, "security-group-id")
	stableEgress, _ := cmd.Flags().GetBool("stable-egress")
	vpcID := mustString(cmd, "vpc-id")
	natCidr := mustString(cmd, "nat-subnet-cidr")
	allowRaw := mustString(cmd, "allow-ip")
	assignIP := mustString(cmd, "assign-public-ip")

	explicit := len(subnets) > 0 && sg != ""

	if !explicit && ict.LinkedAccount() && ict.VpcID != "" {
		return resolveVPCResidentPlacement(ctx, cmd, ict, region, stackName, dryRun)
	}

	if !explicit {
		if ict.LinkedAccount() {
			// BYOC, but provisioning has not reported the VPC yet.
			return nil, errors.New("this cluster runs in your own cloud account but has not reported its VPC yet " +
				"(it is still provisioning). Wait for it to finish, or pass --subnets and --security-group-id " +
				"to place the collector yourself")
		}
		return nil, errors.New("--subnets and --security-group-id are required for a cluster hosted in " +
			"Instaclustr's own account: there is no VPC of yours to discover networking from. The security " +
			"group needs egress to 443 (the Instaclustr and DBGorilla APIs) and 5432 (the cluster)")
	}

	// The explicit path keeps its original rules.
	if stableEgress {
		if vpcID == "" || natCidr == "" {
			return nil, errors.New("--vpc-id and --nat-subnet-cidr are required with --stable-egress " +
				"(the stack creates a private subnet routed through a NAT gateway with an Elastic IP; " +
				"the FIRST --subnets entry must be a public subnet for the NAT gateway). " +
				"Pass --stable-egress=false with --allow-ip to skip the NAT at the cost of firewall churn")
		}
		if _, _, cerr := net.ParseCIDR(natCidr); cerr != nil {
			return nil, fmt.Errorf("--nat-subnet-cidr %q is not a CIDR (e.g. 10.0.200.0/28)", natCidr)
		}
	} else if allowRaw == "" {
		return nil, errors.New("--stable-egress=false needs --allow-ip: a plain Fargate task's public IP is " +
			"ephemeral, so the firewall entry must be an address you manage (a NAT you already have)")
	}
	if assignIP == "" {
		assignIP = "ENABLED"
	}
	usePrivate, _ := cmd.Flags().GetBool("use-private-addresses")
	return &awsPlacement{
		subnets: subnets, securityGroup: sg, assignPublicIP: assignIP,
		stableEgress: stableEgress, vpcID: vpcID, natSubnetCidr: natCidr,
		collectorUsePrivate: usePrivate || ict.PrivateNetworkCluster,
	}, nil
}

// resolveVPCResidentPlacement discovers the collector's home inside the
// cluster's VPC, refuses the flags that contradict that shape, and creates the
// security group the firewall rule will name.
func resolveVPCResidentPlacement(
	ctx context.Context, cmd *cobra.Command, ict collector.InstaclustrTarget,
	region, stackName string, dryRun bool,
) (*awsPlacement, error) {
	// Refuse contradictions before doing any work, so the message is about the
	// flag rather than about whatever failed downstream.
	if cmd.Flags().Changed("stable-egress") {
		if on, _ := cmd.Flags().GetBool("stable-egress"); on {
			return nil, errors.New("--stable-egress does not apply when the collector runs inside the cluster's " +
				"VPC: the allowlist names its security group, not an address, so there is nothing for a NAT " +
				"gateway's static IP to keep valid. Drop the flag, or pass --subnets and " +
				"--security-group-id to place the collector outside the VPC instead")
		}
	}
	if cmd.Flags().Changed("use-private-addresses") {
		if on, _ := cmd.Flags().GetBool("use-private-addresses"); !on {
			return nil, errors.New("--use-private-addresses=false cannot work for a collector inside the " +
				"cluster's VPC: a security-group allowlist matches the source's private address, never its " +
				"public one, so dialling the public address would leave the VPC through the internet gateway " +
				"and fail to match the rule. Place the collector outside the VPC with --subnets and " +
				"--security-group-id if you need public addressing")
		}
	}

	placement, problems, err := discoverVPCPlacement(ctx, region, ict.VpcID)
	if err != nil {
		return nil, err
	}
	if len(problems) > 0 {
		return nil, placementError(ict.VpcID, problems)
	}

	p := &awsPlacement{
		subnets:        placement.SubnetIDs(),
		assignPublicIP: placement.AssignPublicIP(),
		stableEgress:   false,
		vpcID:          placement.VpcID,
		// Inside the VPC the collector takes the private path; that is the
		// whole point of being there.
		collectorUsePrivate: true,
		vpc:                 &placement,
	}

	fmt.Println(style.Success(fmt.Sprintf(
		"✓ Placing the collector in the cluster's VPC %s (%s), dialling private addresses",
		placement.VpcID, strings.Join(p.subnets, ", "))))

	if dryRun {
		// A dry run must not create the security group.
		p.securityGroup = "<created-at-install>"
		return p, nil
	}
	if err := placement.EnsureSecurityGroup(ctx, region, stackName); err != nil {
		return nil, err
	}
	p.vpc, p.securityGroup = &placement, placement.SecurityGroupID
	if placement.SecurityGroupCreated {
		fmt.Println(style.Success(fmt.Sprintf("✓ Collector security group %s (egress 443 and 5432 only)",
			placement.SecurityGroupID)))
	}
	return p, nil
}

// placementError renders every problem with its fix, since an operator hitting
// two of them at once should not have to discover the second by re-running.
func placementError(vpcID string, problems []collector.PlacementProblem) error {
	var b strings.Builder
	fmt.Fprintf(&b, "the collector cannot be placed in the cluster's VPC %s:", vpcID)
	for _, p := range problems {
		fmt.Fprintf(&b, "\n\n  • %s\n    %s", p.Detail, p.Fix)
	}
	return errors.New(b.String())
}

func mustString(cmd *cobra.Command, name string) string {
	v, _ := cmd.Flags().GetString(name)
	return v
}

// allowlistCollectorSecurityGroup allowlists the collector by security group
// rather than by address, and records ownership so refresh-firewall and
// uninstall can tell this rule from somebody else's.
//
// Unlike the address path there is nothing to re-detect later: a redeploy moves
// the task's address but not its security group.
func allowlistCollectorSecurityGroup(
	ctx context.Context, in *instaclustrInstall, p *awsPlacement,
	opCreated bool, removeOperatorRule func(),
) error {
	rule, created, err := ensureSGRule(ctx, in.setupCreds, in.clusterID, p.securityGroup)
	if err != nil {
		removeOperatorRule()
		return fmt.Errorf("the collector deployed but its firewall entry failed: %w\n\n"+
			"Allowlist security group %s on the cluster's Firewall Rules page, or re-run "+
			"`dbg collector refresh-firewall`", err, p.securityGroup)
	}
	fmt.Println(style.Success(fmt.Sprintf("✓ Firewall: allowlisted security group %s for the collector",
		p.securityGroup)))

	// The operator's temporary address rule is never the collector's rule here
	// — they are different kinds of entry — so it always comes back out.
	removeOperatorRule()
	_ = opCreated

	st, lerr := collector.LoadState()
	if lerr != nil || st == nil {
		return nil
	}
	st.CollectorSecurityGroupID = p.securityGroup
	if created {
		st.SecurityGroupRuleID = rule.ID
	}
	if p.vpc != nil && p.vpc.SecurityGroupCreated {
		st.CollectorSecurityGroupCreated = true
	}
	if serr := collector.SaveState(st); serr != nil {
		fmt.Println(style.Warn(fmt.Sprintf("⚠  could not record the firewall rule id: %v", serr)))
	}
	return nil
}
