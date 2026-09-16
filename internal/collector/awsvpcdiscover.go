package collector

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// Subnet discovery for a BYOC collector.
//
// A managed-database target hands us its own networking, but an Instaclustr
// cluster does not: what it gives is the VPC it created in the customer's
// account. Everything else is derivable from that with ordinary EC2 reads,
// which is what this file does — the CLI runs outside the VPC and cannot probe
// it, so the answers have to come from describing it.

// CollectorSubnet is a candidate subnet for the collector task, annotated with
// the fact that decides whether it can host one.
type CollectorSubnet struct {
	ID   string
	CIDR string
	AZ   string
	// InternetRoute names the gateway carrying the subnet's default route — an
	// internet gateway or a NAT gateway. Empty means the subnet has no route
	// off the VPC at all, and a task there could not pull its image, hold the
	// DBGorilla connection, or reach the Instaclustr API.
	InternetRoute string
	// NeedsPublicIP is true when the only way out is an internet gateway, which
	// routes for a task that has a public address and silently blackholes one
	// that does not. A NAT gateway carries a private task on its own.
	NeedsPublicIP bool
}

// RoutesOffVPC reports whether a task in this subnet can reach the internet.
func (s CollectorSubnet) RoutesOffVPC() bool { return s.InternetRoute != "" }

// DiscoverCollectorSubnets returns every subnet in vpcID with its default route
// resolved.
//
// Route tables are matched the way AWS applies them: a subnet uses the table
// explicitly associated with it, and otherwise the VPC's main table. Missing
// that fallback would report an unroutable subnet for the common VPC that
// associates nothing explicitly — including the one Instaclustr creates.
func DiscoverCollectorSubnets(ctx context.Context, client *ec2.Client, vpcID string) ([]CollectorSubnet, error) {
	if vpcID == "" {
		return nil, fmt.Errorf("cannot discover subnets without a VPC id")
	}
	vpcFilter := []ec2types.Filter{{Name: aws.String("vpc-id"), Values: []string{vpcID}}}

	subnetsOut, err := client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{Filters: vpcFilter})
	if err != nil {
		return nil, fmt.Errorf("cannot list the subnets of %s: %w", vpcID, err)
	}
	tablesOut, err := client.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{Filters: vpcFilter})
	if err != nil {
		return nil, fmt.Errorf("cannot list the route tables of %s: %w", vpcID, err)
	}

	bySubnet, main := routeTablesBySubnet(tablesOut.RouteTables)

	out := make([]CollectorSubnet, 0, len(subnetsOut.Subnets))
	for _, s := range subnetsOut.Subnets {
		id := aws.ToString(s.SubnetId)
		table, ok := bySubnet[id]
		if !ok {
			table = main
		}
		gateway, viaIGW := defaultRoute(table)
		out = append(out, CollectorSubnet{
			ID:            id,
			CIDR:          aws.ToString(s.CidrBlock),
			AZ:            aws.ToString(s.AvailabilityZone),
			InternetRoute: gateway,
			NeedsPublicIP: viaIGW,
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("VPC %s has no subnets to place the collector in", vpcID)
	}
	return out, nil
}

// routeTablesBySubnet indexes explicit subnet associations, and separately
// returns the VPC's main table — the one that applies to every subnet that
// associates nothing.
func routeTablesBySubnet(tables []ec2types.RouteTable) (map[string]ec2types.RouteTable, ec2types.RouteTable) {
	bySubnet := make(map[string]ec2types.RouteTable)
	var main ec2types.RouteTable
	for _, t := range tables {
		for _, a := range t.Associations {
			if aws.ToBool(a.Main) {
				main = t
			}
			if id := aws.ToString(a.SubnetId); id != "" {
				bySubnet[id] = t
			}
		}
	}
	return bySubnet, main
}

// defaultRoute returns the gateway carrying 0.0.0.0/0 and whether it is an
// internet gateway (as opposed to a NAT). A blackholed route is ignored: it is
// present but carries nothing.
func defaultRoute(table ec2types.RouteTable) (gateway string, viaIGW bool) {
	for _, r := range table.Routes {
		if aws.ToString(r.DestinationCidrBlock) != "0.0.0.0/0" {
			continue
		}
		if r.State == ec2types.RouteStateBlackhole {
			continue
		}
		if nat := aws.ToString(r.NatGatewayId); nat != "" {
			return nat, false
		}
		if gw := aws.ToString(r.GatewayId); gw != "" {
			// A VPC endpoint or virtual private gateway is not a way to the
			// internet; only an internet gateway is.
			if len(gw) >= 4 && gw[:4] == "igw-" {
				return gw, true
			}
		}
	}
	return "", false
}

// RoutableSubnets narrows a discovered set to the subnets a collector can
// actually run in, preserving order so the choice is stable across runs.
func RoutableSubnets(in []CollectorSubnet) []CollectorSubnet {
	out := make([]CollectorSubnet, 0, len(in))
	for _, s := range in {
		if s.RoutesOffVPC() {
			out = append(out, s)
		}
	}
	return out
}

// SubnetIDs is the id list the CloudFormation template takes.
func SubnetIDs(in []CollectorSubnet) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, s.ID)
	}
	return out
}
