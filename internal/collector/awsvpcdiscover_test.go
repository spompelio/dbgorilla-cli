package collector

import (
	"context"
	"strings"
	"testing"
)

// vpcSubnetsXML renders subnets carrying the availability zone the shared
// subnetsXML helper omits.
func vpcSubnetsXML(subnets ...[3]string) string { // id, cidr, az
	var sb strings.Builder
	for _, s := range subnets {
		sb.WriteString(`<item><subnetId>` + s[0] + `</subnetId><cidrBlock>` + s[1] +
			`</cidrBlock><availabilityZone>` + s[2] + `</availabilityZone></item>`)
	}
	return `<DescribeSubnetsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <subnetSet>` + sb.String() + `</subnetSet>
</DescribeSubnetsResponse>`
}

type fakeRouteTable struct {
	id string
	// main marks the VPC's main table; subnets lists explicit associations.
	main    bool
	subnets []string
	// route is destination, gatewayId, natGatewayId, state
	routes [][4]string
}

func routeTablesXML(tables ...fakeRouteTable) string {
	var sb strings.Builder
	for _, t := range tables {
		sb.WriteString(`<item><routeTableId>` + t.id + `</routeTableId><associationSet>`)
		if t.main {
			sb.WriteString(`<item><main>true</main></item>`)
		}
		for _, s := range t.subnets {
			sb.WriteString(`<item><main>false</main><subnetId>` + s + `</subnetId></item>`)
		}
		sb.WriteString(`</associationSet><routeSet>`)
		for _, r := range t.routes {
			sb.WriteString(`<item><destinationCidrBlock>` + r[0] + `</destinationCidrBlock>`)
			if r[1] != "" {
				sb.WriteString(`<gatewayId>` + r[1] + `</gatewayId>`)
			}
			if r[2] != "" {
				sb.WriteString(`<natGatewayId>` + r[2] + `</natGatewayId>`)
			}
			sb.WriteString(`<state>` + r[3] + `</state></item>`)
		}
		sb.WriteString(`</routeSet></item>`)
	}
	return `<DescribeRouteTablesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <routeTableSet>` + sb.String() + `</routeTableSet>
</DescribeRouteTablesResponse>`
}

func stubVPC(t *testing.T, subnets, tables string) {
	t.Helper()
	stubAWS(t, newAWSFake(t).
		on("DescribeSubnets", subnets).
		on("DescribeRouteTables", tables))
}

func findSubnet(t *testing.T, in []CollectorSubnet, id string) CollectorSubnet {
	t.Helper()
	for _, s := range in {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("subnet %s not in %+v", id, in)
	return CollectorSubnet{}
}

// The shape Instaclustr actually creates: two subnets across two AZs, one route
// table serving both as the VPC's main table, default route to an internet
// gateway and no NAT.
func TestDiscoverCollectorSubnetsOnTheInstaclustrShape(t *testing.T) {
	stubVPC(t,
		vpcSubnetsXML(
			[3]string{"subnet-a", "10.10.0.0/18", "us-east-1a"},
			[3]string{"subnet-b", "10.10.64.0/18", "us-east-1b"}),
		routeTablesXML(fakeRouteTable{
			id: "rtb-main", main: true,
			routes: [][4]string{
				{"10.10.0.0/16", "local", "", "active"},
				{"0.0.0.0/0", "igw-1", "", "active"},
			},
		}))

	got, err := DiscoverCollectorSubnets(context.Background(), ec2Client(t), "vpc-1")
	if err != nil {
		t.Fatalf("DiscoverCollectorSubnets: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d subnets, want 2: %+v", len(got), got)
	}
	a := findSubnet(t, got, "subnet-a")
	if a.CIDR != "10.10.0.0/18" || a.AZ != "us-east-1a" {
		t.Errorf("subnet-a = %+v, want the CIDR and AZ from the API", a)
	}
	// The main table applies even though nothing is explicitly associated —
	// missing that would report this whole VPC as unroutable.
	if !a.RoutesOffVPC() || a.InternetRoute != "igw-1" {
		t.Errorf("subnet-a route = %q, want igw-1 via the main table", a.InternetRoute)
	}
	if !a.NeedsPublicIP {
		t.Error("an internet gateway blackholes a task with no public address, so NeedsPublicIP must be true")
	}
}

func TestDiscoverCollectorSubnetsPrefersAnExplicitAssociation(t *testing.T) {
	stubVPC(t,
		vpcSubnetsXML([3]string{"subnet-a", "10.10.0.0/18", "us-east-1a"}),
		routeTablesXML(
			fakeRouteTable{id: "rtb-main", main: true,
				routes: [][4]string{{"0.0.0.0/0", "igw-1", "", "active"}}},
			fakeRouteTable{id: "rtb-private", subnets: []string{"subnet-a"},
				routes: [][4]string{{"0.0.0.0/0", "", "nat-9", "active"}}},
		))

	got, err := DiscoverCollectorSubnets(context.Background(), ec2Client(t), "vpc-1")
	if err != nil {
		t.Fatalf("DiscoverCollectorSubnets: %v", err)
	}
	a := findSubnet(t, got, "subnet-a")
	if a.InternetRoute != "nat-9" {
		t.Errorf("route = %q, want the explicitly associated table's nat-9", a.InternetRoute)
	}
	if a.NeedsPublicIP {
		t.Error("a NAT gateway carries a private task, so NeedsPublicIP must be false")
	}
}

func TestDiscoverCollectorSubnetsReportsAnIsolatedSubnet(t *testing.T) {
	stubVPC(t,
		vpcSubnetsXML([3]string{"subnet-a", "10.10.0.0/18", "us-east-1a"}),
		routeTablesXML(fakeRouteTable{id: "rtb-main", main: true,
			routes: [][4]string{{"10.10.0.0/16", "local", "", "active"}}}))

	got, err := DiscoverCollectorSubnets(context.Background(), ec2Client(t), "vpc-1")
	if err != nil {
		t.Fatalf("DiscoverCollectorSubnets: %v", err)
	}
	if findSubnet(t, got, "subnet-a").RoutesOffVPC() {
		t.Error("a subnet with only the local route does not reach the internet")
	}
	if len(RoutableSubnets(got)) != 0 {
		t.Error("RoutableSubnets should drop it")
	}
}

// A blackholed default route is present but carries nothing — treating it as a
// way out would deploy a task that silently cannot reach anything.
func TestDiscoverCollectorSubnetsIgnoresABlackholedRoute(t *testing.T) {
	stubVPC(t,
		vpcSubnetsXML([3]string{"subnet-a", "10.10.0.0/18", "us-east-1a"}),
		routeTablesXML(fakeRouteTable{id: "rtb-main", main: true,
			routes: [][4]string{{"0.0.0.0/0", "igw-gone", "", "blackhole"}}}))

	got, err := DiscoverCollectorSubnets(context.Background(), ec2Client(t), "vpc-1")
	if err != nil {
		t.Fatalf("DiscoverCollectorSubnets: %v", err)
	}
	if findSubnet(t, got, "subnet-a").RoutesOffVPC() {
		t.Error("a blackholed default route is not a route off the VPC")
	}
}

// A virtual private gateway carries a default route without reaching the
// internet, so it must not be mistaken for one.
func TestDiscoverCollectorSubnetsRejectsANonInternetGateway(t *testing.T) {
	stubVPC(t,
		vpcSubnetsXML([3]string{"subnet-a", "10.10.0.0/18", "us-east-1a"}),
		routeTablesXML(fakeRouteTable{id: "rtb-main", main: true,
			routes: [][4]string{{"0.0.0.0/0", "vgw-1", "", "active"}}}))

	got, err := DiscoverCollectorSubnets(context.Background(), ec2Client(t), "vpc-1")
	if err != nil {
		t.Fatalf("DiscoverCollectorSubnets: %v", err)
	}
	if findSubnet(t, got, "subnet-a").RoutesOffVPC() {
		t.Error("a virtual private gateway is not an internet gateway")
	}
}

func TestDiscoverCollectorSubnetsRefusesAnEmptyVPC(t *testing.T) {
	if _, err := DiscoverCollectorSubnets(context.Background(), ec2Client(t), ""); err == nil {
		t.Fatal("expected a refusal without a VPC id")
	}

	stubVPC(t, vpcSubnetsXML(), routeTablesXML())
	_, err := DiscoverCollectorSubnets(context.Background(), ec2Client(t), "vpc-empty")
	if err == nil || !strings.Contains(err.Error(), "no subnets") {
		t.Fatalf("expected the no-subnets refusal, got %v", err)
	}
}

func TestSubnetIDsAndRoutableOrderIsStable(t *testing.T) {
	in := []CollectorSubnet{
		{ID: "subnet-a", InternetRoute: "igw-1"},
		{ID: "subnet-b"},
		{ID: "subnet-c", InternetRoute: "nat-1"},
	}
	got := SubnetIDs(RoutableSubnets(in))
	if len(got) != 2 || got[0] != "subnet-a" || got[1] != "subnet-c" {
		t.Errorf("got %v, want [subnet-a subnet-c] in discovery order", got)
	}
}
