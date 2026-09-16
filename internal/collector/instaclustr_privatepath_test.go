package collector

import (
	"errors"
	"net"
	"testing"
)

// stubRoutes answers the route lookup from a table of destination -> local
// source address, so the decision can be tested on a machine that has neither
// a VPN nor a peered VPC. A destination missing from the table errors, which
// is what an unroutable address looks like.
func stubRoutes(t *testing.T, routes map[string]string) {
	t.Helper()
	real := localSourceFor
	localSourceFor = func(addr string) (net.IP, error) {
		src, ok := routes[addr]
		if !ok {
			return nil, errors.New("no route to host")
		}
		return net.ParseIP(src), nil
	}
	t.Cleanup(func() { localSourceFor = real })
}

// Running on a bastion inside the cluster's VPC: this machine's own address
// sits in the cluster block, which settles it outright.
func TestPrivatePathWhenThisMachineIsInsideTheClusterNetwork(t *testing.T) {
	stubRoutes(t, map[string]string{
		"1.1.1.1":    "10.10.9.9",
		"10.10.0.1":  "10.10.9.9",
		"10.10.64.1": "10.10.9.9",
	})
	src, how, ok := PrivatePathToCluster([]string{"10.10.0.0/16"})
	if !ok {
		t.Fatal("an address inside the cluster network should count as a private path")
	}
	if src.String() != "10.10.9.9" {
		t.Fatalf("source = %s, want 10.10.9.9", src)
	}
	if how == "" {
		t.Fatal("expected an explanation of how the cluster is reachable")
	}
}

// On a VPN: internet traffic leaves one interface, cluster traffic another.
// The differing source address is the tell.
func TestPrivatePathWhenClusterTrafficLeavesADifferentInterface(t *testing.T) {
	stubRoutes(t, map[string]string{
		"1.1.1.1":   "192.168.1.252", // home LAN, default route
		"10.10.0.1": "100.109.153.8", // VPN interface
	})
	src, how, ok := PrivatePathToCluster([]string{"10.10.0.0/16"})
	if !ok {
		t.Fatal("a distinct source for the cluster network should count as a private path")
	}
	if src.String() != "100.109.153.8" {
		t.Fatalf("source = %s, want the VPN address", src)
	}
	if how == "" {
		t.Fatal("expected an explanation")
	}
}

// The failing case this ticket exists for: no VPN, no peering. Cluster
// traffic would take the plain internet route, and a private-network cluster
// has nothing listening out there.
func TestNoPrivatePathWhenClusterTrafficTakesTheDefaultRoute(t *testing.T) {
	stubRoutes(t, map[string]string{
		"1.1.1.1":   "192.168.1.252",
		"10.10.0.1": "192.168.1.252",
	})
	if _, _, ok := PrivatePathToCluster([]string{"10.10.0.0/16"}); ok {
		t.Fatal("the default route is not a private path to the cluster")
	}
}

// Several CIDRs: one reachable block is enough.
func TestPrivatePathAcceptsAnyReachableNetwork(t *testing.T) {
	stubRoutes(t, map[string]string{
		"1.1.1.1":   "192.168.1.252",
		"10.10.0.1": "192.168.1.252", // default route, no good
		"10.20.0.1": "100.109.153.8", // VPN
	})
	_, _, ok := PrivatePathToCluster([]string{"10.10.0.0/16", "10.20.0.0/16"})
	if !ok {
		t.Fatal("a reachable second network should still count")
	}
}

// An unrecognised route still yields the source address the OS would use, so
// the caller can allowlist the address the cluster actually sees rather than
// this machine's public egress address. "Not recognised" is not "unreachable".
func TestUnrecognisedRouteStillReturnsTheSourceAddress(t *testing.T) {
	stubRoutes(t, map[string]string{
		"1.1.1.1":   "192.168.1.252",
		"10.10.0.1": "192.168.1.252",
	})
	src, _, ok := PrivatePathToCluster([]string{"10.10.0.0/16"})
	if ok {
		t.Fatal("the default route should not be recognised as private")
	}
	if src == nil || src.String() != "192.168.1.252" {
		t.Fatalf("src = %v, want the routed source 192.168.1.252 even when unrecognised", src)
	}
}

func TestNoPrivatePathWithoutAnyClusterNetwork(t *testing.T) {
	stubRoutes(t, map[string]string{"1.1.1.1": "192.168.1.252"})
	if _, _, ok := PrivatePathToCluster(nil); ok {
		t.Fatal("no CIDRs means nothing to route to")
	}
	if _, _, ok := PrivatePathToCluster([]string{"not-a-cidr"}); ok {
		t.Fatal("an unparseable CIDR must not read as reachable")
	}
}
