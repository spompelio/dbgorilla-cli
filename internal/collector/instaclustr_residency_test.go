package collector

import (
	"context"
	"fmt"
	"testing"
)

// shapeBody builds a cluster-detail payload with the fields that describe
// residency and network shape. The values mirror what the API returns: a
// cluster in Instaclustr's own account names the account "INSTACLUSTR" and
// reports no VPC, while a linked one names the customer's provider account
// and reports the VPC once provisioning has created it.
func shapeBody(providerAccount, vpc string, privateNetwork bool) string {
	account := "null"
	if providerAccount != "" {
		account = fmt.Sprintf("%q", providerAccount)
	}
	vpcID := "null"
	if vpc != "" {
		vpcID = fmt.Sprintf("%q", vpc)
	}
	return fmt.Sprintf(`{
  "id": "c-1", "name": "orders", "status": "RUNNING",
  "postgresqlVersion": "18.4.0", "defaultUserPassword": "pw-1",
  "privateNetworkCluster": %t,
  "dataCentres": [{
    "cloudProvider": "AWS_VPC", "region": "US_EAST_1",
    "providerAccountName": %s,
    "awsSettings": [{"customVirtualNetworkId": %s}],
    "networks": [{"cidr": "10.10.0.0/16", "primary": true}],
    "nodes": [
      {"id": "n1", "publicAddress": "203.0.113.10", "privateAddress": "10.10.3.1"}
    ]
  }]
}`, privateNetwork, account, vpcID)
}

func discoverShape(t *testing.T, body string) InstaclustrTarget {
	t.Helper()
	stubInstaclustr(t, map[string]icResp{"GET " + clusterPath: {200, body}})
	got, err := DiscoverInstaclustrCluster(context.Background(), InstaclustrCreds{Username: "u", APIKey: "k"}, "c-1")
	if err != nil {
		t.Fatalf("discover failed: %v", err)
	}
	return got
}

// The two axes are independent, and the recorded shapes prove it: residency
// is read from providerAccountName, the address side from
// privateNetworkCluster, and neither one implies the other.
func TestDiscoverReadsResidencyAndNetworkShapeIndependently(t *testing.T) {
	cases := []struct {
		name           string
		body           string
		wantLinked     bool
		wantPrivateNet bool
		wantVPC        string
	}{
		{
			name:       "their account, public addresses",
			body:       shapeBody("INSTACLUSTR", "", false),
			wantLinked: false,
		},
		{
			name:           "their account, private network",
			body:           shapeBody("INSTACLUSTR", "", true),
			wantLinked:     false,
			wantPrivateNet: true,
		},
		{
			// The live BYOC fixture: linked AND public. A cluster in our own
			// account still gets dialled publicly from outside its VPC.
			name:       "linked account, public addresses",
			body:       shapeBody("dbgorilla-byoc", "vpc-0ee7a71a1bf660ca3", false),
			wantLinked: true,
			wantVPC:    "vpc-0ee7a71a1bf660ca3",
		},
		{
			name:           "linked account, private network",
			body:           shapeBody("dbgorilla-byoc", "vpc-0ee7a71a1bf660ca3", true),
			wantLinked:     true,
			wantPrivateNet: true,
			wantVPC:        "vpc-0ee7a71a1bf660ca3",
		},
		{
			// Mid-provision: the VPC does not exist yet, so the API reports
			// null for it. The account name still settles residency.
			name:       "linked account, mid-provision with no VPC yet",
			body:       shapeBody("dbgorilla-byoc", "", false),
			wantLinked: true,
			wantVPC:    "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := discoverShape(t, tc.body)
			if got.LinkedAccount() != tc.wantLinked {
				t.Fatalf("LinkedAccount()=%v want %v (providerAccountName=%q vpc=%q)",
					got.LinkedAccount(), tc.wantLinked, got.ProviderAccountName, got.VpcID)
			}
			if got.PrivateNetworkCluster != tc.wantPrivateNet {
				t.Fatalf("PrivateNetworkCluster=%v want %v", got.PrivateNetworkCluster, tc.wantPrivateNet)
			}
			if got.VpcID != tc.wantVPC {
				t.Fatalf("VpcID=%q want %q", got.VpcID, tc.wantVPC)
			}
			if len(got.NetworkCIDRs) != 1 || got.NetworkCIDRs[0] != "10.10.0.0/16" {
				t.Fatalf("NetworkCIDRs=%v want [10.10.0.0/16]", got.NetworkCIDRs)
			}
		})
	}
}

// With no account name at all, a reported VPC is the only residency signal
// left — it stands in rather than defaulting to Instaclustr's account.
func TestLinkedAccountFallsBackToTheVPCWhenNoAccountNameIsReported(t *testing.T) {
	got := discoverShape(t, shapeBody("", "vpc-0ee7a71a1bf660ca3", false))
	if !got.LinkedAccount() {
		t.Fatal("a reported VPC with no account name should still read as linked")
	}
	got = discoverShape(t, shapeBody("", "", false))
	if got.LinkedAccount() {
		t.Fatal("no account name and no VPC should not read as linked")
	}
}

// Multi-region: residency, VPC and CIDR come from the primary data centre,
// matching how the provider crate reads a multi-DC cluster.
func TestDiscoverReadsResidencyFromThePrimaryDataCentre(t *testing.T) {
	body := `{
  "id": "c-1", "name": "orders", "status": "RUNNING",
  "postgresqlVersion": "18.4.0", "defaultUserPassword": "pw-1",
  "privateNetworkCluster": false,
  "dataCentres": [
    {
      "cloudProvider": "AWS_VPC", "region": "US_WEST_2",
      "providerAccountName": "INSTACLUSTR",
      "awsSettings": [{"customVirtualNetworkId": null}],
      "networks": [{"cidr": "10.99.0.0/16"}],
      "interDataCentreReplication": [{"isPrimaryDataCentre": false}],
      "nodes": [{"id": "n2", "publicAddress": "203.0.113.20", "privateAddress": "10.99.0.2"}]
    },
    {
      "cloudProvider": "AWS_VPC", "region": "US_EAST_1",
      "providerAccountName": "dbgorilla-byoc",
      "awsSettings": [{"customVirtualNetworkId": "vpc-primary"}],
      "networks": [{"cidr": "10.10.0.0/16"}],
      "interDataCentreReplication": [{"isPrimaryDataCentre": true}],
      "nodes": [{"id": "n1", "publicAddress": "203.0.113.10", "privateAddress": "10.10.3.1"}]
    }
  ]
}`
	got := discoverShape(t, body)
	if got.Region != "US_EAST_1" {
		t.Fatalf("Region=%q want the primary DC's US_EAST_1", got.Region)
	}
	if got.ProviderAccountName != "dbgorilla-byoc" || !got.LinkedAccount() {
		t.Fatalf("residency should come from the primary DC, got %q", got.ProviderAccountName)
	}
	if got.VpcID != "vpc-primary" {
		t.Fatalf("VpcID=%q want vpc-primary", got.VpcID)
	}
	// Nodes still flatten across every data centre.
	if len(got.Nodes) != 2 {
		t.Fatalf("got %d nodes, want both DCs' nodes", len(got.Nodes))
	}
}
