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
			// Linked AND public — the combination the two axes exist to keep
			// apart. A cluster in the customer's own account still gets dialled
			// publicly from outside its VPC.
			name:       "linked account, public addresses",
			body:       shapeBody("acme-prod", "vpc-linked", false),
			wantLinked: true,
			wantVPC:    "vpc-linked",
		},
		{
			name:           "linked account, private network",
			body:           shapeBody("acme-prod", "vpc-linked", true),
			wantLinked:     true,
			wantPrivateNet: true,
			wantVPC:        "vpc-linked",
		},
		{
			// Mid-provision: the VPC does not exist yet, so the API reports
			// null for it. The account name still settles residency.
			name:       "linked account, mid-provision with no VPC yet",
			body:       shapeBody("acme-prod", "", false),
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
	got := discoverShape(t, shapeBody("", "vpc-linked", false))
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
      "providerAccountName": "acme-prod",
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
	if got.ProviderAccountName != "acme-prod" || !got.LinkedAccount() {
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

// A cluster's own network is reported under the settings block of whichever
// cloud it runs on. Reading only awsSettings left VpcID empty on every GCP and
// Azure cluster -- and with it LinkedAccount()'s fallback, which is the only
// residency signal a mid-provision cluster has.
func TestDiscoverReadsTheVirtualNetworkOnEveryCloud(t *testing.T) {
	cases := []struct{ name, settings, want string }{
		{"aws", `"awsSettings": [{"customVirtualNetworkId": "vpc-linked"}]`, "vpc-linked"},
		{"gcp", `"gcpSettings": [{"customVirtualNetworkId": "projects/p/global/networks/n"}]`, "projects/p/global/networks/n"},
		{"azure", `"azureSettings": [{"customVirtualNetworkId": "vnet-linked"}]`, "vnet-linked"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := discoverShape(t, fmt.Sprintf(`{
  "id": "c-1", "name": "orders", "status": "RUNNING",
  "postgresqlVersion": "18.4.0", "defaultUserPassword": "pw-1",
  "dataCentres": [{
    "cloudProvider": "%s", "region": "r-1",
    "providerAccountName": null,
    %s,
    "networks": [{"cidr": "10.10.0.0/16"}],
    "nodes": [{"id": "n1", "publicAddress": "203.0.113.10"}]
  }]
}`, tc.name, tc.settings))
			if got.VpcID != tc.want {
				t.Fatalf("VpcID=%q want %q", got.VpcID, tc.want)
			}
			// With no account name, the network id is what says "customer's
			// own account" -- so it has to survive on every cloud, not just AWS.
			if !got.LinkedAccount() {
				t.Fatal("a reported network id should read as a linked account")
			}
		})
	}
}

// The primary flag decides the cluster's cloud, region and network blocks, so
// a second flagged data centre must not silently take them over.
func TestDiscoverTakesTheFirstFlaggedPrimaryDataCentre(t *testing.T) {
	got := discoverShape(t, `{
  "id": "c-1", "name": "orders", "status": "RUNNING",
  "postgresqlVersion": "18.4.0", "defaultUserPassword": "pw-1",
  "dataCentres": [
    {
      "cloudProvider": "AWS_VPC", "region": "US_EAST_1",
      "networks": [{"cidr": "10.10.0.0/16"}],
      "interDataCentreReplication": [{"isPrimaryDataCentre": true}],
      "nodes": [{"id": "n1", "publicAddress": "203.0.113.10"}]
    },
    {
      "cloudProvider": "AWS_VPC", "region": "US_WEST_2",
      "networks": [{"cidr": "10.99.0.0/16"}],
      "interDataCentreReplication": [{"isPrimaryDataCentre": true}],
      "nodes": [{"id": "n2", "publicAddress": "203.0.113.20"}]
    }
  ]
}`)
	if got.Region != "US_EAST_1" {
		t.Fatalf("Region=%q want the FIRST flagged DC's US_EAST_1", got.Region)
	}
	if len(got.NetworkCIDRs) != 1 || got.NetworkCIDRs[0] != "10.10.0.0/16" {
		t.Fatalf("NetworkCIDRs=%v want the first flagged DC's blocks", got.NetworkCIDRs)
	}
}

// A data centre still provisioning can report neither cloud nor region. Those
// two ride into the collector config verbatim, so a sibling that has them beats
// rendering the config with neither.
func TestDiscoverFallsBackToASiblingForAnEmptyCloudAndRegion(t *testing.T) {
	got := discoverShape(t, `{
  "id": "c-1", "name": "orders", "status": "PROVISIONING",
  "postgresqlVersion": "18.4.0", "defaultUserPassword": "pw-1",
  "dataCentres": [
    {
      "cloudProvider": "", "region": "",
      "interDataCentreReplication": [{"isPrimaryDataCentre": true}],
      "nodes": [{"id": "n1", "publicAddress": "203.0.113.10"}]
    },
    {
      "cloudProvider": "AWS_VPC", "region": "US_EAST_1",
      "nodes": [{"id": "n2", "publicAddress": "203.0.113.20"}]
    }
  ]
}`)
	if got.CloudProvider != "AWS_VPC" || got.Region != "US_EAST_1" {
		t.Fatalf("cloud/region should fall through to a sibling, got %q/%q", got.CloudProvider, got.Region)
	}
}

// dcBody renders a two-data-centre cluster whose FIRST centre is flagged
// primary, so the fallback below is exercised on the centre that actually wins.
func dcBody(primaryCloud, primaryRegion, siblingCloud, siblingRegion string) string {
	return `{
  "id":"c-1","name":"orders","status":"RUNNING","postgresqlVersion":"18.4.0",
  "dataCentres":[
    {"cloudProvider":"` + primaryCloud + `","region":"` + primaryRegion + `",
     "interDataCentreReplication":[{"isPrimaryDataCentre":true}],
     "nodes":[{"id":"n1","publicAddress":"203.0.113.10"}]},
    {"cloudProvider":"` + siblingCloud + `","region":"` + siblingRegion + `",
     "nodes":[{"id":"n2","publicAddress":"203.0.113.11"}]}
  ]}`
}

// A data centre mid-provision reports an empty cloud, and a sibling fills it.
// What a sibling must never do is erase something the primary did report: the
// primary's own region is the accurate answer for the primary.
func TestPrimaryDataCentreFallbackNeverErasesAKnownValue(t *testing.T) {
	creds := InstaclustrCreds{Username: "u", APIKey: "key123"}
	const path = "GET /cluster-management/v2/resources/applications/postgresql/clusters/v2/c-1"

	for _, tc := range []struct {
		name                  string
		body                  string
		wantCloud, wantRegion string
	}{
		{
			// The regression: copying from a sibling that has nothing took its
			// empty region along and destroyed US_EAST_1.
			name:       "a sibling with nothing leaves the primary's region alone",
			body:       dcBody("", "US_EAST_1", "", ""),
			wantCloud:  "",
			wantRegion: "US_EAST_1",
		},
		{
			name:       "a sibling with a cloud fills only the empty cloud",
			body:       dcBody("", "US_EAST_1", "AWS_VPC", "US_WEST_2"),
			wantCloud:  "AWS_VPC",
			wantRegion: "US_EAST_1",
		},
		{
			name:       "a sibling fills both when the primary has neither",
			body:       dcBody("", "", "AWS_VPC", "US_WEST_2"),
			wantCloud:  "AWS_VPC",
			wantRegion: "US_WEST_2",
		},
		{
			name:       "a complete primary is never overwritten",
			body:       dcBody("AWS_VPC", "US_EAST_1", "GCP", "us-central1"),
			wantCloud:  "AWS_VPC",
			wantRegion: "US_EAST_1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubInstaclustr(t, map[string]icResp{path: {200, tc.body}})
			got, err := DiscoverInstaclustrCluster(context.Background(), creds, "c-1")
			if err != nil {
				t.Fatal(err)
			}
			if got.CloudProvider != tc.wantCloud {
				t.Errorf("CloudProvider = %q, want %q", got.CloudProvider, tc.wantCloud)
			}
			if got.Region != tc.wantRegion {
				t.Errorf("Region = %q, want %q", got.Region, tc.wantRegion)
			}
		})
	}
}
