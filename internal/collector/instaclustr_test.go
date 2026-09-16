package collector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// icFake routes "METHOD /path" to a canned response; unstubbed calls fail the
// test loudly (the awsFake/gcpFake shape).
type icFake struct {
	t         *testing.T
	responses map[string]icResp
	calls     []string
	// bodies records the request body of each non-GET call, in call order, so
	// a test can assert what a set-replacing PUT actually sent.
	bodies []string
}

type icResp struct {
	status int
	body   string
}

func (f *icFake) RoundTrip(req *http.Request) (*http.Response, error) {
	key := req.Method + " " + req.URL.Path
	f.calls = append(f.calls, key)
	if req.Method != http.MethodGet && req.Body != nil {
		raw, _ := io.ReadAll(req.Body)
		f.bodies = append(f.bodies, string(raw))
	}
	if user, _, ok := req.BasicAuth(); !ok || user == "" {
		f.t.Fatalf("request %s carried no basic auth", key)
	}
	resp, ok := f.responses[key]
	if !ok {
		f.t.Fatalf("unstubbed instaclustr call: %s", key)
	}
	return &http.Response{
		StatusCode: resp.status,
		Body:       io.NopCloser(strings.NewReader(resp.body)),
		Header:     make(http.Header),
	}, nil
}

// mutations returns the non-GET calls, so a test can assert nothing was
// written.
func (f *icFake) mutations() []string {
	var out []string
	for _, c := range f.calls {
		if !strings.HasPrefix(c, "GET ") {
			out = append(out, c)
		}
	}
	return out
}

func stubInstaclustr(t *testing.T, responses map[string]icResp) *icFake {
	t.Helper()
	fake := &icFake{t: t, responses: responses}
	orig := instaclustrClient.Transport
	instaclustrClient.Transport = fake
	t.Cleanup(func() { instaclustrClient.Transport = orig })
	return fake
}

const clusterPath = "/cluster-management/v2/resources/applications/postgresql/clusters/v2/c-1"

const clusterBody = `{
  "id": "c-1", "name": "orders", "status": "RUNNING",
  "postgresqlVersion": "18.4.0", "defaultUserPassword": "pw-1",
  "dataCentres": [{
    "cloudProvider": "AWS_VPC", "region": "US_EAST_1",
    "nodes": [
      {"id": "n1", "publicAddress": "203.0.113.10", "privateAddress": "10.0.0.10", "rack": "a", "deletionTime": null},
      {"id": "n2", "publicAddress": null, "privateAddress": null},
      {"id": "n3", "publicAddress": "203.0.113.11", "deletionTime": "2026-01-01T00:00:00Z"}
    ]
  }]
}`

func TestDiscoverInstaclustrCluster(t *testing.T) {
	creds := InstaclustrCreds{Username: "u", APIKey: "key123"}

	t.Run("flattens nodes, skipping deleted and address-less", func(t *testing.T) {
		stubInstaclustr(t, map[string]icResp{"GET " + clusterPath: {200, clusterBody}})
		got, err := DiscoverInstaclustrCluster(context.Background(), creds, "c-1")
		if err != nil {
			t.Fatal(err)
		}
		if got.Name != "orders" || got.CloudProvider != "AWS_VPC" || got.Region != "US_EAST_1" {
			t.Fatalf("unexpected target: %+v", got)
		}
		if got.DefaultUserPassword != "pw-1" {
			t.Fatalf("default user password not captured")
		}
		if len(got.Nodes) != 1 || got.Nodes[0].PublicAddress != "203.0.113.10" {
			t.Fatalf("unexpected nodes: %+v", got.Nodes)
		}
		if got.Nodes[0].Host(true) != "10.0.0.10" || got.Nodes[0].Host(false) != "203.0.113.10" {
			t.Fatalf("Host() side selection wrong")
		}
	})

	t.Run("no addressable nodes is an actionable error", func(t *testing.T) {
		stubInstaclustr(t, map[string]icResp{"GET " + clusterPath: {200,
			`{"id":"c-1","status":"PROVISIONING","dataCentres":[{"nodes":[{"id":"n1"}]}]}`}})
		_, err := DiscoverInstaclustrCluster(context.Background(), creds, "c-1")
		if err == nil || !strings.Contains(err.Error(), "no addressable nodes") {
			t.Fatalf("expected no-addressable-nodes error, got %v", err)
		}
	})

	t.Run("401 names the key kind and where to make one", func(t *testing.T) {
		stubInstaclustr(t, map[string]icResp{"GET " + clusterPath: {401, `{"message":"bad key"}`}})
		_, err := DiscoverInstaclustrCluster(context.Background(), creds, "c-1")
		if err == nil || !strings.Contains(err.Error(), "provisioning API key") || !strings.Contains(err.Error(), "bad key") {
			t.Fatalf("expected credential guidance with the API's message, got %v", err)
		}
	})
}

func TestInstaclustrAdminDSNEscapesPassword(t *testing.T) {
	dsn := InstaclustrAdminDSN("203.0.113.10", 5432, "p@ss:w/rd")
	if !strings.Contains(dsn, "icpostgresql:p%40ss%3Aw%2Frd@203.0.113.10:5432") {
		t.Fatalf("password not URL-escaped: %s", dsn)
	}
	if !strings.Contains(dsn, "sslmode=require") || !strings.Contains(dsn, "connect_timeout=8") {
		t.Fatalf("missing dsn params: %s", dsn)
	}
}

func TestRedactPasswordScrubsBothForms(t *testing.T) {
	err := redactPassword(
		fmt.Errorf("syntax error near PASSWORD 'p''w' at position"),
		"p''w", "p'w",
	)
	if strings.Contains(err.Error(), "p''w") || strings.Contains(err.Error(), "p'w") {
		t.Fatalf("password survived redaction: %v", err)
	}
	if !strings.Contains(err.Error(), "[redacted]") {
		t.Fatalf("no redaction marker: %v", err)
	}
}

func TestRetriableRoleError(t *testing.T) {
	// The connection-failure wrap EnsureInstaclustrRole produces.
	connectErr := fmt.Errorf("%w to create the monitoring role: %w",
		errClusterUnreachable, errors.New("dial tcp: i/o timeout"))
	if !RetriableRoleError(connectErr) {
		t.Fatal("dial timeout should retry")
	}
	if RetriableRoleError(fmt.Errorf("creating role x failed: permission denied to create role")) {
		t.Fatal("a SQL failure is deterministic and must not retry")
	}
	// Recognition is structural (errors.Is), not prose-matching: an error that
	// merely mentions the words does not retry.
	if RetriableRoleError(fmt.Errorf("cannot connect to the cluster somewhere: i/o timeout")) {
		t.Fatal("only the tagged connection failure retries, not any error containing the phrase")
	}
}

func TestAllowCIDR(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.10":   "203.0.113.10/32",
		"203.0.113.0/24": "203.0.113.0/24",
		"2001:db8::1":    "2001:db8::1/128",
		" 203.0.113.10 ": "203.0.113.10/32",
		"2001:db8::/64":  "2001:db8::/64",
	} {
		got, err := AllowCIDR(in)
		if err != nil || got != want {
			t.Fatalf("AllowCIDR(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, wholeInternet := range []string{"0.0.0.0/0", "::/0"} {
		if _, err := AllowCIDR(wholeInternet); err == nil {
			t.Fatalf("AllowCIDR(%q) must refuse to allowlist the whole internet", wholeInternet)
		}
	}
	if _, err := AllowCIDR("<html>portal</html>"); err == nil {
		t.Fatal("garbage must be refused, not sent to the firewall API")
	}
}

func TestBuildInstaclustrRendersAndRoundTrips(t *testing.T) {
	target := InstaclustrTarget{
		ClusterID: "c-1", Name: "orders", CloudProvider: "AWS_VPC", Region: "US_EAST_1",
	}
	comp := BuildInstaclustrComponent(target, "203.0.113.10", 5432, nil, "", "", "someone", false, DBPasswordEnv)
	cfg := BuildInstaclustr("agent-1", "tenant-1", comp, Endpoints{})
	rendered, err := cfg.Render()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`type = "instaclustr"`,
		`cluster_id = "c-1"`,
		`provider = "AWS_VPC"`,
		`region = "US_EAST_1"`,
		`api_username = "someone"`,
		`api_key = "${INSTACLUSTR_API_KEY}"`,
		`user = "dbgorilla_monitor"`,
		`password = "${COLLECTOR_DB_PASSWORD}"`,
		`ssl_mode = "require"`,
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered config missing %q:\n%s", want, rendered)
		}
	}
	if strings.Contains(rendered, "use_private_addresses") {
		t.Fatalf("false use_private_addresses should be omitted:\n%s", rendered)
	}
	// The aws update path round-trips configs through StrictParseConfig; the
	// instaclustr keys must be modelled or an update would refuse them.
	if _, err := StrictParseConfig(rendered); err != nil {
		t.Fatalf("StrictParseConfig rejected the rendered config: %v", err)
	}
}

func TestAwsStackParamsWithInstaclustrComponents(t *testing.T) {
	target := InstaclustrTarget{
		ClusterID: "c-1", Name: "orders", CloudProvider: "AWS_VPC", Region: "US_EAST_1",
	}
	comp := BuildInstaclustrComponent(target, "203.0.113.10", 5432, nil, "", "", "someone", false, CloudDBPasswordEnv)
	params, secrets, err := AwsStackParams(AwsStackInput{
		AgentID: "agent-1", TenantID: "tenant-1", Image: "img@sha256:x",
		Region: "us-east-1", AccountID: "111122223333",
		Components:     []Component{comp},
		Subnets:        []string{"subnet-1"},
		SecurityGroup:  "sg-1",
		AssignPublicIP: "ENABLED",
		ServerSecret:   "sek",
		DBPassword:     "monitor-pw",
		InstaclustrKey: "key456",
		StableEgress:   true,
		VpcID:          "vpc-1",
		NatSubnetCidr:  "10.0.200.0/28",
	})
	if err != nil {
		t.Fatal(err)
	}
	if secrets["InstaclustrApiKey"] != "key456" || params["StableEgress"] != "ENABLED" ||
		params["VpcId"] != "vpc-1" || params["NatSubnetCidr"] != "10.0.200.0/28" {
		t.Fatalf("v1.1 params wrong: %v %v", params, secrets)
	}
	if params["InstaclustrApiKey"] != "" {
		t.Fatal("the API key must never enter the printable params map")
	}
	decoded, err := DecodeConfig(params["CollectorConfig"])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`type = "instaclustr"`,
		`api_key = "${INSTACLUSTR_API_KEY}"`,
		`password = "${DBG_DB_PASSWORD}"`, // the Fargate task's variable name
	} {
		if !strings.Contains(decoded, want) {
			t.Fatalf("stack config missing %q:\n%s", want, decoded)
		}
	}
	if strings.Contains(decoded, "key456") || strings.Contains(decoded, "monitor-pw") {
		t.Fatalf("a literal secret leaked into the stack config:\n%s", decoded)
	}
	// Every param must be in fargateParamKeys or UpgradeImage drops it.
	for k := range params {
		found := false
		for _, fk := range fargateParamKeys {
			if fk == k {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("parameter %s missing from fargateParamKeys — UpgradeImage would drop it", k)
		}
	}
}

func TestFirewallRules(t *testing.T) {
	creds := InstaclustrCreds{Username: "u", APIKey: "key123"}
	const listPath = "/cluster-management/v2/data-sources/cluster/c-1/network-firewall-rules/v2"
	const rulesPath = "/cluster-management/v2/resources/network-firewall-rules/v2/"
	listBody := `[{"clusterId":"c-1","firewallRules":[
		{"id":"r-1","clusterId":"c-1","network":"198.51.100.7/32","type":"POSTGRESQL","status":"RUNNING"}]}]`

	t.Run("ensure returns the existing rule without writing", func(t *testing.T) {
		fake := stubInstaclustr(t, map[string]icResp{"GET " + listPath: {200, listBody}})
		rule, created, err := EnsureFirewallRule(context.Background(), creds, "c-1", "198.51.100.7/32")
		if err != nil || created || rule.ID != "r-1" {
			t.Fatalf("rule=%+v created=%v err=%v", rule, created, err)
		}
		if len(fake.mutations()) != 0 {
			t.Fatalf("unexpected writes: %v", fake.mutations())
		}
	})

	t.Run("ensure creates a missing rule", func(t *testing.T) {
		stubInstaclustr(t, map[string]icResp{
			"GET " + listPath:   {200, listBody},
			"POST " + rulesPath: {202, `{"id":"r-2","clusterId":"c-1","network":"192.0.2.9/32","type":"POSTGRESQL","status":"GENESIS"}`},
		})
		rule, created, err := EnsureFirewallRule(context.Background(), creds, "c-1", "192.0.2.9/32")
		if err != nil || !created || rule.ID != "r-2" {
			t.Fatalf("rule=%+v created=%v err=%v", rule, created, err)
		}
	})

	t.Run("duplicate 409 converges by re-listing to the REAL rule", func(t *testing.T) {
		stubInstaclustr(t, map[string]icResp{
			"POST " + rulesPath: {409, `{"errors":[{"message":"A firewall rule of that type (POSTGRESQL) already exists for that network (198.51.100.7/32) in cluster (c-1)"}]}`},
			"GET " + listPath:   {200, listBody},
		})
		rule, err := AddInstaclustrFirewallRule(context.Background(), creds, "c-1", "198.51.100.7/32")
		if err != nil {
			t.Fatalf("409 duplicate should converge, got %v", err)
		}
		// The rule must carry its real id — a synthetic empty-id rule would
		// silently break refresh-firewall's rotation later.
		if rule.ID != "r-1" {
			t.Fatalf("expected the re-listed rule with its id, got %+v", rule)
		}
	})

	t.Run("delete tolerates already-gone", func(t *testing.T) {
		stubInstaclustr(t, map[string]icResp{
			"DELETE " + rulesPath + "r-9": {404, `{"message":"HTTP 404 Not Found"}`},
		})
		if err := DeleteInstaclustrFirewallRule(context.Background(), creds, "r-9"); err != nil {
			t.Fatalf("404 delete should converge, got %v", err)
		}
	})
}

func TestGcpDeployInputsWithInstaclustrComponents(t *testing.T) {
	target := InstaclustrTarget{
		ClusterID: "c-1", Name: "orders", CloudProvider: "GCP", Region: "us-central1",
	}
	comp := BuildInstaclustrComponent(target, "203.0.113.10", 5432, nil, "", "", "someone", false, CloudDBPasswordEnv)
	inputs, err := GcpDeployInputs(GcpStackInput{
		AgentID: "agent-1", TenantID: "tenant-1", Image: "img@sha256:x",
		Components:     []Component{comp},
		Network:        "projects/p/global/networks/default",
		Region:         "us-central1",
		DeploymentName: "dbgorilla-collector",
		Project:        "p",
		StableEgress:   true,
		NatSubnetCidr:  "10.10.200.0/28",
	})
	if err != nil {
		t.Fatal(err)
	}
	if inputs["stable_egress"] != "true" || inputs["nat_subnet_cidr"] != "10.10.200.0/28" {
		t.Fatalf("v1.3 inputs wrong: %v", inputs)
	}
	if inputs["database_roles"] != "false" {
		t.Fatal("an instaclustr install must not grant the Cloud SQL / AlloyDB project-wide roles")
	}
	if inputs["instaclustr_api_key"] != "" {
		t.Fatal("the API key must never enter the inputs map — it lives in Secret Manager")
	}
	decoded, err := DecodeConfig(inputs["collector_config"])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`type = "instaclustr"`,
		`api_key = "${INSTACLUSTR_API_KEY}"`,
		`password = "${DBG_DB_PASSWORD}"`, // the GCE boot script's variable name
	} {
		if !strings.Contains(decoded, want) {
			t.Fatalf("deploy config missing %q:\n%s", want, decoded)
		}
	}
}

func TestGcpDeploymentOutput(t *testing.T) {
	const (
		icDepPath = "/v1/projects/p/locations/us-central1/deployments/dbg"
		icRevPath = "/v1/projects/p/locations/us-central1/deployments/dbg/revisions/r-3"
	)
	depJSON := `{"name":"projects/p/locations/us-central1/deployments/dbg","state":"ACTIVE",` +
		`"latestRevision":"projects/p/locations/us-central1/deployments/dbg/revisions/r-3"}`

	t.Run("reads the output off the latest revision", func(t *testing.T) {
		f := newGCPFake(t).
			on("GET", icDepPath, 200, depJSON).
			on("GET", icRevPath, 200, `{"applyResults":{"outputs":{"egress_ip":{"value":"198.51.100.20"}}}}`)
		stubGCP(t, f)
		got, err := GcpDeploymentOutput("p", "us-central1", "dbg", "egress_ip")
		if err != nil {
			t.Fatalf("GcpDeploymentOutput: %v", err)
		}
		if got != "198.51.100.20" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("a missing output names stable egress", func(t *testing.T) {
		f := newGCPFake(t).
			on("GET", icDepPath, 200, depJSON).
			on("GET", icRevPath, 200, `{"applyResults":{"outputs":{}}}`)
		stubGCP(t, f)
		_, err := GcpDeploymentOutput("p", "us-central1", "dbg", "egress_ip")
		if err == nil || !strings.Contains(err.Error(), "stable egress") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("an empty output value is refused", func(t *testing.T) {
		f := newGCPFake(t).
			on("GET", icDepPath, 200, depJSON).
			on("GET", icRevPath, 200, `{"applyResults":{"outputs":{"egress_ip":{"value":""}}}}`)
		stubGCP(t, f)
		if _, err := GcpDeploymentOutput("p", "us-central1", "dbg", "egress_ip"); err == nil {
			t.Fatal("an empty egress_ip must be an error, not an empty allowlist entry")
		}
	})

	t.Run("no revision yet reads as still deploying", func(t *testing.T) {
		f := newGCPFake(t).
			on("GET", icDepPath, 200, `{"name":"x","state":"CREATING"}`)
		stubGCP(t, f)
		_, err := GcpDeploymentOutput("p", "us-central1", "dbg", "egress_ip")
		if err == nil || !strings.Contains(err.Error(), "still deploying") {
			t.Fatalf("err = %v", err)
		}
	})
}
