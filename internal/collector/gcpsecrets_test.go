package collector

import (
	"encoding/base64"
	"strings"
	"testing"
)

// The CLI-side secret lifecycle: values travel to Secret Manager directly and
// only in request bodies — never through Infrastructure Manager, a URL, or an
// error message.

const (
	secServerPath = "/v1/projects/p/secrets/dbg-server-secret"
	secDBPath     = "/v1/projects/p/secrets/dbg-db-password"
	secKeyPath    = "/v1/projects/p/secrets/dbg-instaclustr-api-key"
	secCreatePath = "/v1/projects/p/secrets"
)

func TestGcpSecretIDs_MatchTheTemplateNamingContract(t *testing.T) {
	got := strings.Join(GcpSecretIDs("dbg"), ",")
	if got != "dbg-server-secret,dbg-db-password,dbg-instaclustr-api-key" {
		t.Fatalf("secret ids = %s — the template addresses secrets by these names", got)
	}
}

func TestEnsureGcpSecrets_CreatesAndWritesEachValue(t *testing.T) {
	f := newGCPFake(t).
		on("POST", secCreatePath, 200, "{}").
		on("POST", secServerPath+":addVersion", 200, "{}").
		on("POST", secDBPath+":addVersion", 200, "{}").
		on("POST", secKeyPath+":addVersion", 200, "{}")
	stubGCP(t, f)

	err := EnsureGcpSecrets("p", "dbg", GcpSecretValues{
		ServerSecret:   "sek",
		DBPassword:     "monitor-pw",
		InstaclustrKey: "key456",
	})
	if err != nil {
		t.Fatalf("EnsureGcpSecrets: %v", err)
	}
	if f.called("POST", secCreatePath) != 3 {
		t.Errorf("want 3 creates, got %d", f.called("POST", secCreatePath))
	}
	for path, value := range map[string]string{
		secServerPath: "sek", secDBPath: "monitor-pw", secKeyPath: "key456",
	} {
		body := f.lastBody("POST", path+":addVersion")
		want := base64.StdEncoding.EncodeToString([]byte(value))
		if !strings.Contains(body, `"data":"`+want+`"`) {
			t.Errorf("%s version body should carry the value base64-encoded, got %s", path, body)
		}
	}
	// Values never enter a URL: the calls list records method + path + query.
	for _, c := range f.calls {
		for _, secret := range []string{"sek", "monitor-pw", "key456"} {
			if strings.Contains(c, secret) {
				t.Errorf("a secret value leaked into a request URL: %s", c)
			}
		}
	}
	if !strings.Contains(f.lastBody("POST", secCreatePath), `"automatic"`) {
		t.Errorf("secrets should use automatic replication, got %s", f.lastBody("POST", secCreatePath))
	}
}

func TestEnsureGcpSecrets_WritesThePlaceholderForAbsentCredentials(t *testing.T) {
	f := newGCPFake(t).
		on("POST", secCreatePath, 200, "{}").
		on("POST", secServerPath+":addVersion", 200, "{}").
		on("POST", secDBPath+":addVersion", 200, "{}").
		on("POST", secKeyPath+":addVersion", 200, "{}")
	stubGCP(t, f)

	if err := EnsureGcpSecrets("p", "dbg", GcpSecretValues{ServerSecret: "sek"}); err != nil {
		t.Fatalf("EnsureGcpSecrets: %v", err)
	}
	placeholder := base64.StdEncoding.EncodeToString([]byte(gcpSecretPlaceholder))
	for _, path := range []string{secDBPath, secKeyPath} {
		if !strings.Contains(f.lastBody("POST", path+":addVersion"), placeholder) {
			t.Errorf("%s should hold the placeholder so the boot script can always fetch it", path)
		}
	}
}

func TestEnsureGcpSecrets_ToleratesAlreadyExisting(t *testing.T) {
	f := newGCPFake(t).
		on("POST", secCreatePath, 409, `{"error":{"message":"already exists","status":"ALREADY_EXISTS"}}`).
		on("POST", secServerPath+":addVersion", 200, "{}").
		on("POST", secDBPath+":addVersion", 200, "{}").
		on("POST", secKeyPath+":addVersion", 200, "{}")
	stubGCP(t, f)

	if err := EnsureGcpSecrets("p", "dbg", GcpSecretValues{ServerSecret: "sek"}); err != nil {
		t.Fatalf("an existing secret should get a new version, not an error: %v", err)
	}
	if f.called("POST", secServerPath+":addVersion") != 1 {
		t.Error("the value must still be written when the secret pre-exists")
	}
}

func TestEnsureGcpSecrets_SurfacesWriteFailures(t *testing.T) {
	f := newGCPFake(t).
		on("POST", secCreatePath, 403, `{"error":{"message":"denied","status":"PERMISSION_DENIED"}}`)
	stubGCP(t, f)

	err := EnsureGcpSecrets("p", "dbg", GcpSecretValues{ServerSecret: "sek"})
	if err == nil || !strings.Contains(err.Error(), "could not create secret") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "sek") {
		t.Fatal("the error must not carry the secret value")
	}
}

func TestDeleteGcpSecrets_ToleratesAlreadyGone(t *testing.T) {
	f := newGCPFake(t).
		on("DELETE", secServerPath, 200, "{}").
		on("DELETE", secDBPath, 404, gcpNotFoundJSON).
		on("DELETE", secKeyPath, 200, "{}")
	stubGCP(t, f)

	if err := DeleteGcpSecrets("p", "dbg"); err != nil {
		t.Fatalf("DeleteGcpSecrets: %v", err)
	}
	for _, path := range []string{secServerPath, secDBPath, secKeyPath} {
		if f.called("DELETE", path) != 1 {
			t.Errorf("%s not deleted", path)
		}
	}
}

func TestDeleteGcpSecrets_ReportsRealFailures(t *testing.T) {
	f := newGCPFake(t).
		on("DELETE", secServerPath, 403, `{"error":{"message":"denied","status":"PERMISSION_DENIED"}}`).
		on("DELETE", secDBPath, 200, "{}").
		on("DELETE", secKeyPath, 200, "{}")
	stubGCP(t, f)

	err := DeleteGcpSecrets("p", "dbg")
	if err == nil || !strings.Contains(err.Error(), "dbg-server-secret") {
		t.Fatalf("err = %v", err)
	}
}

// An update that adds or rotates password auth rewrites the password only.
func TestEnsureGcpDBPassword_WritesOnlyThePassword(t *testing.T) {
	f := newGCPFake(t).
		on("POST", secCreatePath, 409, `{"error":{"code":409,"message":"already exists","status":"ALREADY_EXISTS"}}`).
		on("POST", secDBPath+":addVersion", 200, "{}")
	stubGCP(t, f)
	if err := EnsureGcpDBPassword("p", "dbg", "new-pw"); err != nil {
		t.Fatalf("EnsureGcpDBPassword: %v", err)
	}
	if f.called("POST", secServerPath+":addVersion") != 0 || f.called("POST", secKeyPath+":addVersion") != 0 {
		t.Error("only the password may be rewritten")
	}
	if !strings.Contains(f.lastBody("POST", secDBPath+":addVersion"), base64.StdEncoding.EncodeToString([]byte("new-pw"))) {
		t.Error("the new password should be the newest version")
	}
}
