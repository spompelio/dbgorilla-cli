package collector

import (
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// Instaclustr's default user holds no membership in pg_read_all_data, and
// PostgreSQL 16+ requires ADMIN OPTION on a role to grant it. No install can
// clear that, so treating it as fatal blocked every install on a modern
// server — the role and its pg_monitor grant had already landed.
func TestReadAllDataGrantRefusedForLackOfPrivilegeOnlyWarns(t *testing.T) {
	warning, fatal := classifyReadAllDataGrant(
		&pgconn.PgError{Code: "42501", Message: `permission denied to grant role "pg_read_all_data"`},
		"dbgorilla_monitor",
	)
	if fatal {
		t.Fatal("42501 must not end the install: the role is usable without this grant")
	}
	for _, want := range []string{"dbgorilla_monitor", "pg_read_all_data", "SELECT granted on that table"} {
		if !strings.Contains(warning, want) {
			t.Fatalf("warning %q does not mention %q", warning, want)
		}
	}
	// The warning must not send an operator hunting a monitoring fault: those
	// paths are covered by pg_monitor and are genuinely unaffected.
	if !strings.Contains(warning, "unaffected") {
		t.Fatalf("warning %q should say what still works, not just what does not", warning)
	}
}

// Servers older than PG 14 have no such role at all — already tolerated, kept
// pinned so the refactor to a shared classifier did not drop it.
func TestReadAllDataGrantMissingRoleOnlyWarns(t *testing.T) {
	warning, fatal := classifyReadAllDataGrant(
		&pgconn.PgError{Code: "42704", Message: `role "pg_read_all_data" does not exist`},
		"dbgorilla_monitor",
	)
	if fatal {
		t.Fatal("42704 must not end the install")
	}
	if !strings.Contains(warning, "PostgreSQL 14") {
		t.Fatalf("warning %q should explain why the role is absent", warning)
	}
}

// Anything else is a real failure: a role the collector cannot use is worse
// than an install that stops and says so.
func TestOtherGrantFailuresStayFatal(t *testing.T) {
	for _, pgErr := range []*pgconn.PgError{
		{Code: "57P01", Message: "terminating connection due to administrator command"},
		{Code: "42P01", Message: "relation does not exist"},
	} {
		if warning, fatal := classifyReadAllDataGrant(pgErr, "dbgorilla_monitor"); !fatal || warning != "" {
			t.Fatalf("SQLSTATE %s should stay fatal, got warning %q fatal=%v", pgErr.Code, warning, fatal)
		}
	}
}

// A non-Postgres error (a dropped connection mid-statement) carries no
// SQLSTATE to reason about, so it cannot be waved through.
func TestNonPostgresGrantFailureStaysFatal(t *testing.T) {
	if _, fatal := classifyReadAllDataGrant(errors.New("write: broken pipe"), "dbgorilla_monitor"); !fatal {
		t.Fatal("an error with no SQLSTATE must stay fatal")
	}
}
