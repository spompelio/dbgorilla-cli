package collector

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// stubRecovery swaps the pg_is_in_recovery() probe for a canned map of
// host -> in-recovery, restoring the real one when the test ends. A host
// missing from the map answers with an error, standing in for a node the
// probe cannot reach.
func stubRecovery(t *testing.T, answers map[string]bool) *[]string {
	t.Helper()
	real := hostInRecovery
	probed := &[]string{}
	hostInRecovery = func(_ context.Context, host string, _ int, _ string) (bool, error) {
		*probed = append(*probed, host)
		v, ok := answers[host]
		if !ok {
			return false, errors.New("dial tcp: i/o timeout")
		}
		return v, nil
	}
	t.Cleanup(func() { hostInRecovery = real })
	return probed
}

// The cluster API lists nodes in no meaningful order, so the primary is as
// likely to be second as first. Taking the first node is what broke the
// install: CREATE ROLE on a standby fails with SQLSTATE 25006.
func TestPrimaryHostPicksTheWriterWhenTheReplicaIsListedFirst(t *testing.T) {
	stubRecovery(t, map[string]bool{
		"10.0.0.1": true,  // standby, listed first
		"10.0.0.2": false, // primary
	})
	got, err := PrimaryHost(context.Background(), []string{"10.0.0.1", "10.0.0.2"}, 5432, "pw")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "10.0.0.2" {
		t.Fatalf("got %q, want the primary 10.0.0.2", got)
	}
}

func TestPrimaryHostKeepsTheWriterWhenItIsListedFirst(t *testing.T) {
	probed := stubRecovery(t, map[string]bool{
		"10.0.0.1": false,
		"10.0.0.2": true,
	})
	got, err := PrimaryHost(context.Background(), []string{"10.0.0.1", "10.0.0.2"}, 5432, "pw")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "10.0.0.1" {
		t.Fatalf("got %q, want 10.0.0.1", got)
	}
	// Stops at the writer rather than probing every node.
	if len(*probed) != 1 {
		t.Fatalf("probed %v, want to stop at the first writer", *probed)
	}
}

// A one-node cluster is its own primary; probing would only add a round trip
// to the common case.
func TestPrimaryHostReturnsASingleNodeWithoutProbing(t *testing.T) {
	probed := stubRecovery(t, map[string]bool{})
	got, err := PrimaryHost(context.Background(), []string{"10.0.0.9"}, 5432, "pw")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "10.0.0.9" {
		t.Fatalf("got %q, want 10.0.0.9", got)
	}
	if len(*probed) != 0 {
		t.Fatalf("probed %v, want no probe for a single node", *probed)
	}
}

// Mid-failover a cluster can have no writer at all. The error has to name
// what was tried, because SQLSTATE 25006 further down explains nothing.
func TestPrimaryHostReportsEveryNodeWhenNoneIsTheWriter(t *testing.T) {
	stubRecovery(t, map[string]bool{
		"10.0.0.1": true,
		"10.0.0.2": true,
	})
	_, err := PrimaryHost(context.Background(), []string{"10.0.0.1", "10.0.0.2"}, 5432, "pw")
	if err == nil {
		t.Fatal("expected an error when no node is the primary")
	}
	for _, want := range []string{"10.0.0.1", "10.0.0.2", "standby", "pg_is_in_recovery"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
}

// An unreachable node must not end the search — the reachable one may still
// be the writer.
func TestPrimaryHostSkipsUnreachableNodes(t *testing.T) {
	stubRecovery(t, map[string]bool{
		"10.0.0.2": false, // 10.0.0.1 is absent, so it errors
	})
	got, err := PrimaryHost(context.Background(), []string{"10.0.0.1", "10.0.0.2"}, 5432, "pw")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "10.0.0.2" {
		t.Fatalf("got %q, want 10.0.0.2", got)
	}
}

func TestPrimaryHostRefusesAnEmptyCandidateList(t *testing.T) {
	if _, err := PrimaryHost(context.Background(), nil, 5432, "pw"); err == nil {
		t.Fatal("expected an error with no candidates")
	}
}

// Retrying costs a full dial of every node at connect_timeout each, so it has
// to be reserved for the failure a retry can actually fix: a firewall rule that
// has not started passing packets yet.
func TestRetriableProbeErrorOnlyCoversAnUnreachableNode(t *testing.T) {
	// Every node answered, and answered "standby" -- a complete answer. A
	// cluster mid-failover is re-run by the operator, not re-dialled in a loop.
	stubRecovery(t, map[string]bool{"10.0.0.1": true, "10.0.0.2": true})
	_, err := PrimaryHost(context.Background(), []string{"10.0.0.1", "10.0.0.2"}, 5432, "pw")
	if err == nil {
		t.Fatal("a cluster with no writer should fail")
	}
	if RetriableProbeError(err) {
		t.Fatal("an all-standby answer is deterministic; retrying it only delays the real error")
	}

	// One node unreachable: the firewall rule may simply not be live yet.
	stubRecovery(t, map[string]bool{"10.0.0.1": true})
	_, err = PrimaryHost(context.Background(), []string{"10.0.0.1", "10.0.0.2"}, 5432, "pw")
	if err == nil {
		t.Fatal("an unreachable node with no writer should fail")
	}
	if !RetriableProbeError(err) {
		t.Fatalf("an unreachable node is worth another attempt: %v", err)
	}

	// Nothing to probe at all is a caller error, not a propagation delay.
	_, err = PrimaryHost(context.Background(), nil, 5432, "pw")
	if err == nil || RetriableProbeError(err) {
		t.Fatalf("no candidates is deterministic, got %v", err)
	}
}
