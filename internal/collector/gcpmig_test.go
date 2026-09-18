package collector

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	migBase   = "/compute/v1/projects/p/regions/us-central1/instanceGroupManagers/dbg"
	waitPath  = "/compute/v1/projects/p/regions/us-central1/operations/op-9/wait"
	logsPath  = "/v2/entries:list"
	computeOp = `{"name":"op-9","status":"RUNNING"}`
	opDone    = `{"name":"op-9","status":"DONE"}`
)

func TestScaleGcpMig(t *testing.T) {
	f := newGCPFake(t).
		on("POST", migBase+"/resize", 200, computeOp).
		on("POST", waitPath, 200, opDone)
	stubGCP(t, f)
	if err := ScaleGcpMig("p", "us-central1", "dbg", 0); err != nil {
		t.Fatalf("scale: %v", err)
	}
	if c := f.lastCall("POST " + migBase + "/resize"); !strings.Contains(c, "size=0") {
		t.Errorf("resize must carry the target size, got %s", c)
	}
	if f.called("POST", waitPath) != 1 {
		t.Error("the operation should be waited on")
	}
}

func TestRestartGcpMig_RecreatesEveryInstance(t *testing.T) {
	f := newGCPFake(t).
		on("POST", migBase+"/listManagedInstances", 200,
			`{"managedInstances":[{"instance":"zones/us-central1-b/instances/dbg-x1y2"},{"instance":"zones/us-central1-c/instances/dbg-a9z8"}]}`).
		on("POST", migBase+"/recreateInstances", 200, computeOp).
		on("POST", waitPath, 200, opDone)
	stubGCP(t, f)
	if err := RestartGcpMig("p", "us-central1", "dbg"); err != nil {
		t.Fatalf("restart: %v", err)
	}
	body := f.lastBody("POST", migBase+"/recreateInstances")
	for _, want := range []string{"dbg-x1y2", "dbg-a9z8"} {
		if !strings.Contains(body, want) {
			t.Errorf("recreate must name every instance, %s missing from %s", want, body)
		}
	}
}

func TestRestartGcpMig_StoppedGroupPointsAtStart(t *testing.T) {
	f := newGCPFake(t).on("POST", migBase+"/listManagedInstances", 200, `{"managedInstances":[]}`)
	stubGCP(t, f)
	err := RestartGcpMig("p", "us-central1", "dbg")
	if err == nil || !strings.Contains(err.Error(), "dbg collector start") {
		t.Fatalf("err = %v, want the start hint", err)
	}
	if f.called("POST", migBase+"/recreateInstances") != 0 {
		t.Error("nothing to recreate must mean no recreate call")
	}
}

func TestWaitComputeOperation_SurfacesTheOperationError(t *testing.T) {
	stubGCP(t, newGCPFake(t).
		on("POST", migBase+"/resize", 200, computeOp).
		on("POST", waitPath, 200, `{"name":"op-9","status":"DONE","error":{"errors":[{"message":"QUOTA_EXCEEDED"}]}}`))
	err := ScaleGcpMig("p", "us-central1", "dbg", 1)
	if err == nil || !strings.Contains(err.Error(), "QUOTA_EXCEEDED") {
		t.Fatalf("err = %v, want the operation's error", err)
	}
}

func TestTailGcpLogs_PaginatesAndPrintsEachEntryOnce(t *testing.T) {
	ts := func(sec int) string {
		return time.Now().UTC().Add(-time.Minute + time.Duration(sec)*time.Second).Format(time.RFC3339Nano)
	}
	f := newGCPFake(t).
		on("POST", migBase+"/listManagedInstances", 200,
			`{"managedInstances":[{"instance":"zones/us-central1-b/instances/dbg-x1y2","id":"8574"}]}`).
		onSeq("POST", logsPath,
			gcpFakeResp{200, `{"entries":[
			{"insertId":"a","timestamp":"` + ts(0) + `","textPayload":"first line"},
			{"insertId":"b","timestamp":"` + ts(1) + `","jsonPayload":{"message":"second line"}}
		],"nextPageToken":"page2"}`},
			gcpFakeResp{200, `{"entries":[
			{"insertId":"b","timestamp":"` + ts(1) + `","jsonPayload":{"message":"second line"}},
			{"insertId":"c","timestamp":"` + ts(2) + `","jsonPayload":{"level":"info"}}
		]}`})
	stubGCP(t, f)

	out := captureStdout(t, func() {
		if err := TailGcpLogs("p", "us-central1", "dbg", false); err != nil {
			t.Fatalf("TailGcpLogs: %v", err)
		}
	})
	for _, want := range []string{"first line", "second line", `{"level":"info"}`} {
		if strings.Count(out, want) != 1 {
			t.Errorf("%q should print exactly once, got:\n%s", want, out)
		}
	}
	if f.called("POST", logsPath) != 2 {
		t.Errorf("both pages must be read, read %d", f.called("POST", logsPath))
	}
	// The second page continues the first: the token travels in the body.
	if !strings.Contains(f.lastBody("POST", logsPath), `"pageToken":"page2"`) {
		t.Errorf("the page token must be sent back, body: %s", f.lastBody("POST", logsPath))
	}
	// The filter names the group's instances by numeric id and the collector
	// container: the labels Container-Optimized OS actually attaches.
	first := f.bodies["POST "+logsPath][0]
	for _, want := range []string{`resource.labels.instance_id=(\"8574\")`, `cos.googleapis.com/container_name\"=\"dbg-collector\"`} {
		if !strings.Contains(first, want) {
			t.Errorf("filter should contain %s, got %s", want, first)
		}
	}
}

func TestTailGcpLogs_StoppedGroupPointsAtStart(t *testing.T) {
	f := newGCPFake(t).on("POST", migBase+"/listManagedInstances", 200, `{"managedInstances":[]}`)
	stubGCP(t, f)
	err := TailGcpLogs("p", "us-central1", "dbg", false)
	if err == nil || !strings.Contains(err.Error(), "dbg collector start") {
		t.Fatalf("err = %v, want the start hint", err)
	}
	if f.called("POST", logsPath) != 0 {
		t.Error("no instances means no log query")
	}
}

func TestWaitGcpMigStable_PollsUntilStable(t *testing.T) {
	f := newGCPFake(t).onSeq("GET", migBase,
		gcpFakeResp{200, `{"status":{"isStable":false}}`},
		gcpFakeResp{200, `{"status":{"isStable":true}}`})
	stubGCP(t, f)
	if err := WaitGcpMigStable("p", "us-central1", "dbg"); err != nil {
		t.Fatalf("wait: %v", err)
	}
	if f.called("GET", migBase) != 2 {
		t.Errorf("polled %d times, want 2", f.called("GET", migBase))
	}
}

func TestWaitGcpMigStable_BudgetRunsOutAsStillRolling(t *testing.T) {
	orig := computeOpTimeout
	computeOpTimeout = 0
	t.Cleanup(func() { computeOpTimeout = orig })
	stubGCP(t, newGCPFake(t).on("GET", migBase, 200, `{"status":{"isStable":false}}`))
	err := WaitGcpMigStable("p", "us-central1", "dbg")
	if !errors.Is(err, ErrGcpMigRolling) {
		t.Fatalf("err = %v, want ErrGcpMigRolling", err)
	}
}
