package siteapi

import (
	"strings"
	"testing"
)

func TestCompletionFailureDoesNotCommitPartialTerminalState(t *testing.T) {
	e := setup(t, &testAgent{})
	exec(t, e.db, `CREATE TRIGGER job_finish_fail BEFORE UPDATE ON jobs WHEN NEW.status='succeeded' BEGIN SELECT RAISE(ABORT,'offline'); END`)
	w := e.req("POST", "/api/v1/sites", `{"domain":"example.com"}`)
	if w.Code != 500 || !strings.Contains(w.Body.String(), "manual_reconciliation") {
		t.Fatalf("completion %d %s", w.Code, w.Body)
	}
	if count(t, e.db, `SELECT count(*) FROM sites WHERE status='active'`) != 0 {
		t.Fatal("partial site completion committed")
	}
	if count(t, e.db, `SELECT count(*) FROM jobs WHERE status='running'`) != 1 {
		t.Fatal("durable unresolved intent lost")
	}
}
