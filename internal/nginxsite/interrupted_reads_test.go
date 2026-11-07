package nginxsite

import (
	"errors"
	"testing"
)

func TestInterruptedOperationPreventsMisleadingReads(t *testing.T) {
	c := fixture(t)
	m := manager(t, c)
	j := journal{OperationID: op1, Action: "apply", Domain: "example.com", Digest: requestDigest("apply", "example.com", c.Listen), Phase: phasePending}
	if e := m.writeJournal(j); e != nil {
		t.Fatal(e)
	}
	if _, e := m.Status(testCtx(t), "example.com"); !errors.Is(e, ErrInterruptedOp) {
		t.Errorf("Status conceals interrupted mutation: %v", e)
	}
	if _, e := m.Plan("example.com"); !errors.Is(e, ErrInterruptedOp) {
		t.Errorf("Plan conceals interrupted mutation: %v", e)
	}
}
