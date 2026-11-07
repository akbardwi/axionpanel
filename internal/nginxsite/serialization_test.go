package nginxsite

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPlanDeadlineBeginsBeforeSerialization(t *testing.T) {
	c := unitFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	c.Reloader = func(context.Context) error { close(entered); <-release; return nil }
	m := manager(t, c)
	m.planTimeout = 60 * time.Millisecond
	done := make(chan error, 1)
	go func() { _, e := m.Apply(testCtx(t), op1, "example.com"); done <- e }()
	<-entered
	timer := time.AfterFunc(300*time.Millisecond, func() { close(release) })
	defer timer.Stop()
	start := time.Now()
	_, e := m.Plan("example.com")
	elapsed := time.Since(start)
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Errorf("plan error: %v", e)
	}
	if elapsed > 250*time.Millisecond || elapsed < 40*time.Millisecond {
		t.Errorf("plan waited %s, want its own bounded timeout rather than the blocked operation", elapsed)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}

func TestCloseAfterUseIsIdempotent(t *testing.T) {
	c := unitFixture(t)
	m := manager(t, c)
	if _, e := m.Apply(testCtx(t), op1, "example.com"); e != nil {
		t.Fatal(e)
	}
	if e := m.Close(); e != nil {
		t.Fatal(e)
	}
	if e := m.Close(); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, e := m.Status(ctx, "example.com"); e == nil {
		t.Fatal("closed manager served a read")
	}
}

func TestSameManagerWaitHonorsContext(t *testing.T) {
	for _, method := range []string{"status", "apply", "remove"} {
		t.Run(method, func(t *testing.T) {
			c := unitFixture(t)
			entered := make(chan struct{})
			release := make(chan struct{})
			c.Reloader = func(context.Context) error { close(entered); <-release; return nil }
			m := manager(t, c)
			done := make(chan error, 1)
			first := testCtx(t)
			go func() { _, e := m.Apply(first, op1, "example.com"); done <- e }()
			<-entered
			// Keep the first operation in-flight past the second's deadline, without
			// making test cleanup depend on a successful deadline implementation.
			timer := time.AfterFunc(300*time.Millisecond, func() { close(release) })
			defer timer.Stop()
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
			defer cancel()
			start := time.Now()
			var e error
			switch method {
			case "status":
				_, e = m.Status(ctx, "other.com")
			case "apply":
				_, e = m.Apply(ctx, op2, "other.com")
			case "remove":
				_, e = m.Remove(ctx, op2, "other.com")
			}
			elapsed := time.Since(start)
			if !errors.Is(e, context.DeadlineExceeded) {
				t.Errorf("deadline error: %v", e)
			}
			if elapsed > 150*time.Millisecond {
				t.Errorf("25ms operation waited %s behind same Manager", elapsed)
			}
			if e := <-done; e != nil {
				t.Fatal(e)
			}
		})
	}
}
