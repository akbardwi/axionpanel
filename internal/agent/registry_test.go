package agent

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestRegistryRunsRegisteredOperation(t *testing.T) {
	r := NewRegistry()
	r.Register("test.echo", func(ctx context.Context, p json.RawMessage, m RequestMeta) (any, error) {
		var in struct{ X int }
		if err := decodeParams(p, &in); err != nil {
			return nil, err
		}
		return in.X, nil
	})
	got, err := r.Run(context.Background(), "test.echo", json.RawMessage(`{"x":42}`), RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if got != 42 {
		t.Fatalf("got %v, want 42", got)
	}
}

func TestRegistryRejectsUnknownOperation(t *testing.T) {
	r := NewRegistry()
	_, err := r.Run(context.Background(), "exec", nil, RequestMeta{})
	var oe *OpError
	if !errors.As(err, &oe) {
		t.Fatalf("expected *OpError, got %T", err)
	}
	if oe.Code != ErrNotFound {
		t.Fatalf("code = %q, want not_found", oe.Code)
	}
	if oe.HTTPStatus() != 404 {
		t.Fatalf("status = %d, want 404", oe.HTTPStatus())
	}
}

func TestRegistryRejectsDuplicateRegistration(t *testing.T) {
	r := NewRegistry()
	r.Register("test.a", func(context.Context, json.RawMessage, RequestMeta) (any, error) { return nil, nil })
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on duplicate registration")
		}
	}()
	r.Register("test.a", func(context.Context, json.RawMessage, RequestMeta) (any, error) { return nil, nil })
}

func TestRegistryRejectsNonCatalogName(t *testing.T) {
	r := NewRegistry()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on malformed operation name")
		}
	}()
	r.Register("../etc/passwd", func(context.Context, json.RawMessage, RequestMeta) (any, error) { return nil, nil })
}

func TestDecodeParamsRejectsUnknownFields(t *testing.T) {
	var in struct{ A string }
	err := decodeParams(json.RawMessage(`{"a":"x","b":"y"}`), &in)
	var oe *OpError
	if !errors.As(err, &oe) || oe.Code != ErrInvalidParams {
		t.Fatalf("err = %v, want invalid_params", err)
	}
	if _, ok := oe.Details.(map[string]string)["unknown_field"]; !ok {
		t.Fatalf("details = %#v, want unknown_field", oe.Details)
	}
}

func TestDecodeParamsRejectsTrailingData(t *testing.T) {
	var in struct{ A string }
	if err := decodeParams(json.RawMessage(`{"a":"x"} {"a":"y"}`), &in); err == nil {
		t.Fatal("expected error for trailing JSON")
	}
}

func TestDecodeParamsAcceptsEmptyBody(t *testing.T) {
	var in struct{}
	if err := decodeParams(nil, &in); err != nil {
		t.Fatalf("empty body rejected: %v", err)
	}
}

func TestDecodeParamsRejectsNonObject(t *testing.T) {
	for _, raw := range []string{`null`, `[]`, `1`, `"x"`, `true`} {
		var in struct{}
		if err := decodeParams(Params(raw), &in); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}

func TestRegistryContainsOperationPanics(t *testing.T) {
	r := NewRegistry()
	r.Register("test.panic", func(context.Context, Params, RequestMeta) (any, error) { panic("SECRET") })
	got, err := r.Run(context.Background(), "test.panic", nil, RequestMeta{})
	var oe *OpError
	if got != nil || !errors.As(err, &oe) || oe.Code != ErrInternal || oe.Message != "unexpected failure" || oe.Details != nil {
		t.Fatalf("got=%v err=%#v", got, err)
	}
}
