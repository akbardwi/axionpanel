package siteapi

import (
	"axionpanel/internal/auth"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDeleteFilesFieldForbiddenEvenFalse(t *testing.T) {
	e := setup(t, &testAgent{})
	w := e.req("POST", "/api/v1/sites", `{"domain":"example.com"}`)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	w = e.req("DELETE", "/api/v1/sites/1", `{"confirm_domain":"example.com","delete_files":false}`)
	if w.Code != 400 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestPanelHostnameCannotBecomeSite(t *testing.T) {
	e := setup(t, &testAgent{})
	w := e.req("POST", "/api/v1/sites", `{"domain":"localhost"}`)
	if w.Code != 400 || count(t, e.db, `SELECT count(*) FROM sites`) != 0 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestFailedRemovalDoesNotAdvertiseRetainedSuccess(t *testing.T) {
	a := &testAgent{}
	e := setup(t, a)
	if w := e.req("POST", "/api/v1/sites", `{"domain":"example.com"}`); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	a.mutation = func(string, OperationParams) error { return errInvalidAgentResult }
	var response struct {
		RetainedContent bool `json:"retained_content"`
		Job             Job  `json:"job"`
	}
	w := e.req("DELETE", "/api/v1/sites/1", `{"confirm_domain":"example.com"}`)
	json.Unmarshal(w.Body.Bytes(), &response)
	if w.Code != 200 || response.Job.Status != "failed" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if response.RetainedContent {
		t.Fatal("failed removal advertised retained content")
	}
}

func TestJobReadScopedToActor(t *testing.T) {
	e := setup(t, &testAgent{})
	w := e.req("POST", "/api/v1/sites", `{"domain":"example.com"}`)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var created struct {
		Job Job `json:"job"`
	}
	json.Unmarshal(w.Body.Bytes(), &created)
	u, err := e.svc.Create(context.Background(), "viewer", "secret", "user")
	if err != nil {
		t.Fatal(err)
	}
	other, err := e.svc.CreateSession(context.Background(), u.ID, "192.0.2.2", "test")
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/api/v1/jobs/"+created.Job.ID, nil)
	r.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: other.Token})
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, r)
	if rec.Code != 404 {
		t.Fatalf("cross-actor job read %d %s", rec.Code, rec.Body)
	}
}
