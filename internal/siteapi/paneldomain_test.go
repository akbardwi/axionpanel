package siteapi

import (
	"axionpanel/internal/auth"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConfiguredPanelHostnameRejectedBeforeDispatch(t *testing.T) {
	a := &testAgent{}
	e := setup(t, a)
	cfg := auth.DefaultConfig()
	cfg.Origin = "https://panel.example.com:7800"
	svc := auth.New(e.db, cfg, nil)
	h, err := New(e.db, a, svc)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.Register(mux)
	// GET uses the configured panel authority, not the untrusted Host header.
	r := httptest.NewRequest("GET", "/api/v1/sites/plan?domain=PANEL.EXAMPLE.COM", nil)
	r.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: e.sess.Token})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if len(a.calls) != 0 {
		t.Fatal("panel domain dispatched to agent")
	}
}
