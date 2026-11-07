package main

import (
	"errors"
	"fmt"
	"time"

	"axionpanel/internal/agent"
	"axionpanel/internal/nginxsite"
)

// siteOptions are the trusted startup configuration for opt-in static sites.
// Every value is an operator-supplied CLI flag, never a request parameter.
type siteOptions struct {
	Enable      bool
	StateDir    string
	ContentDir  string
	ConfigDir   string
	NginxBinary string
	NginxConfig string
	NginxPrefix string
	Listen      string
}

// staticSitesHTTPTimeout keeps site mutations alive for the panel's 90s
// dispatch budget plus response, without widening read-only operations.
func staticSitesHTTPTimeout(enabled bool) time.Duration {
	if !enabled {
		return 0
	}
	return 100 * time.Second
}

func (o siteOptions) anySet() bool {
	return o.StateDir != "" || o.ContentDir != "" || o.ConfigDir != "" ||
		o.NginxBinary != "" || o.NginxConfig != "" || o.NginxPrefix != "" || o.Listen != ""
}

// configureRegistry registers site operations only when the full opt-in
// configuration and dedicated host policy are present. It never starts a
// listener or invokes nginx; the adapter is returned for the caller to close.
func configureRegistry(reg *agent.Registry, policy agent.Policy, o siteOptions) (*nginxsite.Manager, error) {
	if !o.Enable {
		if o.anySet() {
			return nil, errors.New("static-site paths may only be set together with --static-sites")
		}
		return nil, nil
	}
	required := []struct{ flag, value string }{
		{"--site-state-dir", o.StateDir},
		{"--site-content-dir", o.ContentDir},
		{"--site-config-dir", o.ConfigDir},
		{"--nginx-binary", o.NginxBinary},
		{"--nginx-config", o.NginxConfig},
		{"--nginx-prefix", o.NginxPrefix},
		{"--site-listen", o.Listen},
	}
	for _, r := range required {
		if r.value == "" {
			return nil, fmt.Errorf("%s is required when --static-sites is enabled", r.flag)
		}
	}
	if !policy.AllowStaticSites {
		return nil, errors.New("static sites require allow_static_sites = true in the host policy")
	}
	backend, err := nginxsite.New(nginxsite.Config{
		StateDir:    o.StateDir,
		ContentDir:  o.ContentDir,
		ConfigDir:   o.ConfigDir,
		NginxBinary: o.NginxBinary,
		NginxConfig: o.NginxConfig,
		Prefix:      o.NginxPrefix,
		Listen:      o.Listen,
	})
	if err != nil {
		return nil, err
	}
	agent.RegisterStaticSites(reg, backend)
	return backend, nil
}
