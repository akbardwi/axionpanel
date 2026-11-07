// Command agent is the AxionPanel privileged daemon. It accepts validated
// operation requests from the panel over a Unix socket whose peer UID the
// kernel reports, and executes only operations in its closed registry.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"axionpanel/internal/agent"
)

// version is set at link time with -X main.version=... . It is deliberately an
// uninitialised string so the linker can stamp it; when unset the daemon falls
// back to the agent package version. Both CLI and /v1/info use one value.
var version string

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		log.Fatal(startupMessage(err))
	}
}

// startupMessage produces a single "agent: " prefixed failure line. Errors
// from the agent package already carry the prefix; the prefix is only added
// when the original message lacks it.
func startupMessage(err error) string {
	msg := err.Error()
	if strings.HasPrefix(msg, "agent: ") {
		return msg
	}
	return "agent: " + msg
}

// run is the whole daemon lifecycle and never calls os.Exit, so tests can
// exercise flags, validation, startup and graceful shutdown directly.
func run(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("axionpanel-agent", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	socket := fs.String("socket", "/run/axionpanel/agent.sock", "absolute Unix socket path")
	policyPath := fs.String("policy", "/etc/axionpanel/agent.toml", "host policy file (optional; absent means deny by default)")
	allowUID := fs.String("allow-uid", "", "required: panel user name or numeric UID")
	socketGID := fs.String("socket-gid", "", "required: panel group name or numeric GID")
	showVersion := fs.Bool("version", false, "print version and exit")
	staticSites := fs.Bool("static-sites", false, "opt in to journal-backed static nginx sites (requires every --site-* and --nginx-* flag plus allow_static_sites policy)")
	siteStateDir := fs.String("site-state-dir", "", "private root-only journal/lock directory for static sites")
	siteContentDir := fs.String("site-content-dir", "", "managed static content root")
	siteConfigDir := fs.String("site-config-dir", "", "managed vhost config directory")
	nginxBinary := fs.String("nginx-binary", "", "absolute path to the trusted nginx binary")
	nginxConfig := fs.String("nginx-config", "", "absolute path to the isolated nginx main config")
	nginxPrefix := fs.String("nginx-prefix", "", "nginx -p prefix directory")
	siteListen := fs.String("site-listen", "", "literal ip:port static sites listen on")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if version == "" {
		version = agent.Version
	}
	agent.Version = version
	if *showVersion {
		fmt.Fprintln(os.Stdout, version)
		return nil
	}

	if *allowUID == "" {
		return errors.New("--allow-uid is required (panel user name or numeric UID)")
	}
	uid, err := resolveUID(*allowUID)
	if err != nil {
		return fmt.Errorf("peer uid: %w", err)
	}
	if uid == 0 {
		return errors.New("refusing root as the panel peer; the panel must run as its own user")
	}
	if *socketGID == "" {
		return errors.New("--socket-gid is required (panel group name or numeric GID)")
	}
	gid, err := resolveGID(*socketGID)
	if err != nil {
		return fmt.Errorf("socket gid: %w", err)
	}
	if gid == 0 {
		return errors.New("refusing root group for the agent socket; use a dedicated panel group")
	}

	policy := agent.Policy{}
	if *policyPath != "" {
		policy, err = agent.LoadPolicy(*policyPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				log.Printf("agent: no policy at %s; using deny-by-default", *policyPath)
				policy = agent.Policy{}
			} else {
				return err
			}
		}
	}

	registry := agent.NewRegistry()
	agent.RegisterBuiltins(registry)
	backend, err := configureRegistry(registry, policy, siteOptions{
		Enable:      *staticSites,
		StateDir:    *siteStateDir,
		ContentDir:  *siteContentDir,
		ConfigDir:   *siteConfigDir,
		NginxBinary: *nginxBinary,
		NginxConfig: *nginxConfig,
		NginxPrefix: *nginxPrefix,
		Listen:      *siteListen,
	})
	if err != nil {
		return fmt.Errorf("static sites: %w", err)
	}
	srv := &agent.Server{
		Registry:           registry,
		Policy:             policy,
		Socket:             *socket,
		SocketGID:          gid,
		AllowedUID:         uid,
		StaticSitesTimeout: staticSitesHTTPTimeout(backend != nil),
		Logger:             log.Printf,
	}
	if backend != nil {
		defer backend.Close()
	}

	ln, err := srv.Listen(ctx)
	if err != nil {
		return err
	}
	defer ln.Close()

	log.Printf("axionpanel agent %s ready (socket %s, peer uid %d, gid %d)", version, *socket, uid, gid)
	// Serve returns nil after a signal-driven graceful shutdown; that is a clean
	// stop (exit 0), not a failure. Only pre-Serve cancellation (Listen) reports
	// context.Canceled.
	if err := srv.Serve(ctx, ln); err != nil {
		return err
	}
	log.Print("agent: stopped")
	return nil
}

func resolveUID(value string) (uint32, error) {
	if n, err := strconv.ParseUint(value, 10, 32); err == nil {
		if strconv.FormatUint(n, 10) != value {
			return 0, errors.New("invalid numeric uid " + value)
		}
		return uint32(n), nil
	}
	u, err := user.Lookup(value)
	if err != nil {
		return 0, fmt.Errorf("cannot resolve user %q: %w", value, err)
	}
	n, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("user %q has invalid uid", value)
	}
	return uint32(n), nil
}

func resolveGID(value string) (int, error) {
	if n, err := strconv.ParseUint(value, 10, 31); err == nil {
		if strconv.FormatUint(n, 10) != value {
			return 0, errors.New("invalid numeric gid " + value)
		}
		return int(n), nil
	}
	g, err := user.LookupGroup(value)
	if err != nil {
		return 0, fmt.Errorf("cannot resolve group %q: %w", value, err)
	}
	n, err := strconv.ParseUint(g.Gid, 10, 31)
	if err != nil {
		return 0, fmt.Errorf("group %q has invalid gid", value)
	}
	return int(n), nil
}
