# AxionPanel

Open-source control panel for VPS servers. Manage websites, databases, SSL,
files, cron, backups, and server security from one dashboard. Inspired by
aaPanel and cPanel: simple enough for a personal VPS, structured so it can
grow into multi-user hosting later.

**Status: pre-alpha.** This repository currently holds the workspace scaffold
and architecture notes.

## Design

Two processes with separated privileges:

- `panel` — API server and web UI, runs unprivileged
- `agent` — privileged daemon that performs system operations (vhost files,
  service reloads, certificates) on validated requests over a Unix socket

The internet-facing component never runs as root. Panel metadata lives in
SQLite in single-server mode; the schema is written so a hosted or
multi-server edition can move to PostgreSQL without a rewrite. Websites keep
using MySQL/MariaDB/PostgreSQL as usual — the panel must never depend on the
services it manages.

## Roadmap

1. MVP: installer, auth with 2FA, dashboard, websites with Nginx vhosts,
   Let's Encrypt, MySQL management, file manager, cron, firewall, web terminal
2. App store, one-click apps (WordPress, Laravel), scheduled backups to cloud
   storage, Docker management, Node.js/Python projects, notifications,
   signed auto-updates
3. Multi-user (admin/reseller/user) with packages and quotas, DNS, mail,
   public REST API, billing integration, multi-node management

## Stack

- Go: `panel` and `agent` binaries
- Vue 3 + Vite + Tailwind: web UI, embedded into the panel binary
- SQLite (modernc.org/sqlite) for panel data; PostgreSQL for future
  multi-server mode

## Layout

```
cmd/panel/     API server entrypoint
cmd/agent/     privileged daemon entrypoint
internal/      shared packages (api, services, store, templates)
web/           Vue 3 SPA
scripts/       installer and packaging
docs/          specifications and architecture decisions
```

## License

Not decided yet. No license file is included on purpose; until one is added,
the code is not open source by definition.
