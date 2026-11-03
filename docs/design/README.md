# AxionPanel UI design

## Status and source

Production builds use real password/MFA authentication and an embedded Go server.
Host-control screens remain non-functional samples: no terminal, firewall,
enrollment, deploy or restore operation reaches a server. Resource values are
example data. Explicit design-preview builds bypass route authentication for
visual review, but disable sign-in; never use them as production builds.

The supplied Stitch export is preserved unchanged in `reference/` (5 HTML files,
5 screenshots, 2 DESIGN.md files). The original branding is preserved only in those
source references. The application is in `../../web/` relative to this directory.

## Visual contract

- Primary surface: **Operate**, with Monitor sections on the overview.
- Obsidian DevOps YAML front matter supplies the 47 dark semantic color tokens.
  It matches the exported screen configuration; contradictory prose is not used.
- Light values are derived from the separate supplied light overview (not a
  claim that the ZIP supplied a complete light token specification).
- Plus Jakarta Sans for navigation/headings; JetBrains Mono for telemetry and code.
- Navy canvas, cyan actions, green healthy state, amber warnings, red destructive actions.
- Desktop: 288px sidebar, 64px header; mobile: a navigation drawer. Thin borders,
  compact tables, minimal rounding. Token values in `web/src/style.css`.
- Fonts/icons are bundled locally by Vite, not loaded from Google or a CDN.
- The reference image’s Raft, live-security and hypervisor claims are not adopted
  as implemented capabilities. Multi-node MVP means independent managed hosts;
  HA scheduling/consensus needs separate approval and implementation.
- The firewall backend remains the nftables contract in `spec.md`; the UFW label
  in the source artwork is not an implementation decision.

## Screen inventory

Reference-derived: Overview & Metrics, Containers & Deploy, Security & Backups,
Terminal & Logs. These retain the supplied HTML structure; controls show a
preview-only notice, not simulated system success. Light/dark share the same DOM.

New designs:

1. Websites — searchable resource list, site type/runtime/domain, create flow and inspector.
2. Databases — databases/users, create flow and grant configuration.
3. SSL Certificates — validity/renewal state, HTTP-01 issuance and custom certificate import.
4. File Manager — scoped folder navigation, file list and example text editor.
5. Cron Jobs — schedule builder, command/user settings and example run history.
6. Login — real password then conditional TOTP/recovery authentication.
7. Settings — general/security/notifications, MFA/session settings, save feedback.
8. Nodes — host inventory/enrollment/trust design added for expanded MVP.

State for sample resource forms stays in memory and is discarded on reload.
Auth passwords/codes are cleared on submit and never persisted in web storage.
Session/challenge cookies are HttpOnly; the readable CSRF cookie is not a session
credential. Design preview requires exactly `VITE_DESIGN_PREVIEW=true`.

## Run and verify

```sh
cd web
npm ci
VITE_DESIGN_PREVIEW=true npm run dev -- --host 127.0.0.1 --port 15173
npm run build
npm test
npx playwright install chromium
npx playwright test
```

Open `http://127.0.0.1:15173/` for design preview. Production `npm run build`
(without the preview environment variable) is embedded by `make build`. See the
repository README for a loopback-only authenticated test setup. Vite proxies
`/api` to port 7800; the backend `-origin` must equal the browser-facing Vite URL.
Use SSH forwarding rather than publishing the Vite development server publicly.

Browser verification screenshots are written into `screens/`. They are review
artifacts, not proof that the corresponding host features work.

`python scripts/build-design-preview.py` reimports the four original layouts,
regenerating those views, `web/src/style.css` and Tailwind config. It does not
modify the originals or the new views. Do not edit generated files independently
without updating the importer or its token sources.
