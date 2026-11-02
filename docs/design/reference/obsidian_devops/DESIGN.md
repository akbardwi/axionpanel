---
name: Obsidian DevOps
colors:
  surface: '#0b1326'
  surface-dim: '#0b1326'
  surface-bright: '#31394d'
  surface-container-lowest: '#060e20'
  surface-container-low: '#131b2e'
  surface-container: '#171f33'
  surface-container-high: '#222a3d'
  surface-container-highest: '#2d3449'
  on-surface: '#dae2fd'
  on-surface-variant: '#bcc9cd'
  inverse-surface: '#dae2fd'
  inverse-on-surface: '#283044'
  outline: '#869397'
  outline-variant: '#3d494c'
  surface-tint: '#4cd7f6'
  primary: '#4cd7f6'
  on-primary: '#003640'
  primary-container: '#06b6d4'
  on-primary-container: '#00424f'
  inverse-primary: '#00687a'
  secondary: '#4edea3'
  on-secondary: '#003824'
  secondary-container: '#00a572'
  on-secondary-container: '#00311f'
  tertiary: '#ffb95f'
  on-tertiary: '#472a00'
  tertiary-container: '#e79400'
  on-tertiary-container: '#563400'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#acedff'
  primary-fixed-dim: '#4cd7f6'
  on-primary-fixed: '#001f26'
  on-primary-fixed-variant: '#004e5c'
  secondary-fixed: '#6ffbbe'
  secondary-fixed-dim: '#4edea3'
  on-secondary-fixed: '#002113'
  on-secondary-fixed-variant: '#005236'
  tertiary-fixed: '#ffddb8'
  tertiary-fixed-dim: '#ffb95f'
  on-tertiary-fixed: '#2a1700'
  on-tertiary-fixed-variant: '#653e00'
  background: '#0b1326'
  on-background: '#dae2fd'
  surface-variant: '#2d3449'
typography:
  headline-xl:
    fontFamily: Plus Jakarta Sans
    fontSize: 32px
    fontWeight: '700'
    lineHeight: 40px
    letterSpacing: -0.02em
  headline-xl-mobile:
    fontFamily: Plus Jakarta Sans
    fontSize: 24px
    fontWeight: '700'
    lineHeight: 32px
    letterSpacing: -0.015em
  headline-lg:
    fontFamily: Plus Jakarta Sans
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.015em
  headline-lg-mobile:
    fontFamily: Plus Jakarta Sans
    fontSize: 20px
    fontWeight: '600'
    lineHeight: 28px
    letterSpacing: -0.01em
  headline-md:
    fontFamily: Plus Jakarta Sans
    fontSize: 18px
    fontWeight: '600'
    lineHeight: 26px
    letterSpacing: -0.01em
  body-lg:
    fontFamily: Plus Jakarta Sans
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
    letterSpacing: -0.005em
  body-md:
    fontFamily: Plus Jakarta Sans
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  body-sm:
    fontFamily: Plus Jakarta Sans
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 18px
  code-lg:
    fontFamily: JetBrains Mono
    fontSize: 14px
    fontWeight: '500'
    lineHeight: 20px
  code-md:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 18px
  code-sm:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '400'
    lineHeight: 16px
  label-caps:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '600'
    lineHeight: 14px
    letterSpacing: 0.06em
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  gutter: 1rem
  gutter-lg: 1.5rem
  margin: 1rem
  margin-md: 1.5rem
  margin-lg: 2rem
  space-xs: 0.25rem
  space-sm: 0.5rem
  space-md: 0.75rem
  space-lg: 1rem
  space-xl: 1.5rem
---

## Brand & Style

This design system is engineered for modern infrastructure engineers, sysadmins, and self-hosters who demand complete clarity, high operational density, and immediate feedback from their VPS control planes. Drawing inspiration from modern developer toolkits such as Vercel, Railway, and Supabase, the visual language marries high-precision utility with refined technical minimalism.

### Key Visual Tenets
- **Precision Engineering:** Interfaces favor crisp, 1px structural boundaries, micro-status indicators, and dense informational hierarchies over decorative ornamentation.
- **Deep Technical Immersion:** An uncompromising dark-mode-first environment built on cool, layered slates provides sustained optical comfort during extended terminal monitoring and configuration sessions.
- **Immediate Telemetry Hierarchy:** High-chroma electric signals (cyan, emerald, amber, rose) are reserved strictly for machine health, dynamic deployment states, throughput metrics, and fault alerts. Everything else recedes into calm, structural slate tiers.

## Colors

The palette operates on calibrated contrast tiers built specifically for deep dark interfaces:

- **Primary (`#06b6d4` - Electric Cyan):** Used for focal system hooks, active deployment indicators, highlighted CLI directives, active tab strokes, and primary interactive surfaces.
- **Secondary (`#10b981` - Hyper Emerald):** Reserved for live daemon states, operational health tags ("running", "healthy"), low-latency telemetry, and successful deploys.
- **Tertiary (`#f59e0b` - Alert Amber):** Governs rate-limiting warnings, pending build jobs, memory threshold warnings (>80%), and restart-required badges.
- **Neutral Core (`#0f172a` - Deep Slate):** The anchoring canvas tone. Extended system-wide through sub-tiers:
  - Base Viewport Canvas: `#090d16`
  - Container / Card Panels: `#0f172a`
  - Elevated Popovers & Terminal Shells: `#1e293b`
  - Subtle Structural Borders: `#334155`
- **Error / Critical (`#f43f5e` - Core Rose):** Denotes fatal kernel exceptions, crashed containers, unauthorized SSH access alerts, and destructive actions.

## Typography

The typographic hierarchy implements a strict segregation of semantic domains:

- **Plus Jakarta Sans** delivers structural balance for high-level navigation, resource cluster summaries, modal headers, and descriptive operational prose. It keeps the UI approachable without sacrificing technical crispness.
- **JetBrains Mono** is enforced strictly for raw infrastructural entities: IP addresses (v4/v6), CIDR blocks, SHA-256 commit hashes, container IDs, port bindings (`0.0.0.0:8080`), resource telemetry readouts (`1.42 GiB / 8.00 GiB`), and real-time streaming build logs.
- Metric display values (such as CPU% counters or IOPS tallies) leverage `code-lg` in medium weight to prevent baseline jumping when figures rapidly fluctuate.

## Layout & Spacing

This design system enforces a modular 12-column layout configured for dense developer workflows:

- **Desktop (>= 1280px):** 12-column fluid grid locked within a maximum 1600px canvas, 24px margins (`margin-lg`), and 24px gutters (`gutter-lg`). Grid structures allow high-density multi-pane splits: e.g., 3-column live metric widgets or 4-column container topologies flanking an 8-column log stream.
- **Tablet (768px - 1279px):** 8-column grid with 24px margins (`margin-md`) and 16px gutters (`gutter`). Multi-pane telemetry drops to dual-column stacks.
- **Mobile (< 768px):** 4-column reflow with 16px margins (`margin`) and 16px gutters (`gutter`). Navigation collapses to an indexed command tray; cards and system metrics flatten into single-column vertical flows.
- **Spacing Rhythm:** Internal card structures and component groupings default to tight, uniform intervals (`space-xs` through `space-md`) to ensure high visible data density per viewport fold.

## Elevation & Depth

Visual depth is achieved through structural color stacking and razor-sharp border boundaries rather than heavy blurred drop shadows.

- **Surface Tiers:**
  - **Tier 0 (Root Canvas):** `#090d16` (Deepest operational background).
  - **Tier 1 (Surface/Panels):** `#0f172a` bounded by a 1px solid `#334155` border.
  - **Tier 2 (Elevated Nodes/Popovers/Modals):** `#1e293b` with a 1px solid `#475569` perimeter border.
  - **Tier 3 (Terminal Viewports):** Pure dark `#050811` recessed panels inset with 1px `#1e293b`.
- **Micro-Shadows:** Standard floating items (command palettes, floating metric tooltips) employ an ultra-subtle, ambient dark drop shadow: `0 4px 20px -2px rgba(0, 0, 0, 0.65)`.
- **Active State Highlights:** Focused or active elements discard external blur in favor of an internal or snug 1px electric accent outline: `box-shadow: 0 0 0 1px #06b6d4`.

## Shapes

The design system maintains a disciplined, technical silhouette utilizing **Soft (`1`)** geometry:
- Standard buttons, badges, input controls, and system pills use `0.25rem` (4px) corner radii.
- Telemetry containers, cards, and modal dialogs scale up to `rounded-lg` (`0.5rem` / 8px) to establish subtle enclosure without soft, consumer-app bubble aesthetics.
- Outer borders are perpetually crisp 1px strokes (`#334155` default, `#475569` on hover).

## Components

### Buttons
- **Primary:** `#06b6d4` background with `#090d16` text, bold `0.25rem` radius. On hover: subtle brightness shift and `box-shadow: 0 0 12px rgba(6, 182, 212, 0.35)`.
- **Secondary:** Semi-transparent slate (`rgba(30, 41, 59, 0.6)`), 1px solid `#334155` border, `#f8fafc` text. Hover shifts border to `#64748b`.
- **Danger:** Inset `#f43f5e15` background with 1px solid `#f43f5e50` border and `#f43f5e` text for destructive operations (e.g., "Purge Volume").

### Server Status Pills & Badges
- **Live/Healthy:** `#10b98115` fill, `#10b98140` border, `#10b981` text with a 6px pulsating circular dot.
- **Provisioning/Pending:** `#06b6d415` fill, `#06b6d440` border, `#06b6d4` text with an animated linear loader or spin icon.
- **Warning/High Load:** `#f59e0b15` fill, `#f59e0b40` border, `#f59e0b` text.
- Badges strictly consume `label-caps` typography (`JetBrains Mono`, 11px uppercase).

### Terminal & Metric Cards
- Surface background `#0f172a` wrapped in 1px `#334155`.
- Header bar: `#1e293b` separation with resource titles on the left and monospace real-time timestamps (`UTC`) or actions on the right.
- Internal terminal instances feature `#050811` background, green/cyan prompt carats, and syntax coloring matching the telemetry accents.

### Input Fields & Monospace Controls
- Surfaces use `#090d16` inset background with a 1px `#334155` border. Focus state replaces border with `#06b6d4` and zero ambient blur.
- Environment variable keys, port numbers, and domain inputs strictly render with `code-md` (`JetBrains Mono`).

### Checkboxes & Switches
- Checkboxes: 16x16px boxes, `#090d16` fill, `#334155` stroke, popping to `#06b6d4` fill with checkmark when active.
- Micro-toggles: Segmented rectangular track with a slide offset of 2px, providing high contrast between disabled muted slate and active emerald/cyan states.

### Lists & Resource Tables
- Dense tabular rows separated by 1px solid `#1e293b` lines.
- Zebra striping is avoided in favor of responsive row hover states (`#1e293b40`).
- Columns align figures right with `JetBrains Mono` for rapid vertical scanning of RAM, CPU, and network I/O.