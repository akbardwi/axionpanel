---
name: Obsidian Telemetry
colors:
  surface: '#0b1326'
  surface-dim: '#0b1326'
  surface-bright: '#31394e'
  surface-container-lowest: '#060d20'
  surface-container-low: '#131b2e'
  surface-container: '#171f33'
  surface-container-high: '#222a3e'
  surface-container-highest: '#2d3449'
  on-surface: '#dbe2fd'
  on-surface-variant: '#bcc9cd'
  inverse-surface: '#dbe2fd'
  inverse-on-surface: '#283044'
  outline: '#869397'
  outline-variant: '#3d494c'
  surface-tint: '#4cd7f6'
  primary: '#4cd7f6'
  on-primary: '#003640'
  primary-container: '#06b6d4'
  on-primary-container: '#00424f'
  inverse-primary: '#00687a'
  secondary: '#6cd3f7'
  on-secondary: '#003543'
  secondary-container: '#269dbe'
  on-secondary-container: '#002e3b'
  tertiary: '#7bd0ff'
  on-tertiary: '#00354a'
  tertiary-container: '#23b2ec'
  on-tertiary-container: '#00415a'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#acedff'
  primary-fixed-dim: '#4cd7f6'
  on-primary-fixed: '#001f26'
  on-primary-fixed-variant: '#004e5c'
  secondary-fixed: '#b7eaff'
  secondary-fixed-dim: '#6cd3f7'
  on-secondary-fixed: '#001f28'
  on-secondary-fixed-variant: '#004e61'
  tertiary-fixed: '#c4e7ff'
  tertiary-fixed-dim: '#7bd0ff'
  on-tertiary-fixed: '#001e2c'
  on-tertiary-fixed-variant: '#004c69'
  background: '#0b1326'
  on-background: '#dbe2fd'
  surface-variant: '#2d3449'
typography:
  display:
    fontFamily: Geist
    fontSize: 32px
    fontWeight: '600'
    lineHeight: 40px
    letterSpacing: -0.02em
  headline-lg:
    fontFamily: Geist
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.015em
  headline-lg-mobile:
    fontFamily: Geist
    fontSize: 20px
    fontWeight: '600'
    lineHeight: 28px
    letterSpacing: -0.01em
  headline-md:
    fontFamily: Geist
    fontSize: 18px
    fontWeight: '600'
    lineHeight: 24px
    letterSpacing: -0.01em
  body-lg:
    fontFamily: Geist
    fontSize: 15px
    fontWeight: '400'
    lineHeight: 22px
    letterSpacing: '0'
  body-md:
    fontFamily: Geist
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 18px
    letterSpacing: '0'
  code-body:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 18px
    letterSpacing: '0'
  code-inline:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '500'
    lineHeight: 16px
    letterSpacing: 0.02em
  label-md:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '600'
    lineHeight: 16px
    letterSpacing: 0.05em
  label-sm:
    fontFamily: JetBrains Mono
    fontSize: 10px
    fontWeight: '600'
    lineHeight: 14px
    letterSpacing: 0.06em
rounded:
  sm: 0.25rem
  DEFAULT: 0.5rem
  md: 0.75rem
  lg: 1rem
  xl: 1.5rem
  full: 9999px
spacing:
  gutter: 1rem
  gutter-dense: 0.5rem
  margin: 1.5rem
  margin-mobile: 1rem
  space-xs: 0.25rem
  space-sm: 0.5rem
  space-md: 0.75rem
  space-lg: 1rem
  space-xl: 1.5rem
---

## Brand & Style

This design system targets infrastructure engineers, cloud architects, and site reliability teams requiring instant comprehension across telemetry streams, cluster states, and deployment pipelines. 

The aesthetic is precision-driven high-density engineering: balancing surgical data layouts with deep atmospheric elegance. Drawing from functional modernism and dark technical instrumentation, the interface emphasizes legibility under critical operational workloads without visual fatigue. Surfaces prioritize clear visual hierarchy through fine-line geometry, strict column alignment, and high-contrast typographic accents.

## Colors

The system uses an infrastructure-first palette optimized for long monitoring sessions, switching cleanly between a deep obsidian dark theme and a high-legibility slate light theme.

- **Primary (`#06b6d4`)**: Active telemetry hooks, primary operations, deployment health highlights.
- **Secondary (`#0891b2`)**: Structural focus lines, selection states, secondary trigger buttons.
- **Tertiary (`#38bdf8`)**: Transient notifications, protocol tags, auxiliary metric overlays.
- **Dark Mode Surfaces**: Base background `#0b1326`, elevated panels and cards `#131b2e`, structural dividers `#1e293b`.
- **Light Mode Surfaces**: Canvas background `#f8fafc`, primary card layers `#ffffff`, borders `#e2e8f0`. Text defaults to `#0f172a` for primary labels and `#64748b` for secondary readouts.
- **Status Accents**: Production green (`#10b981`), critical failure (`#f43f5e`), pipeline warning (`#f59e0b`).

## Typography

Typography prioritizes tabular accuracy and dense vertical scanning. Geist provides optical balance for structural interface layers and dashboard titles, while JetBrains Mono anchors all telemetry streams, cluster hashes, IP masks, JSON configurations, and component badges.

All uppercase tags and badges require `label-sm` or `label-md` with strict letter tracking (`0.05em` to `0.06em`) to preserve legibility against colored container fills.

## Layout & Spacing

The layout is built on a 12-column fluid grid system optimized for high data density, featuring a collapsible fixed-width navigation rail (240px expanded, 64px collapsed).

- **Grid Alignment**: Standard layouts use 16px (`1rem`) gutters; dense node topologies and metric charts scale down to `gutter-dense` (8px / `0.5rem`).
- **Breakpoints**: Mobile (<768px), Tablet (768px–1023px), Desktop (1024px–1439px), and Ultra-wide Monitor (1440px+). 
- **Reflow Rules**: On screens under 1024px, 4-column metric overviews reflow into a 2x2 matrix; below 768px, single-column vertical stacks are enforced, and side-by-side terminal inspector panels collapse into swipeable tabs.

## Elevation & Depth

Visual hierarchy uses crisp boundary delineation rather than heavy drop shadows, reinforcing an analytical control-room aesthetic.

- **Base Tiers**: Canvas is Level 0 (`#0b1326` dark / `#f8fafc` light). Workload cards and log viewers sit at Level 1 (`#131b2e` dark / `#ffffff` light) framed by a 1px solid border (`#1e293b` dark / `#e2e8f0` light).
- **Floating Overlays & Menus**: Drawers, cluster dropdowns, and flyout terminals map to Level 2 (`#1a243b` dark / `#ffffff` light) with an ambient shadow: `0 8px 24px -4px rgba(0, 0, 0, 0.45)` in dark mode and `0 8px 20px -4px rgba(15, 23, 42, 0.08)` in light mode.
- **Active Focus**: Interactive cards and table rows apply an active cyan edge highlight (`border-color: #06b6d4`) without altering layout geometry.

## Shapes

The interface balances sharp industrial utility with modern softness using the standard `roundedness: 2` (0.5rem / 8px).

- **Standard Elements**: Metric widgets, log panels, inputs, and standard buttons use `rounded-md` (0.5rem).
- **Enclosures**: Main viewport dashboards and high-level service cards use `rounded-lg` (1rem).
- **Micro UI**: Status indicators, inline code blocks, and counter chips use tighter radii (0.25rem to 0.375rem). Circular radii (full pill) are reserved exclusively for alive/dead node status pips.

## Components

### Buttons
- **Primary**: Background `#06b6d4`, foreground `#0b1326` (dark) or `#ffffff` (light), font `Geist` 13px weight 600, padding `0.5rem 1rem`, border-radius 8px. Hover state shifts to `#0891b2`.
- **Secondary**: Transparent background, 1px border (`#1e293b` dark / `#e2e8f0` light), foreground neutral text, hover surface tint with 5% cyan opacity.
- **Terminal Action**: Monospaced font `JetBrains Mono` 11px, compact padding `0.25rem 0.5rem`.

### Chips & Badges
- **Status Badges**: Semi-transparent surface (10% tint of status color), 1px matching border at 20% opacity, `JetBrains Mono` 10px uppercase, padding `0.125rem 0.375rem`, rounded 4px.
- **Resource Tags**: Key-value pairs displayed with a subtle vertical divider (e.g., `env:prod`), utilizing slate-500 keys and primary cyan values.

### Input Fields
- Height 36px, background `#0e1628` (dark) or `#ffffff` (light), border 1px solid `#1e293b` (dark) or `#cbd5e1` (light). Focus shifts border to `#06b6d4` with a 2px outer cyan glow ring at 15% opacity. Font `JetBrains Mono` 12px for configuration fields; `Geist` 13px for general search.

### Tables & Lists
- Row height 40px for compact monitoring; alternating surface highlights disabled in favor of 1px subtle divider lines (`#1e293b` / `#f1f5f9`).
- Hover row state renders an active 2px left border accent in `#06b6d4`. Monospaced tabular figures used across all numerical metrics.

### Cloud Cards & Panels
- Background `#131b2e` (dark) or `#ffffff` (light), rounded 12px, border 1px solid `#1e293b` (dark) or `#e2e8f0` (light). Includes structured header containing title, status pip, and resource breadcrumb.

### Telemetry Streamers & Console Terminals
- Background `#070c18` with subtle inset scrollbars. Font `JetBrains Mono` 12px with syntax-highlighted timestamp anchors in muted slate and error traces in `#f43f5e`.