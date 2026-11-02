<script setup>
import { ref } from 'vue'
const notice = ref('')
function previewAction(event) {
  const target = event.target.closest('button, a, input[type=checkbox]')
  if (!target) return
  event.preventDefault()
  notice.value = 'Preview only — no command was sent to a server.'
}
</script>
<template>
<section @click="previewAction" @submit.prevent>
<div v-if="notice" class="preview-notice" role="status">{{ notice }} <button class="ax-btn ax-btn-ghost" @click.stop="notice = ''">Dismiss</button></div>
<main v-pre class="w-full pt-16 bg-surface min-h-screen"><div class="flex flex-col w-full">
<!-- Top Node Context & Session Telemetry Ribbon -->
<div class="px-gutter-lg pt-space-lg pb-space-md bg-surface-container-low flex flex-col gap-space-md">
<div class="flex flex-wrap items-center justify-between gap-space-md">
<div class="flex items-center gap-space-md">
<div class="w-10 h-10 rounded-lg bg-surface-container flex items-center justify-center text-primary shadow-sm">
<span aria-hidden="true" class="material-symbols-outlined text-2xl">terminal</span>
</div>
<div>
<div class="flex items-center gap-space-sm">
<h1 class="font-headline-md text-headline-md font-bold text-on-surface tracking-tight">Web SSH &amp; Live Log Console</h1>
<span class="px-space-xs py-0.5 rounded font-label-caps text-label-caps bg-secondary/15 text-secondary flex items-center gap-1">
<span class="w-1.5 h-1.5 rounded-full bg-secondary animate-ping"></span>
              TERMINAL DESIGN PREVIEW
            </span>
</div>
<p class="font-code-sm text-code-sm text-on-surface-variant flex items-center gap-space-sm mt-0.5">
<span>NODE: <strong class="text-on-surface font-mono">node-01</strong></span>
<span class="text-outline-variant">/</span>
<span>PUBLIC: <strong class="text-on-surface font-mono">203.0.113.10</strong></span>
<span class="text-outline-variant">/</span>
<span>ARCH: <strong class="text-on-surface font-mono">x86_64 Ubuntu 24.04 LTS</strong></span>
</p>
</div>
</div>
<!-- Quick Session Badges -->
<div class="flex items-center gap-space-sm flex-wrap">
<div class="flex items-center gap-space-xs px-space-md py-1.5 rounded-lg bg-surface-container font-code-sm text-code-sm text-on-surface-variant">
<span aria-hidden="true" class="material-symbols-outlined text-sm text-primary">speed</span>
<span>RTT:</span>
<span class="text-secondary font-mono font-medium">18ms</span>
</div>
<div class="flex items-center gap-space-xs px-space-md py-1.5 rounded-lg bg-surface-container font-code-sm text-code-sm text-on-surface-variant">
<span aria-hidden="true" class="material-symbols-outlined text-sm text-tertiary">timer</span>
<span>Session:</span>
<span class="text-on-surface font-mono font-medium" id="session-timer">00:34:12</span>
</div>
<div class="flex items-center gap-space-xs px-space-md py-1.5 rounded-lg bg-surface-container font-code-sm text-code-sm text-on-surface-variant">
<span aria-hidden="true" class="material-symbols-outlined text-sm text-outline">key</span>
<span>Auth:</span>
<span class="text-primary font-mono font-medium">ed25519-sk</span>
</div>
<button class="flex items-center gap-space-xs px-space-md py-1.5 rounded-lg bg-primary-container text-on-primary-container font-body-sm text-body-sm font-semibold hover:brightness-110 transition-all shadow-sm" id="btn-reconnect">
<span aria-hidden="true" class="material-symbols-outlined text-base">refresh</span>
<span>Reconnect</span>
</button>
</div>
</div>
<!-- Target Selector Navigation Pills -->
<div class="flex items-center justify-between gap-space-md pt-space-xs overflow-x-auto">
<div class="flex items-center gap-space-xs p-1 rounded-xl bg-surface-container-lowest shrink-0" role="tablist">
<button aria-selected="true" class="flex items-center gap-space-xs px-space-md py-1.5 rounded-lg bg-surface-container-high text-primary font-code-sm text-code-sm font-semibold shadow-sm transition-all" role="tab">
<span aria-hidden="true" class="material-symbols-outlined text-base">host</span>
<span>Host Root Shell (node-01)</span>
</button>
<button aria-selected="false" class="flex items-center gap-space-xs px-space-md py-1.5 rounded-lg text-on-surface-variant hover:text-on-surface hover:bg-surface-container font-code-sm text-code-sm transition-all" role="tab">
<span aria-hidden="true" class="material-symbols-outlined text-base text-secondary">layers</span>
<span>Container: production-api</span>
<span class="w-1.5 h-1.5 rounded-full bg-secondary"></span>
</button>
<button aria-selected="false" class="flex items-center gap-space-xs px-space-md py-1.5 rounded-lg text-on-surface-variant hover:text-on-surface hover:bg-surface-container font-code-sm text-code-sm transition-all" role="tab">
<span aria-hidden="true" class="material-symbols-outlined text-base text-primary">database</span>
<span>Container: postgres-cluster-01</span>
<span class="w-1.5 h-1.5 rounded-full bg-secondary"></span>
</button>
<button aria-selected="false" class="flex items-center gap-space-xs px-space-md py-1.5 rounded-lg text-on-surface-variant hover:text-on-surface hover:bg-surface-container font-code-sm text-code-sm transition-all" role="tab">
<span aria-hidden="true" class="material-symbols-outlined text-base text-tertiary">article</span>
<span>Systemd Journal Logs</span>
</button>
</div>
<div class="flex items-center gap-space-xs text-on-surface-variant shrink-0 font-code-sm text-code-sm">
<span class="hidden xl:inline">TTY:</span>
<span class="bg-surface-container px-space-xs py-0.5 rounded text-on-surface font-mono">/dev/pts/3</span>
<span class="hidden xl:inline text-outline-variant">•</span>
<span class="hidden xl:inline">TERM:</span>
<span class="hidden xl:inline bg-surface-container px-space-xs py-0.5 rounded text-on-surface font-mono">xterm-256color</span>
</div>
</div>
</div>
<!-- Main Viewport Dual-Panel Workstation -->
<div class="p-gutter-lg grid grid-cols-1 xl:grid-cols-12 gap-gutter-lg flex-1">
<!-- PANEL A: Full Interactive SSH Terminal (7 Cols on Ultra-Wide / 12 on Tablet) -->
<section class="xl:col-span-7 flex flex-col rounded-xl bg-surface-container-lowest overflow-hidden shadow-xl min-h-[580px]">
<!-- Terminal Header / Titlebar -->
<div class="px-space-md py-2.5 bg-surface-container-low flex items-center justify-between gap-space-md">
<!-- Window Controls & Path -->
<div class="flex items-center gap-space-md min-w-0">
<div class="flex items-center gap-1.5">
<span class="w-2.5 h-2.5 rounded-full bg-error cursor-pointer hover:opacity-80"></span>
<span class="w-2.5 h-2.5 rounded-full bg-tertiary cursor-pointer hover:opacity-80"></span>
<span class="w-2.5 h-2.5 rounded-full bg-secondary cursor-pointer hover:opacity-80"></span>
</div>
<div class="flex items-center gap-space-xs min-w-0">
<span aria-hidden="true" class="material-symbols-outlined text-base text-primary">terminal</span>
<span class="font-code-md text-code-md font-semibold text-on-surface truncate">root@node-01:~#</span>
<span class="hidden md:inline font-code-sm text-code-sm text-on-surface-variant truncate">(zsh 5.9)</span>
</div>
</div>
<!-- Terminal Quick Action Toolbar -->
<div class="flex items-center gap-space-xs">
<button class="p-1.5 rounded-lg text-on-surface-variant hover:text-on-surface hover:bg-surface-container transition-colors" id="btn-split" title="Split Screen (Ctrl+Shift+D)">
<span aria-hidden="true" class="material-symbols-outlined text-base">vertical_split</span>
</button>
<button class="p-1.5 rounded-lg text-on-surface-variant hover:text-on-surface hover:bg-surface-container transition-colors" id="btn-font-dec" title="Decrease Font">
<span aria-hidden="true" class="material-symbols-outlined text-base">text_decrease</span>
</button>
<button class="p-1.5 rounded-lg text-on-surface-variant hover:text-on-surface hover:bg-surface-container transition-colors" id="btn-font-inc" title="Increase Font">
<span aria-hidden="true" class="material-symbols-outlined text-base">text_increase</span>
</button>
<button class="p-1.5 rounded-lg text-on-surface-variant hover:text-on-surface hover:bg-surface-container transition-colors" id="btn-clear" title="Clear Buffer (Ctrl+L)">
<span aria-hidden="true" class="material-symbols-outlined text-base">clear_all</span>
</button>
<button class="p-1.5 rounded-lg text-on-surface-variant hover:text-on-surface hover:bg-surface-container transition-colors" id="btn-copy" title="Copy Selected Buffer">
<span aria-hidden="true" class="material-symbols-outlined text-base">content_copy</span>
</button>
<div class="w-px h-4 bg-surface-container-high mx-0.5"></div>
<button class="p-1.5 rounded-lg text-primary hover:bg-surface-container transition-colors" id="btn-fullscreen" title="Expand Fullscreen">
<span aria-hidden="true" class="material-symbols-outlined text-base">fullscreen</span>
</button>
</div>
</div>
<!-- Terminal Body Content (xterm styled canvas emulation) -->
<div class="flex-1 p-space-md font-code-sm text-code-sm text-on-surface overflow-y-auto leading-relaxed select-text space-y-3 font-mono bg-surface-container-lowest" id="terminal-body">
<!-- MOTD Banner Output -->
<div class="text-on-surface-variant">
<p class="text-primary font-bold">Welcome to AxionPanel Management Hypervisor v2.4.1 (x86_64)</p>
<p class="text-on-surface-variant">System information as of Sun Nov 02 10:44:02 UTC 2026</p>
<div class="grid grid-cols-2 md:grid-cols-4 gap-space-sm pt-2 text-on-surface">
<div class="bg-surface-container p-2 rounded">
<span class="text-outline text-label-caps uppercase block">System Load</span>
<span class="font-bold text-secondary">0.42, 0.58, 0.49</span>
</div>
<div class="bg-surface-container p-2 rounded">
<span class="text-outline text-label-caps uppercase block">RAM Usage</span>
<span class="font-bold text-primary">5.21 GB / 8.00 GB</span>
</div>
<div class="bg-surface-container p-2 rounded">
<span class="text-outline text-label-caps uppercase block">Root Volume</span>
<span class="font-bold text-tertiary">38% of 120GB</span>
</div>
<div class="bg-surface-container p-2 rounded">
<span class="text-outline text-label-caps uppercase block">Active Tunnels</span>
<span class="font-bold text-secondary">14 Containers</span>
</div>
</div>
<p class="mt-2 text-outline">Last login: Sun Nov 02 09:12:44 from 223.18.91.242 (ed25519-agent)</p>
</div>
<!-- Executed Command 1: docker stats -->
<div class="pt-2">
<div class="flex items-center gap-space-xs text-secondary">
<span class="text-primary font-bold">root@node-01</span><span class="text-on-surface">:</span><span class="text-primary">~</span><span class="text-on-surface-variant">#</span>
<span class="text-on-surface font-semibold">docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}"</span>
</div>
<!-- Colorized ASCII / Tabular Output -->
<div class="mt-2 overflow-x-auto p-space-sm rounded bg-surface-container-low text-on-surface font-mono text-xs">
<div class="text-outline-variant font-bold pb-1 flex justify-between gap-4">
<span class="w-44 text-left">CONTAINER</span>
<span class="w-20 text-right">CPU %</span>
<span class="w-32 text-right">MEM USAGE / LIMIT</span>
<span class="w-28 text-right">NET I/O</span>
<span class="w-24 text-right">PIDS</span>
</div>
<div class="flex justify-between gap-4 py-0.5 hover:bg-surface-container text-on-surface">
<span class="w-44 truncate text-primary font-medium">production-api</span>
<span class="w-20 text-right text-secondary font-bold">8.42%</span>
<span class="w-32 text-right text-on-surface">412.3MiB / 2GiB</span>
<span class="w-28 text-right text-outline">1.2GB / 890MB</span>
<span class="w-24 text-right text-on-surface-variant">38</span>
</div>
<div class="flex justify-between gap-4 py-0.5 hover:bg-surface-container text-on-surface">
<span class="w-44 truncate text-primary font-medium">postgres-cluster-01</span>
<span class="w-20 text-right text-secondary font-bold">14.19%</span>
<span class="w-32 text-right text-on-surface">1.84GiB / 4GiB</span>
<span class="w-28 text-right text-outline">4.8GB / 12.1GB</span>
<span class="w-24 text-right text-on-surface-variant">64</span>
</div>
<div class="flex justify-between gap-4 py-0.5 hover:bg-surface-container text-on-surface">
<span class="w-44 truncate text-primary font-medium">redis-cache-layer</span>
<span class="w-20 text-right text-secondary font-bold">1.05%</span>
<span class="w-32 text-right text-on-surface">84.2MiB / 512MiB</span>
<span class="w-28 text-right text-outline">890MB / 1.1GB</span>
<span class="w-24 text-right text-on-surface-variant">8</span>
</div>
<div class="flex justify-between gap-4 py-0.5 hover:bg-surface-container text-on-surface">
<span class="w-44 truncate text-primary font-medium">nginx-edge-proxy</span>
<span class="w-20 text-right text-secondary font-bold">3.88%</span>
<span class="w-32 text-right text-on-surface">62.1MiB / 512MiB</span>
<span class="w-28 text-right text-outline">18.4GB / 24.6GB</span>
<span class="w-24 text-right text-on-surface-variant">16</span>
</div>
</div>
</div>
<!-- Executed Command 2: System Health and Network sockets -->
<div class="pt-2">
<div class="flex items-center gap-space-xs text-secondary">
<span class="text-primary font-bold">root@node-01</span><span class="text-on-surface">:</span><span class="text-primary">~</span><span class="text-on-surface-variant">#</span>
<span class="text-on-surface font-semibold">ip -br -c a &amp;&amp; systemctl is-active axion-agent wireguard@wg0</span>
</div>
<div class="mt-1 text-on-surface-variant">
<p><span class="text-outline">lo</span> <span class="text-secondary font-bold">UNKNOWN</span>        127.0.0.1/8 ::1/128</p>
<p><span class="text-outline">eth0</span> <span class="text-secondary font-bold">UP</span>             203.0.113.10/24 2400:cb00::14/64</p>
<p><span class="text-outline">docker0</span> <span class="text-secondary font-bold">UP</span>             172.17.0.1/16</p>
<p><span class="text-outline">wg0</span> <span class="text-secondary font-bold">UP</span>             10.88.0.1/24</p>
<p class="text-secondary pt-1">active</p>
<p class="text-secondary">active</p>
</div>
</div>
<!-- Active Interactive Line with blinking block cursor -->
<div class="pt-2 flex items-center gap-space-xs text-secondary">
<span class="text-primary font-bold">root@node-01</span><span class="text-on-surface">:</span><span class="text-primary">~</span><span class="text-on-surface-variant">#</span>
<input autofocus="" class="flex-1 bg-transparent text-on-surface font-mono outline-none border-none p-0 focus:ring-0 text-code-sm" id="terminal-input" spellcheck="false" type="text" value="journalctl -u docker.service -n 5 --no-pager"/>
<span class="w-2 h-4 bg-primary inline-block animate-pulse"></span>
</div>
</div>
<!-- Terminal Bottom Status Bar -->
<div class="px-space-md py-1.5 bg-surface-container-low flex items-center justify-between font-code-sm text-code-sm text-on-surface-variant">
<div class="flex items-center gap-space-md">
<span class="flex items-center gap-1.5 text-secondary">
<span class="w-2 h-2 rounded-full bg-secondary"></span>
            NOT CONNECTED
          </span>
<span class="hidden sm:inline text-outline-variant">|</span>
<span class="hidden sm:inline">ENCODING: UTF-8</span>
<span class="hidden md:inline text-outline-variant">|</span>
<span class="hidden md:inline">118x38 COLS</span>
</div>
<div class="flex items-center gap-space-md font-mono">
<span class="text-outline">ESC to ungrab</span>
<span class="text-primary">100% BUFFER</span>
</div>
</div>
</section>
<!-- PANEL B: Live Streaming Log Console (5 Cols on Ultra-Wide / 12 on Tablet) -->
<section class="xl:col-span-5 flex flex-col rounded-xl bg-surface-container-lowest overflow-hidden shadow-xl min-h-[580px]">
<!-- Log Viewer Header & Quick Filters -->
<div class="p-space-md bg-surface-container-low flex flex-col gap-space-sm">
<div class="flex items-center justify-between">
<div class="flex items-center gap-space-xs">
<span aria-hidden="true" class="material-symbols-outlined text-base text-secondary">receipt_long</span>
<span class="font-headline-md text-body-lg font-bold text-on-surface">Live System Log Ingestion</span>
</div>
<div class="flex items-center gap-space-xs">
<button class="flex items-center gap-1 px-space-sm py-1 rounded bg-secondary/10 text-secondary font-code-sm text-code-sm hover:bg-secondary/20 transition-colors" id="btn-autoscroll">
<span class="w-2 h-2 rounded-full bg-secondary animate-pulse"></span>
<span id="scroll-status-text">AUTO-SCROLL ON</span>
</button>
<div class="relative group">
<button class="flex items-center gap-1 px-space-sm py-1 rounded bg-surface-container hover:bg-surface-container-high text-on-surface font-body-sm text-body-sm transition-colors">
<span aria-hidden="true" class="material-symbols-outlined text-sm">download</span>
<span>Export</span>
</button>
</div>
</div>
</div>
<!-- Filter Controls Row -->
<div class="grid grid-cols-1 sm:grid-cols-12 gap-space-xs pt-1">
<!-- Keyword Search -->
<div class="sm:col-span-6 relative">
<span aria-hidden="true" class="material-symbols-outlined text-base text-outline absolute left-2.5 top-2">filter_alt</span>
<input class="w-full pl-8 pr-2 py-1.5 rounded-lg bg-surface-container text-on-surface placeholder:text-outline font-code-sm text-code-sm outline-none focus:bg-surface-container-high" id="log-search-input" placeholder="Search (e.g. error, 500, nginx)..." type="text"/>
</div>
<!-- Log Severity Dropdown Filter -->
<div class="sm:col-span-3">
<select class="w-full px-2 py-1.5 rounded-lg bg-surface-container text-on-surface font-code-sm text-code-sm outline-none cursor-pointer hover:bg-surface-container-high" id="log-severity-filter">
<option value="ALL">ALL LEVELS</option>
<option value="INFO">INFO ONLY</option>
<option value="WARN">WARN ONLY</option>
<option value="ERROR">ERROR ONLY</option>
</select>
</div>
<!-- Time Window Filter -->
<div class="sm:col-span-3">
<select class="w-full px-2 py-1.5 rounded-lg bg-surface-container text-on-surface font-code-sm text-code-sm outline-none cursor-pointer hover:bg-surface-container-high">
<option>Last 15m</option>
<option>Last 1h</option>
<option>Last 24h</option>
<option>Live Stream</option>
</select>
</div>
</div>
</div>
<!-- Live Stream Output List -->
<div class="flex-1 p-space-md font-code-sm text-code-sm overflow-y-auto space-y-1.5 bg-surface-container-lowest max-h-[500px]" id="logs-container">
<!-- Log Item 1: INFO -->
<div class="log-row p-1.5 rounded hover:bg-surface-container/60 transition-colors flex flex-col gap-0.5">
<div class="flex items-center justify-between text-outline">
<span class="font-mono text-xs">2026-05-18T10:44:18.441Z</span>
<span class="px-1.5 py-0.2 rounded font-label-caps text-label-caps bg-secondary/10 text-secondary">INFO</span>
</div>
<div class="text-on-surface font-mono">
<span class="text-primary font-semibold">[nginx-proxy]</span> GET /api/v1/metrics - 200 OK - 4.12ms (client: 103.14.88.1)
          </div>
</div>
<!-- Log Item 2: INFO -->
<div class="log-row p-1.5 rounded hover:bg-surface-container/60 transition-colors flex flex-col gap-0.5">
<div class="flex items-center justify-between text-outline">
<span class="font-mono text-xs">2026-05-18T10:44:16.890Z</span>
<span class="px-1.5 py-0.2 rounded font-label-caps text-label-caps bg-secondary/10 text-secondary">INFO</span>
</div>
<div class="text-on-surface font-mono">
<span class="text-primary font-semibold">[certbot-manager]</span> Let's Encrypt challenge verified successfully for *.axionvps.internal
          </div>
</div>
<!-- Log Item 3: WARN -->
<div class="log-row p-1.5 rounded bg-tertiary-container/10 hover:bg-tertiary-container/20 transition-colors flex flex-col gap-0.5">
<div class="flex items-center justify-between text-tertiary">
<span class="font-mono text-xs">2026-05-18T10:43:59.201Z</span>
<span class="px-1.5 py-0.2 rounded font-label-caps text-label-caps bg-tertiary/20 text-tertiary font-bold">WARN</span>
</div>
<div class="text-on-surface font-mono">
<span class="text-tertiary font-semibold">[postgres-cluster-01]</span> Connection pool reaching 76.8% capacity (77/100 active clients)
          </div>
</div>
<!-- Log Item 4: INFO -->
<div class="log-row p-1.5 rounded hover:bg-surface-container/60 transition-colors flex flex-col gap-0.5">
<div class="flex items-center justify-between text-outline">
<span class="font-mono text-xs">2026-05-18T10:43:44.110Z</span>
<span class="px-1.5 py-0.2 rounded font-label-caps text-label-caps bg-secondary/10 text-secondary">INFO</span>
</div>
<div class="text-on-surface font-mono">
<span class="text-primary font-semibold">[production-api]</span> Redis cluster sync complete: 18,492 keys reconciled in 34ms
          </div>
</div>
<!-- Log Item 5: ERROR -->
<div class="log-row p-1.5 rounded bg-error-container/15 hover:bg-error-container/25 transition-colors flex flex-col gap-0.5">
<div class="flex items-center justify-between text-error">
<span class="font-mono text-xs">2026-05-18T10:42:30.912Z</span>
<span class="px-1.5 py-0.2 rounded font-label-caps text-label-caps bg-error/20 text-error font-bold">ERROR</span>
</div>
<div class="text-on-surface font-mono">
<span class="text-error font-semibold">[webhook-worker]</span> ConnectionTimeout: Endpoint `https://hooks.slack.com/services/...` returned 504 Gateway Timeout after 5000ms
          </div>
</div>
<!-- Log Item 6: INFO -->
<div class="log-row p-1.5 rounded hover:bg-surface-container/60 transition-colors flex flex-col gap-0.5">
<div class="flex items-center justify-between text-outline">
<span class="font-mono text-xs">2026-05-18T10:41:02.040Z</span>
<span class="px-1.5 py-0.2 rounded font-label-caps text-label-caps bg-secondary/10 text-secondary">INFO</span>
</div>
<div class="text-on-surface font-mono">
<span class="text-primary font-semibold">[systemd-journal]</span> Daily scheduled logrotate executed on `/var/log/nginx/*.log`. 4 archives rotated.
          </div>
</div>
<!-- Log Item 7: WARN -->
<div class="log-row p-1.5 rounded bg-tertiary-container/10 hover:bg-tertiary-container/20 transition-colors flex flex-col gap-0.5">
<div class="flex items-center justify-between text-tertiary">
<span class="font-mono text-xs">2026-05-18T10:39:22.503Z</span>
<span class="px-1.5 py-0.2 rounded font-label-caps text-label-caps bg-tertiary/20 text-tertiary font-bold">WARN</span>
</div>
<div class="text-on-surface font-mono">
<span class="text-tertiary font-semibold">[dockerd]</span> Handler for POST /v1.44/containers/create took 892ms (threshold: 500ms)
          </div>
</div>
<!-- Dynamic Injected Line Anchor -->
<div id="logs-end-anchor"></div>
</div>
<!-- Realtime Ingestion Footer Metrics -->
<div class="px-space-md py-2 bg-surface-container-low flex items-center justify-between font-code-sm text-code-sm text-on-surface-variant">
<div class="flex items-center gap-space-sm">
<span class="text-secondary font-medium font-mono">142 eps</span>
<span class="text-outline-variant">•</span>
<span>Buffer: <span class="text-on-surface font-mono">1,482 / 5,000 lines</span></span>
</div>
<div class="flex items-center gap-space-xs text-xs">
<span class="w-1.5 h-1.5 rounded-full bg-secondary animate-pulse"></span>
<span class="text-secondary font-semibold">EXAMPLE STREAM</span>
</div>
</div>
</section>
</div>
<!-- Bottom Command Palette / Shortcut Reference Bar -->
<div class="px-gutter-lg pb-gutter-lg">
<div class="p-space-md rounded-xl bg-surface-container-low flex flex-wrap items-center justify-between gap-space-md">
<div class="flex flex-wrap items-center gap-space-md font-code-sm text-code-sm text-on-surface-variant">
<span class="font-semibold text-on-surface flex items-center gap-1">
<span aria-hidden="true" class="material-symbols-outlined text-sm text-primary">keyboard</span>
          Keybindings:
        </span>
<div class="flex items-center gap-1">
<kbd class="px-1.5 py-0.5 rounded bg-surface-container-highest text-on-surface font-mono">Ctrl+L</kbd>
<span>Clear terminal</span>
</div>
<div class="flex items-center gap-1">
<kbd class="px-1.5 py-0.5 rounded bg-surface-container-highest text-on-surface font-mono">Ctrl+C</kbd>
<span>Interrupt process</span>
</div>
<div class="flex items-center gap-1">
<kbd class="px-1.5 py-0.5 rounded bg-surface-container-highest text-on-surface font-mono">Ctrl+Shift+F</kbd>
<span>Find in logs</span>
</div>
<div class="flex items-center gap-1">
<kbd class="px-1.5 py-0.5 rounded bg-surface-container-highest text-on-surface font-mono">Tab</kbd>
<span>Auto-complete</span>
</div>
</div>
<div class="flex items-center gap-space-sm font-code-sm text-code-sm">
<span class="text-outline">Terminal Engine:</span>
<span class="px-2 py-0.5 rounded bg-surface-container text-primary font-mono font-medium">xterm.js WebGL / PTY Core</span>
</div>
</div>
</div>
</div>
</main>
</section>
</template>
