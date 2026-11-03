<script setup>
import { onMounted, ref, computed } from 'vue'
import { session } from '../auth/session.js'
import { isDesignPreview } from '../designMode.js'
import { loadHost, formatBytes, formatUptime, reasonText } from '../system/host.js'
const notice = ref('')
const preview = isDesignPreview()
const host = ref(null)
const loading = ref(false)
async function refreshHost() {
  if (preview) return
  loading.value = true
  try {
    host.value = await loadHost(undefined, {
      onUnauthorized: () => {
        // A 401 means the HttpOnly session may have expired. Hide the previous
        // agent values immediately, then revalidate through session.check().
        host.value = null
        return session.check()
      },
    })
  } finally { loading.value = false }
}
function previewAction(event) {
  const target = event.target.closest('button, a, input[type=checkbox]')
  if (!target) return
  event.preventDefault()
  notice.value = 'Preview only — no command was sent to a server.'
}
const memUsedPct = computed(() => {
  const s = host.value?.stats
  if (!s || !s.mem_total_bytes) return null
  return Math.round(((s.mem_total_bytes - s.mem_available_bytes) / s.mem_total_bytes) * 100)
})
onMounted(refreshHost)
</script>
<template>
<!-- Live host data: real read-only agent values via the authenticated panel API. -->
<section class="pt-16 px-gutter-lg">
  <div class="rounded-xl border p-4 mb-2" style="background: rgb(var(--c-surface-container-low)); border-color: rgb(var(--c-outline-variant) / .3)">
    <div class="flex items-center justify-between gap-3 flex-wrap">
      <div class="flex items-center gap-2">
        <span aria-hidden="true" class="material-symbols-outlined text-base" style="color: rgb(var(--c-primary))">monitoring</span>
        <h2 class="font-headline-sm text-headline-sm text-on-surface">Host data (live)</h2>
        <span v-if="preview" class="ax-pill ax-pill-warn">not loaded in design preview</span>
        <span v-else-if="loading" class="ax-pill ax-pill-dim">loading…</span>
        <span v-else-if="host?.connected" class="ax-pill ax-pill-ok">agent connected</span>
        <span v-else class="ax-pill ax-pill-warn">agent unavailable</span>
      </div>
      <button v-if="!preview" class="ax-btn ax-btn-ghost" :disabled="loading" @click="refreshHost">
        <span aria-hidden="true" class="material-symbols-outlined text-base">refresh</span>Refresh
      </button>
    </div>
    <p v-if="preview" class="ax-mono text-xs text-outline mt-2">Design preview build: the panel API is not called. The sample below is illustrative only.</p>
    <p v-else-if="host && !host.connected" class="text-body-sm mt-2" style="color: rgb(var(--c-tertiary))">
      {{ reasonText[host.reason] || 'Host data is unavailable.' }} <span class="ax-mono text-[11px] text-outline">({{ host.reason }})</span>
    </p>
    <template v-else-if="host?.connected">
      <dl class="grid grid-cols-2 md:grid-cols-4 gap-3 mt-3 ax-mono text-xs">
        <div><dt class="text-outline">hostname</dt><dd class="text-on-surface">{{ host.info.hostname || '—' }}</dd></div>
        <div><dt class="text-outline">os</dt><dd class="text-on-surface">{{ host.info.os || '—' }}</dd></div>
        <div><dt class="text-outline">kernel</dt><dd class="text-on-surface">{{ host.info.kernel || '—' }}</dd></div>
        <div><dt class="text-outline">agent</dt><dd class="text-on-surface">{{ host.info.version || '—' }} · proto {{ host.info.protocol }}</dd></div>
        <div><dt class="text-outline">load 1 / 5 / 15</dt><dd class="text-on-surface">{{ host.stats ? `${host.stats.load1} / ${host.stats.load5} / ${host.stats.load15}` : '—' }}</dd></div>
        <div><dt class="text-outline">memory used</dt><dd class="text-on-surface">{{ memUsedPct === null ? '—' : memUsedPct + '%' }}<span v-if="host.stats" class="text-outline"> of {{ formatBytes(host.stats.mem_total_bytes) }}</span></dd></div>
        <div><dt class="text-outline">memory free</dt><dd class="text-on-surface">{{ host.stats ? formatBytes(host.stats.mem_available_bytes) : '—' }}</dd></div>
        <div><dt class="text-outline">uptime</dt><dd class="text-on-surface">{{ host.stats ? formatUptime(host.stats.uptime_seconds) : '—' }}</dd></div>
      </dl>
      <p v-if="host.statsReason" class="ax-mono text-[11px] mt-2" style="color: rgb(var(--c-tertiary))">stats unavailable: {{ host.statsReason }}</p>
      <p class="ax-mono text-[11px] text-outline mt-2">Values above come from the local agent. Everything below is the static design sample with example data.</p>
    </template>
  </div>
</section>
<section @click="previewAction" @submit.prevent>
<div v-if="notice" class="preview-notice" role="status">{{ notice }} <button class="ax-btn ax-btn-ghost" @click.stop="notice = ''">Dismiss</button></div>
<main v-pre class="w-full pt-4 bg-surface min-h-screen"><div class="flex flex-col w-full">
<!-- Sub-header Node Status Bar & Actions -->
<section class="w-full bg-surface-container-low px-gutter-lg py-space-md">
<div class="max-w-[1600px] mx-auto flex flex-col xl:flex-row xl:items-center justify-between gap-space-md">
<!-- Node Identification -->
<div class="flex items-center gap-space-lg flex-wrap">
<div class="flex items-center gap-space-md">
<div class="p-space-sm rounded-xl bg-surface-container-high flex items-center justify-center">
<span aria-hidden="true" class="material-symbols-outlined text-primary text-2xl">dns</span>
</div>
<div>
<div class="flex items-center gap-space-sm">
<span class="font-headline-md text-headline-md text-on-surface font-semibold tracking-tight">node-01</span>
<span class="inline-flex items-center gap-1 font-label-caps text-label-caps text-secondary bg-secondary/10 px-2 py-0.5 rounded-full">
<span class="h-1.5 w-1.5 rounded-full bg-secondary animate-pulse"></span>
                HEALTHY / ACTIVE
              </span>
<span class="font-label-caps text-label-caps text-outline bg-surface-container-highest px-2 py-0.5 rounded">
                SGP-DC-02
              </span>
</div>
<div class="flex items-center gap-space-md mt-0.5 font-code-sm text-code-sm text-on-surface-variant">
<span class="font-mono text-primary">203.0.113.10</span>
<span class="">•</span>
<span class="">Ubuntu 24.04 LTS (6.8.0-31-generic)</span>
<span class="">•</span>
<span class="">Uptime: <strong class="text-on-surface font-mono">99.98% (42d 18h)</strong></span>
</div>
</div>
</div>
</div>
<!-- Quick Action Controls -->
<div class="flex items-center gap-space-sm flex-wrap">
<button class="flex items-center gap-space-xs px-space-md py-space-xs rounded-lg bg-primary text-on-primary font-body-sm text-body-sm font-semibold hover:bg-primary-container transition-all shadow-sm" type="button">
<span aria-hidden="true" class="material-symbols-outlined text-base">terminal</span>
<span class="">Open Web SSH</span>
</button>
<button class="flex items-center gap-space-xs px-space-md py-space-xs rounded-lg bg-surface-container text-on-surface hover:bg-surface-container-high transition-colors font-body-sm text-body-sm" type="button">
<span aria-hidden="true" class="material-symbols-outlined text-base text-primary">photo_camera</span>
<span class="">Create Backup</span>
</button>
<button class="flex items-center gap-space-xs px-space-md py-space-xs rounded-lg bg-surface-container text-on-surface hover:bg-surface-container-high transition-colors font-body-sm text-body-sm" type="button">
<span aria-hidden="true" class="material-symbols-outlined text-base text-tertiary">restart_alt</span>
<span class="">Reboot</span>
</button>
<button class="flex items-center gap-space-xs px-space-md py-space-xs rounded-lg bg-error-container/20 text-error hover:bg-error-container/40 transition-colors font-body-sm text-body-sm" type="button">
<span aria-hidden="true" class="material-symbols-outlined text-base">power_settings_new</span>
<span class="">Power Off</span>
</button>
</div>
</div>
</section>
<!-- Main Content Space -->
<div class="w-full px-gutter-lg py-margin-md max-w-[1600px] mx-auto space-y-gutter-lg">
<!-- 1. Real-time Telemetry Bento Grid -->
<section class="space-y-space-sm">
<div class="flex items-center justify-between">
<div class="flex items-center gap-space-sm">
<span class="font-label-caps text-label-caps text-outline uppercase tracking-wider">Live System Metrics</span>
<span class="h-1.5 w-1.5 rounded-full bg-primary animate-ping"></span>
<span class="font-code-sm text-code-sm text-primary">Example telemetry · not live</span>
</div>
<div class="flex items-center gap-space-xs font-code-sm text-code-sm text-outline">
<span class="">Telemetry Interval:</span>
<span class="text-on-surface bg-surface-container-high px-2 py-0.5 rounded">Past 1 Hour</span>
</div>
</div>
<div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-gutter">
<!-- Metric 1: CPU Usage -->
<div class="p-space-lg rounded-xl bg-surface-container-low shadow-sm flex flex-col justify-between">
<div>
<div class="flex items-center justify-between mb-space-xs">
<span class="font-label-caps text-label-caps text-outline uppercase">Processor Load</span>
<span aria-hidden="true" class="material-symbols-outlined text-primary text-xl">memory</span>
</div>
<div class="flex items-baseline justify-between">
<div class="font-headline-xl text-headline-xl font-bold text-on-surface font-mono">
                34.2<span class="text-headline-md text-primary">%</span>
</div>
<span class="font-code-sm text-code-sm text-secondary font-mono bg-secondary/10 px-2 py-0.5 rounded">
                -2.1% avg
              </span>
</div>
<p class="font-code-sm text-code-sm text-on-surface-variant mt-1">4 vCPU AMD EPYC 9354 @ 2.80GHz</p>
</div>
<!-- Sparkline CPU SVG -->
<div class="mt-space-md pt-space-xs">
<div class="h-12 w-full flex items-end">
<svg class="w-full h-full text-primary" preserveAspectRatio="none" viewBox="0 0 200 48">
<defs>
<linearGradient id="cpuGrad" x1="0" x2="0" y1="0" y2="1">
<stop offset="0%" stop-color="currentColor" stop-opacity="0.3"></stop>
<stop offset="100%" stop-color="currentColor" stop-opacity="0.0"></stop>
</linearGradient>
</defs>
<path d="M0,38 L15,35 L30,40 L45,28 L60,32 L75,18 L90,26 L105,20 L120,30 L135,16 L150,22 L165,12 L180,24 L200,16 L200,48 L0,48 Z" fill="url(#cpuGrad)"></path>
<path d="M0,38 L15,35 L30,40 L45,28 L60,32 L75,18 L90,26 L105,20 L120,30 L135,16 L150,22 L165,12 L180,24 L200,16" fill="none" stroke="currentColor" stroke-linecap="round" stroke-width="2"></path>
</svg>
</div>
<div class="flex justify-between items-center font-code-sm text-code-sm text-outline mt-1 font-mono">
<span class="">-60m</span>
<span class="">Load: 0.78, 0.65, 0.54</span>
<span class="">Now</span>
</div>
</div>
</div>
<!-- Metric 2: Memory RAM -->
<div class="p-space-lg rounded-xl bg-surface-container-low shadow-sm flex flex-col justify-between">
<div>
<div class="flex items-center justify-between mb-space-xs">
<span class="font-label-caps text-label-caps text-outline uppercase">RAM Memory</span>
<span aria-hidden="true" class="material-symbols-outlined text-secondary text-xl">straighten</span>
</div>
<div class="flex items-baseline justify-between">
<div class="font-headline-xl text-headline-xl font-bold text-on-surface font-mono">
                4.8<span class="text-headline-md text-on-surface-variant font-normal"> / 8.0 GB</span>
</div>
<span class="font-code-sm text-code-sm text-secondary font-mono bg-secondary/10 px-2 py-0.5 rounded">
                60.0%
              </span>
</div>
<p class="font-code-sm text-code-sm text-on-surface-variant mt-1">DDR5 ECC Registered RAM</p>
</div>
<!-- Memory Breakdown Bar -->
<div class="mt-space-md space-y-space-xs">
<div class="h-2 w-full bg-surface-container-highest rounded-full overflow-hidden flex">
<div class="h-full bg-secondary" style="width: 42%" title="Active"></div>
<div class="h-full bg-primary" style="width: 18%" title="Cached"></div>
<div class="h-full bg-tertiary" style="width: 5%" title="Buffers"></div>
</div>
<div class="grid grid-cols-3 gap-1 pt-1 font-code-sm text-code-sm">
<div>
<span class="text-outline block">Active</span>
<span class="text-secondary font-mono">3.36 GB</span>
</div>
<div>
<span class="text-outline block">Cached</span>
<span class="text-primary font-mono">1.44 GB</span>
</div>
<div class="text-right">
<span class="text-outline block">Swap</span>
<span class="text-on-surface font-mono">0 / 2 GB</span>
</div>
</div>
</div>
</div>
<!-- Metric 3: NVMe Storage -->
<div class="p-space-lg rounded-xl bg-surface-container-low shadow-sm flex flex-col justify-between">
<div>
<div class="flex items-center justify-between mb-space-xs">
<span class="font-label-caps text-label-caps text-outline uppercase">NVMe Storage (/)</span>
<span aria-hidden="true" class="material-symbols-outlined text-tertiary text-xl">hard_drive</span>
</div>
<div class="flex items-baseline justify-between">
<div class="font-headline-xl text-headline-xl font-bold text-on-surface font-mono">
                58.2<span class="text-headline-md text-on-surface-variant font-normal"> / 160 GB</span>
</div>
<span class="font-code-sm text-code-sm text-tertiary font-mono bg-tertiary/10 px-2 py-0.5 rounded">
                36.4%
              </span>
</div>
<p class="font-code-sm text-code-sm text-on-surface-variant mt-1">PCIe 4.0 ZFS Pool `tank/root`</p>
</div>
<!-- Disk Throughput Info -->
<div class="mt-space-md space-y-space-xs">
<div class="h-2 w-full bg-surface-container-highest rounded-full overflow-hidden">
<div class="h-full bg-tertiary" style="width: 36.4%"></div>
</div>
<div class="flex justify-between items-center pt-1 font-code-sm text-code-sm">
<div class="flex items-center gap-1">
<span aria-hidden="true" class="material-symbols-outlined text-xs text-primary">arrow_downward</span>
<span class="text-outline">R:</span>
<span class="text-on-surface font-mono">12.4 MB/s</span>
</div>
<div class="flex items-center gap-1">
<span aria-hidden="true" class="material-symbols-outlined text-xs text-tertiary">arrow_upward</span>
<span class="text-outline">W:</span>
<span class="text-on-surface font-mono">3.8 MB/s</span>
</div>
<div>
<span class="text-secondary font-mono">1.2k IOPS</span>
</div>
</div>
</div>
</div>
<!-- Metric 4: Network Bandwidth -->
<div class="p-space-lg rounded-xl bg-surface-container-low shadow-sm flex flex-col justify-between">
<div>
<div class="flex items-center justify-between mb-space-xs">
<span class="font-label-caps text-label-caps text-outline uppercase">Interface eth0</span>
<span aria-hidden="true" class="material-symbols-outlined text-primary text-xl">router</span>
</div>
<div class="flex items-baseline justify-between">
<div class="font-headline-xl text-headline-xl font-bold text-on-surface font-mono">
                60.8<span class="text-headline-md text-on-surface-variant font-normal"> Mbps</span>
</div>
<span class="font-code-sm text-code-sm text-primary font-mono bg-primary/10 px-2 py-0.5 rounded">
                10 Gbps Pipe
              </span>
</div>
<p class="font-code-sm text-code-sm text-on-surface-variant mt-1">Egress limit quota: 1.2 / 10 TB (12%)</p>
</div>
<!-- Network Rx/Tx Specs -->
<div class="mt-space-md space-y-space-xs">
<div class="flex justify-between items-center font-code-sm text-code-sm">
<span class="text-outline">Inbound (RX)</span>
<span class="text-primary font-mono font-medium">42.6 Mbps</span>
</div>
<div class="h-1.5 w-full bg-surface-container-highest rounded-full overflow-hidden">
<div class="h-full bg-primary" style="width: 42.6%"></div>
</div>
<div class="flex justify-between items-center font-code-sm text-code-sm pt-1">
<span class="text-outline">Outbound (TX)</span>
<span class="text-secondary font-mono font-medium">18.2 Mbps</span>
</div>
<div class="h-1.5 w-full bg-surface-container-highest rounded-full overflow-hidden">
<div class="h-full bg-secondary" style="width: 18.2%"></div>
</div>
</div>
</div>
</div>
</section>
<!-- 2. Dual-Pane: Daemons & Fleet Status -->
<div class="grid grid-cols-1 lg:grid-cols-12 gap-gutter-lg">
<!-- Left Column: Daemon & Core Stack Runtime (7 cols) -->
<section class="lg:col-span-7 space-y-space-sm flex flex-col">
<div class="flex items-center justify-between">
<div class="flex items-center gap-space-sm">
<span aria-hidden="true" class="material-symbols-outlined text-primary text-lg">deployed_code</span>
<span class="font-headline-md text-headline-md text-on-surface font-semibold">System Daemons &amp; Services</span>
</div>
<button class="font-code-sm text-code-sm text-primary hover:underline flex items-center gap-1" type="button">
<span class="">Manage All (5)</span>
<span aria-hidden="true" class="material-symbols-outlined text-sm">chevron_right</span>
</button>
</div>
<div class="space-y-space-xs">
<!-- Service 1: Docker -->
<div class="p-space-md rounded-xl bg-surface-container-low hover:bg-surface-container transition-colors flex items-center justify-between gap-space-md">
<div class="flex items-center gap-space-md min-w-0">
<div class="h-10 w-10 rounded-lg bg-surface-container-high flex items-center justify-center shrink-0">
<span aria-hidden="true" class="material-symbols-outlined text-primary text-xl">token</span>
</div>
<div class="min-w-0">
<div class="flex items-center gap-space-sm">
<h4 class="font-body-md text-body-md font-semibold text-on-surface">Docker Engine</h4>
<span class="font-code-sm text-code-sm px-1.5 py-0.5 rounded bg-surface-container-highest text-outline font-mono">v26.1.2</span>
</div>
<p class="font-code-sm text-code-sm text-on-surface-variant truncate">
                  14 containers running • 2 stopped • overlay2 driver
                </p>
</div>
</div>
<div class="flex items-center gap-space-md shrink-0">
<div class="text-right hidden sm:block">
<span class="font-code-sm text-code-sm text-secondary font-mono block">RUNNING</span>
<span class="font-code-sm text-code-sm text-outline font-mono">1.82 GB allocated</span>
</div>
<span class="h-2.5 w-2.5 rounded-full bg-secondary shadow-sm"></span>
</div>
</div>
<!-- Service 2: Nginx -->
<div class="p-space-md rounded-xl bg-surface-container-low hover:bg-surface-container transition-colors flex items-center justify-between gap-space-md">
<div class="flex items-center gap-space-md min-w-0">
<div class="h-10 w-10 rounded-lg bg-surface-container-high flex items-center justify-center shrink-0">
<span aria-hidden="true" class="material-symbols-outlined text-secondary text-xl">sync_alt</span>
</div>
<div class="min-w-0">
<div class="flex items-center gap-space-sm">
<h4 class="font-body-md text-body-md font-semibold text-on-surface">Nginx Reverse Proxy</h4>
<span class="font-code-sm text-code-sm px-1.5 py-0.5 rounded bg-surface-container-highest text-outline font-mono">1.26.0</span>
</div>
<p class="font-code-sm text-code-sm text-on-surface-variant truncate">
                  HTTP/3 QUIC enabled • SSL auto-renewing in 48 days (Certbot)
                </p>
</div>
</div>
<div class="flex items-center gap-space-md shrink-0">
<div class="text-right hidden sm:block">
<span class="font-code-sm text-code-sm text-secondary font-mono block">ACTIVE</span>
<span class="font-code-sm text-code-sm text-outline font-mono">Ports: 80, 443</span>
</div>
<span class="h-2.5 w-2.5 rounded-full bg-secondary shadow-sm"></span>
</div>
</div>
<!-- Service 3: PostgreSQL -->
<div class="p-space-md rounded-xl bg-surface-container-low hover:bg-surface-container transition-colors flex items-center justify-between gap-space-md">
<div class="flex items-center gap-space-md min-w-0">
<div class="h-10 w-10 rounded-lg bg-surface-container-high flex items-center justify-center shrink-0">
<span aria-hidden="true" class="material-symbols-outlined text-primary text-xl">database</span>
</div>
<div class="min-w-0">
<div class="flex items-center gap-space-sm">
<h4 class="font-body-md text-body-md font-semibold text-on-surface">PostgreSQL Relational DB</h4>
<span class="font-code-sm text-code-sm px-1.5 py-0.5 rounded bg-surface-container-highest text-outline font-mono">v16.3</span>
</div>
<p class="font-code-sm text-code-sm text-on-surface-variant truncate">
                  28 active connections • pg_stat_statements active • 42 TPS
                </p>
</div>
</div>
<div class="flex items-center gap-space-md shrink-0">
<div class="text-right hidden sm:block">
<span class="font-code-sm text-code-sm text-secondary font-mono block">ACTIVE</span>
<span class="font-code-sm text-code-sm text-outline font-mono">Port: 5432</span>
</div>
<span class="h-2.5 w-2.5 rounded-full bg-secondary shadow-sm"></span>
</div>
</div>
<!-- Service 4: Redis -->
<div class="p-space-md rounded-xl bg-surface-container-low hover:bg-surface-container transition-colors flex items-center justify-between gap-space-md">
<div class="flex items-center gap-space-md min-w-0">
<div class="h-10 w-10 rounded-lg bg-surface-container-high flex items-center justify-center shrink-0">
<span aria-hidden="true" class="material-symbols-outlined text-tertiary text-xl">bolt</span>
</div>
<div class="min-w-0">
<div class="flex items-center gap-space-sm">
<h4 class="font-body-md text-body-md font-semibold text-on-surface">Redis Cache &amp; PubSub</h4>
<span class="font-code-sm text-code-sm px-1.5 py-0.5 rounded bg-surface-container-highest text-outline font-mono">v7.2.4</span>
</div>
<p class="font-code-sm text-code-sm text-on-surface-variant truncate">
                  Memory usage: 184.2 MB • Hit rate: 98.4% • 1,420 keys
                </p>
</div>
</div>
<div class="flex items-center gap-space-md shrink-0">
<div class="text-right hidden sm:block">
<span class="font-code-sm text-code-sm text-secondary font-mono block">ACTIVE</span>
<span class="font-code-sm text-code-sm text-outline font-mono">Port: 6379</span>
</div>
<span class="h-2.5 w-2.5 rounded-full bg-secondary shadow-sm"></span>
</div>
</div>
<!-- Service 5: UFW Firewall -->
<div class="p-space-md rounded-xl bg-surface-container-low hover:bg-surface-container transition-colors flex items-center justify-between gap-space-md">
<div class="flex items-center gap-space-md min-w-0">
<div class="h-10 w-10 rounded-lg bg-surface-container-high flex items-center justify-center shrink-0">
<span aria-hidden="true" class="material-symbols-outlined text-secondary text-xl">shield</span>
</div>
<div class="min-w-0">
<div class="flex items-center gap-space-sm">
<h4 class="font-body-md text-body-md font-semibold text-on-surface">Host Firewall</h4>
<span class="font-code-sm text-code-sm px-1.5 py-0.5 rounded bg-surface-container-highest text-outline font-mono">v0.36.2</span>
</div>
<p class="font-code-sm text-code-sm text-on-surface-variant truncate">
                  4 ingress rules active • Default DENY incoming • WireGuard port open
                </p>
</div>
</div>
<div class="flex items-center gap-space-md shrink-0">
<div class="text-right hidden sm:block">
<span class="font-code-sm text-code-sm text-secondary font-mono block">FILTERING</span>
<span class="font-code-sm text-code-sm text-outline font-mono">Drops: 184/min</span>
</div>
<span class="h-2.5 w-2.5 rounded-full bg-secondary shadow-sm"></span>
</div>
</div>
</div>
</section>
<!-- Right Column: Clustered Node Fleet Table (5 cols) -->
<section class="lg:col-span-5 space-y-space-sm flex flex-col">
<div class="flex items-center justify-between">
<div class="flex items-center gap-space-sm">
<span aria-hidden="true" class="material-symbols-outlined text-primary text-lg">lan</span>
<span class="font-headline-md text-headline-md text-on-surface font-semibold">Managed Nodes</span>
</div>
<span class="font-label-caps text-label-caps px-2 py-0.5 rounded bg-surface-container-highest text-on-surface-variant font-mono">3 / 3 ONLINE</span>
</div>
<div class="p-space-md rounded-xl bg-surface-container-low shadow-sm flex-1 flex flex-col justify-between">
<div class="overflow-x-auto">
<table class="w-full text-left font-body-sm text-body-sm">
<thead>
<tr class="font-label-caps text-label-caps text-outline uppercase">
<th class="pb-space-sm">Node Tag</th>
<th class="pb-space-sm text-center">Ping</th>
<th class="pb-space-sm text-right">CPU</th>
<th class="pb-space-sm text-right">RAM</th>
<th class="pb-space-sm text-right">State</th>
</tr>
</thead>
<tbody class="font-code-sm text-code-sm">
<!-- Row 1: SGP (Current) -->
<tr class="bg-surface-container/60 rounded">
<td class="py-space-sm font-semibold text-on-surface flex items-center gap-2">
<span class="h-2 w-2 rounded-full bg-secondary"></span>
<span class="text-primary font-mono">node-sgp-01</span>
<span class="font-label-caps text-label-caps bg-primary/10 text-primary px-1.5 rounded">LEADER</span>
</td>
<td class="py-space-sm text-center font-mono text-secondary">0.4ms</td>
<td class="py-space-sm text-right font-mono text-on-surface">34.2%</td>
<td class="py-space-sm text-right font-mono text-on-surface">60%</td>
<td class="py-space-sm text-right">
<span class="text-secondary font-mono font-medium">OK</span>
</td>
</tr>
<!-- Row 2: FRA -->
<tr class="hover:bg-surface-container-high/40 transition-colors">
<td class="py-space-sm font-semibold text-on-surface flex items-center gap-2">
<span class="h-2 w-2 rounded-full bg-secondary"></span>
<span class="font-mono">node-fra-02</span>
<span class="font-label-caps text-label-caps text-outline">WORKER</span>
</td>
<td class="py-space-sm text-center font-mono text-on-surface-variant">142ms</td>
<td class="py-space-sm text-right font-mono text-on-surface">51.8%</td>
<td class="py-space-sm text-right font-mono text-on-surface">78%</td>
<td class="py-space-sm text-right">
<span class="text-secondary font-mono font-medium">OK</span>
</td>
</tr>
<!-- Row 3: NYC -->
<tr class="hover:bg-surface-container-high/40 transition-colors">
<td class="py-space-sm font-semibold text-on-surface flex items-center gap-2">
<span class="h-2 w-2 rounded-full bg-secondary"></span>
<span class="font-mono">node-nyc-03</span>
<span class="font-label-caps text-label-caps text-outline">WORKER</span>
</td>
<td class="py-space-sm text-center font-mono text-on-surface-variant">186ms</td>
<td class="py-space-sm text-right font-mono text-on-surface">19.4%</td>
<td class="py-space-sm text-right font-mono text-on-surface">44%</td>
<td class="py-space-sm text-right">
<span class="text-secondary font-mono font-medium">OK</span>
</td>
</tr>
</tbody>
</table>
</div>
<!-- Quick Cluster Overview Box -->
<div class="mt-space-md p-space-sm rounded-lg bg-surface-container flex items-center justify-between">
<div class="flex items-center gap-space-sm">
<span aria-hidden="true" class="material-symbols-outlined text-outline text-lg">sync_problem</span>
<span class="font-body-sm text-body-sm text-on-surface-variant">Example host group · independent managed nodes</span>
</div>
<button class="font-label-caps text-label-caps text-primary hover:underline uppercase" type="button">
              Topology View
            </button>
</div>
</div>
</section>
</div>
<!-- 3. Bottom Pane: Audit Events & Active Log Stream -->
<section class="space-y-space-sm">
<div class="flex items-center justify-between">
<div class="flex items-center gap-space-sm">
<span aria-hidden="true" class="material-symbols-outlined text-primary text-lg">history_toggle_off</span>
<span class="font-headline-md text-headline-md text-on-surface font-semibold">System Audit &amp; Event Stream</span>
</div>
<div class="flex items-center gap-space-sm">
<button class="font-code-sm text-code-sm text-outline hover:text-on-surface flex items-center gap-1" type="button">
<span aria-hidden="true" class="material-symbols-outlined text-sm">filter_list</span> Filter
          </button>
<span class="text-outline-variant">|</span>
<button class="font-code-sm text-code-sm text-primary hover:underline" type="button">
            Export JSON Logs
          </button>
</div>
</div>
<div class="rounded-xl bg-surface-container-low shadow-sm p-space-md space-y-space-sm">
<!-- Log Entry 1: Deploy -->
<div class="p-space-sm rounded-lg bg-surface-container hover:bg-surface-container-high transition-colors flex flex-col md:flex-row md:items-center justify-between gap-space-sm">
<div class="flex items-center gap-space-md min-w-0">
<div class="h-8 w-8 rounded bg-primary/10 flex items-center justify-center shrink-0">
<span aria-hidden="true" class="material-symbols-outlined text-primary text-base">cloud_sync</span>
</div>
<div class="min-w-0">
<div class="flex items-center gap-space-sm flex-wrap">
<span class="font-code-sm text-code-sm font-semibold text-primary">DEPLOYMENT_SUCCESS</span>
<span class="font-code-sm text-code-sm text-on-surface">Git webhook deployed commit</span>
<span class="font-code-sm text-code-sm font-mono px-1.5 py-0.2 rounded bg-surface-container-highest text-tertiary">#a8f92c1</span>
<span class="font-code-sm text-code-sm text-on-surface">to container <strong class="text-on-surface font-mono">axion-api:latest</strong></span>
</div>
<p class="font-code-sm text-code-sm text-outline truncate">Triggered via GitHub Action runner pipeline ID #84912 • Healthcheck 200 OK</p>
</div>
</div>
<div class="flex items-center gap-space-md shrink-0 text-right">
<span class="font-code-sm text-code-sm text-outline font-mono">2 mins ago (14:38:12 UTC)</span>
<span class="font-label-caps text-label-caps text-secondary bg-secondary/10 px-2 py-0.5 rounded">200 OK</span>
</div>
</div>
<!-- Log Entry 2: SSL Renew -->
<div class="p-space-sm rounded-lg bg-surface-container hover:bg-surface-container-high transition-colors flex flex-col md:flex-row md:items-center justify-between gap-space-sm">
<div class="flex items-center gap-space-md min-w-0">
<div class="h-8 w-8 rounded bg-secondary/10 flex items-center justify-center shrink-0">
<span aria-hidden="true" class="material-symbols-outlined text-secondary text-base">verified</span>
</div>
<div class="min-w-0">
<div class="flex items-center gap-space-sm flex-wrap">
<span class="font-code-sm text-code-sm font-semibold text-secondary">CERT_RENEWED</span>
<span class="font-code-sm text-code-sm text-on-surface">Let's Encrypt TLS certificate renewed automatically</span>
<span class="font-code-sm text-code-sm font-mono text-outline">*.api.axion.io</span>
</div>
<p class="font-code-sm text-code-sm text-outline truncate">ACME challenge passed via Cloudflare DNS-01 validation • Next expiration: 89 days</p>
</div>
</div>
<div class="flex items-center gap-space-md shrink-0 text-right">
<span class="font-code-sm text-code-sm text-outline font-mono">1 hr ago (13:30:00 UTC)</span>
<span class="font-label-caps text-label-caps text-secondary bg-secondary/10 px-2 py-0.5 rounded">SUCCESS</span>
</div>
</div>
<!-- Log Entry 3: Backup Snapshot -->
<div class="p-space-sm rounded-lg bg-surface-container hover:bg-surface-container-high transition-colors flex flex-col md:flex-row md:items-center justify-between gap-space-sm">
<div class="flex items-center gap-space-md min-w-0">
<div class="h-8 w-8 rounded bg-tertiary/10 flex items-center justify-center shrink-0">
<span aria-hidden="true" class="material-symbols-outlined text-tertiary text-base">inventory_2</span>
</div>
<div class="min-w-0">
<div class="flex items-center gap-space-sm flex-wrap">
<span class="font-code-sm text-code-sm font-semibold text-tertiary">SNAPSHOT_COMPLETED</span>
<span class="font-code-sm text-code-sm text-on-surface">Nightly differential disk snapshot created</span>
<span class="font-code-sm text-code-sm font-mono px-1.5 py-0.2 rounded bg-surface-container-highest text-on-surface">1.42 GB</span>
</div>
<p class="font-code-sm text-code-sm text-outline truncate">Stored in S3 compatible cold storage vault (ap-southeast-1) • SHA-256 integrity verified</p>
</div>
</div>
<div class="flex items-center gap-space-md shrink-0 text-right">
<span class="font-code-sm text-code-sm text-outline font-mono">4 hrs ago (10:15:22 UTC)</span>
<span class="font-label-caps text-label-caps text-outline bg-surface-container-highest px-2 py-0.5 rounded">ARCHIVED</span>
</div>
</div>
</div>
</section>
</div>
</div></main>
</section>
</template>
