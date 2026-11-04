<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { session } from '../auth/session.js'
import { isDesignPreview } from '../designMode.js'
import { loadHost, formatBytes, reasonText } from '../system/host.js'
import { hostSummary, cpuCard, memoryCard, diskCard, networkCard, staleAfter, formatRate, formatPercent } from '../system/overview.js'
import { createHostPoller } from '../system/poller.js'

const notice = ref('')
const preview = isDesignPreview()
const host = ref(null)
const loading = ref(false)
const live = ref(false)
const now = ref(Date.now())
let clock = null
let disposed = false
let poller = null

function publishHost(result) {
  host.value = result
  live.value = Boolean(result?.connected)
  window.dispatchEvent(new CustomEvent('axp:host', { detail: result }))
}

function applyHost(result) {
  if (disposed) return
  publishHost(result)
}

const onUnauthorized = () => {
  // A 401 means the HttpOnly session may have expired. Drop every value
  // (identity and metrics) before revalidating so no stale agent data is
  // shown while redirecting to sign-in. After unmount this response belongs
  // to a dead view: it must not publish or revalidate for the live one.
  if (disposed) return Promise.resolve()
  publishHost(null)
  return session.check()
}

poller = createHostPoller({
  load: () => loadHost(undefined, { onUnauthorized }),
  onResult: applyHost,
})

async function refreshHost() {
  if (preview) return
  loading.value = true
  try { await poller.refresh() } finally { loading.value = false }
}

function previewAction(event) {
  if (!preview) return
  const target = event.target.closest('button, a, input[type=checkbox]')
  if (!target) return
  event.preventDefault()
  notice.value = 'Preview only — no command was sent to a server.'
}

const summary = computed(() => hostSummary(host.value, { loading: loading.value, preview }))
const cpu = computed(() => cpuCard(host.value, { preview }))
const mem = computed(() => memoryCard(host.value, { preview }))
const disk = computed(() => diskCard(host.value, { preview }))
const net = computed(() => networkCard(host.value, { preview }))
const stale = computed(() => staleAfter(host.value?.metrics, now.value))

const statusLabel = computed(() => {
  if (preview) return 'DESIGN PREVIEW'
  if (summary.value.linkStatus === 'loading') return 'LOADING'
  if (summary.value.linkStatus === 'live') return 'LIVE / ACTIVE'
  return 'AGENT UNAVAILABLE'
})

onMounted(() => {
  if (preview) return
  clock = setInterval(() => { now.value = Date.now() }, 1000)
  loading.value = true
  poller.start()
  poller.idle().finally(() => { loading.value = false })
})
onUnmounted(() => {
  disposed = true
  clearInterval(clock)
  clock = null
  poller?.stop()
  publishHost(null)
})
</script>
<template>
<section class="pt-16 px-gutter-lg">
  <div v-if="notice" class="preview-notice" role="status">{{ notice }} <button class="ax-btn ax-btn-ghost" @click="notice = ''">Dismiss</button></div>
</section>
<section @click="previewAction" @submit.prevent>
<main class="w-full pt-4 bg-surface min-h-screen"><div class="flex flex-col w-full">
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
<span class="font-headline-md text-headline-md text-on-surface font-semibold tracking-tight">{{ summary.hostname || 'Host' }}</span>
<span class="inline-flex items-center gap-1 font-label-caps text-label-caps px-2 py-0.5 rounded-full"
  :class="live ? 'text-secondary bg-secondary/10' : 'text-outline bg-surface-container-highest'">
<span class="h-1.5 w-1.5 rounded-full" :class="live ? 'bg-secondary animate-pulse' : 'bg-outline'"></span>
                {{ statusLabel }}
              </span>
<span class="font-label-caps text-label-caps text-outline bg-surface-container-highest px-2 py-0.5 rounded">
                IP: unavailable
              </span>
</div>
<div class="flex items-center gap-space-md mt-0.5 font-code-sm text-code-sm text-on-surface-variant">
<span class="font-mono text-primary">{{ summary.os ? `${summary.os}${summary.kernel ? ` (${summary.kernel})` : ''}` : 'OS unavailable' }}</span>
<span class="">•</span>
<span class="">{{ summary.arch || 'arch unavailable' }}</span>
<span class="">•</span>
<span class="">Uptime: <strong class="text-on-surface font-mono">{{ summary.uptime || '—' }}</strong></span>
<span class="">•</span>
<span class="">RAM: <strong class="text-on-surface font-mono">{{ summary.totalRam || '—' }}</strong></span>
</div>
</div>
</div>
</div>
<!-- Quick Action Controls -->
<div class="flex items-center gap-space-sm flex-wrap">
<button class="flex items-center gap-space-xs px-space-md py-space-xs rounded-lg bg-surface-container text-on-surface-variant font-body-sm text-body-sm font-semibold transition-all cursor-not-allowed" type="button" disabled title="Unavailable — no backend action exists">
<span aria-hidden="true" class="material-symbols-outlined text-base">terminal</span>
<span class="">Open Web SSH (unavailable)</span>
</button>
<button class="flex items-center gap-space-xs px-space-md py-space-xs rounded-lg bg-surface-container text-on-surface-variant font-body-sm text-body-sm cursor-not-allowed" type="button" disabled title="Unavailable — no backend action exists">
<span aria-hidden="true" class="material-symbols-outlined text-base">photo_camera</span>
<span class="">Create Backup (unavailable)</span>
</button>
<button class="flex items-center gap-space-xs px-space-md py-space-xs rounded-lg bg-surface-container text-on-surface-variant font-body-sm text-body-sm cursor-not-allowed" type="button" disabled title="Unavailable — no backend action exists">
<span aria-hidden="true" class="material-symbols-outlined text-base">restart_alt</span>
<span class="">Reboot (unavailable)</span>
</button>
<button class="flex items-center gap-space-xs px-space-md py-space-xs rounded-lg bg-surface-container text-on-surface-variant font-body-sm text-body-sm cursor-not-allowed" type="button" disabled title="Unavailable — no backend action exists">
<span aria-hidden="true" class="material-symbols-outlined text-base">power_settings_new</span>
<span class="">Power Off (unavailable)</span>
</button>
</div>
</div>
</section>
<!-- Main Content Space -->
<div class="w-full px-gutter-lg py-margin-md max-w-[1600px] mx-auto space-y-gutter-lg">
<!-- 1. Live System Metrics Bento Grid -->
<section class="space-y-space-sm">
<div class="flex items-center justify-between">
<div class="flex items-center gap-space-sm">
<span class="font-label-caps text-label-caps text-outline uppercase tracking-wider">Live system metrics</span>
<span class="h-1.5 w-1.5 rounded-full" :class="live ? 'bg-primary animate-ping' : 'bg-outline'"></span>
<span class="font-code-sm text-code-sm" :class="live ? 'text-primary' : 'text-outline'">
{{ preview ? 'not loaded in design preview' : live ? (stale ? 'live · values may be stale' : 'live · updates every 5s') : (summary.linkStatus === 'loading' ? 'loading…' : (reasonText[summary.reason] || 'unavailable')) }}
</span>
</div>
<div class="flex items-center gap-space-xs font-code-sm text-code-sm text-outline">
<span class="">Refresh interval:</span>
<span class="text-on-surface bg-surface-container-high px-2 py-0.5 rounded">Every 5 seconds</span>
<button v-if="!preview" class="ax-btn ax-btn-ghost" :disabled="loading" @click="refreshHost">
<span aria-hidden="true" class="material-symbols-outlined text-base">refresh</span>Refresh
</button>
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
                {{ cpu.percent === null ? '—' : cpu.percent.toFixed(1) }}<span class="text-headline-md text-primary">%</span>
</div>
<span class="font-code-sm text-code-sm font-mono px-2 py-0.5 rounded" :class="cpu.available ? 'text-primary bg-primary/10' : 'text-outline bg-surface-container-highest'">
                {{ cpu.available ? 'live' : (cpu.reason || 'unavailable') }}
              </span>
</div>
<p class="font-code-sm text-code-sm text-on-surface-variant mt-1">{{ cpu.available ? `${cpu.logicalCpus} logical CPUs` : `unavailable: ${cpu.reason}` }}</p>
</div>
<div class="mt-space-md pt-space-xs">
<div class="h-12 w-full flex items-center justify-center rounded" style="background: rgb(var(--c-surface-container-highest) / .4)">
<span class="font-code-sm text-code-sm text-outline">History unavailable — no CPU history endpoint</span>
</div>
<div class="flex justify-between items-center font-code-sm text-code-sm text-outline mt-1 font-mono">
<span class="">Load:</span>
<span class="text-on-surface font-mono">{{ cpu.load || '—' }}</span>
<span class="">1 / 5 / 15 min</span>
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
                {{ mem.available ? formatBytes(mem.usedBytes) : '—' }}<span class="text-headline-md text-on-surface-variant font-normal"> / {{ mem.available ? formatBytes(mem.totalBytes) : '—' }}</span>
</div>
<span class="font-code-sm text-code-sm font-mono px-2 py-0.5 rounded" :class="mem.available ? 'text-secondary bg-secondary/10' : 'text-outline bg-surface-container-highest'">
                {{ mem.available ? formatPercent(mem.usedPercent) : (mem.reason || 'unavailable') }}
              </span>
</div>
<p class="font-code-sm text-code-sm text-on-surface-variant mt-1">{{ mem.available ? 'used = total − available' : `unavailable: ${mem.reason}` }}</p>
</div>
<div class="mt-space-md space-y-space-xs">
<div class="h-2 w-full bg-surface-container-highest rounded-full overflow-hidden">
<div class="h-full bg-secondary" :style="{ width: (mem.available ? Math.min(100, mem.usedPercent) : 0) + '%' }"></div>
</div>
<div class="grid grid-cols-3 gap-1 pt-1 font-code-sm text-code-sm">
<div><span class="text-outline block">Used</span><span class="text-secondary font-mono">{{ mem.available ? formatBytes(mem.usedBytes) : '—' }}</span></div>
<div><span class="text-outline block">Available</span><span class="text-primary font-mono">{{ mem.available ? formatBytes(mem.availableBytes) : '—' }}</span></div>
<div class="text-right"><span class="text-outline block">Total</span><span class="text-on-surface font-mono">{{ mem.available ? formatBytes(mem.totalBytes) : '—' }}</span></div>
</div>
</div>
</div>
<!-- Metric 3: Root Storage -->
<div class="p-space-lg rounded-xl bg-surface-container-low shadow-sm flex flex-col justify-between">
<div>
<div class="flex items-center justify-between mb-space-xs">
<span class="font-label-caps text-label-caps text-outline uppercase">Root filesystem ({{ disk.available ? disk.mount : '/' }})</span>
<span aria-hidden="true" class="material-symbols-outlined text-tertiary text-xl">hard_drive</span>
</div>
<div class="flex items-baseline justify-between">
<div class="font-headline-xl text-headline-xl font-bold text-on-surface font-mono">
                {{ disk.available ? formatBytes(disk.usedBytes) : '—' }}<span class="text-headline-md text-on-surface-variant font-normal"> / {{ disk.available ? formatBytes(disk.totalBytes) : '—' }}</span>
</div>
<span class="font-code-sm text-code-sm font-mono px-2 py-0.5 rounded" :class="disk.available ? 'text-tertiary bg-tertiary/10' : 'text-outline bg-surface-container-highest'">
                {{ disk.available ? formatPercent(disk.usedPercent) : (disk.reason || 'unavailable') }}
              </span>
</div>
<p class="font-code-sm text-code-sm text-on-surface-variant mt-1">{{ disk.available ? `${formatBytes(disk.availableBytes)} free` : `unavailable: ${disk.reason}` }}</p>
</div>
<div class="mt-space-md space-y-space-xs">
<div class="h-2 w-full bg-surface-container-highest rounded-full overflow-hidden">
<div class="h-full bg-tertiary" :style="{ width: (disk.available ? Math.min(100, disk.usedPercent) : 0) + '%' }"></div>
</div>
<div class="grid grid-cols-3 gap-1 pt-1 font-code-sm text-code-sm">
<div><span class="text-outline block">Used</span><span class="text-on-surface font-mono">{{ disk.available ? formatBytes(disk.usedBytes) : '—' }}</span></div>
<div><span class="text-outline block">Available</span><span class="text-on-surface font-mono">{{ disk.available ? formatBytes(disk.availableBytes) : '—' }}</span></div>
<div class="text-right"><span class="text-outline block">Total</span><span class="text-on-surface font-mono">{{ disk.available ? formatBytes(disk.totalBytes) : '—' }}</span></div>
</div>
</div>
</div>
<!-- Metric 4: Network Bandwidth -->
<div class="p-space-lg rounded-xl bg-surface-container-low shadow-sm flex flex-col justify-between">
<div>
<div class="flex items-center justify-between mb-space-xs">
<span class="font-label-caps text-label-caps text-outline uppercase">Interface {{ net.available ? net.interface : '—' }}</span>
<span aria-hidden="true" class="material-symbols-outlined text-primary text-xl">router</span>
</div>
<div class="flex items-baseline justify-between">
<div class="font-headline-xl text-headline-xl font-bold text-on-surface font-mono">
                {{ net.available ? formatRate(net.rxBytesPerSecond + net.txBytesPerSecond) : '—' }}
</div>
<span class="font-code-sm text-code-sm font-mono px-2 py-0.5 rounded" :class="net.available ? 'text-primary bg-primary/10' : 'text-outline bg-surface-container-highest'">
                {{ net.available ? 'live' : (net.reason || 'unavailable') }}
              </span>
</div>
<p class="font-code-sm text-code-sm text-on-surface-variant mt-1">{{ net.available ? 'RX + TX throughput' : `unavailable: ${net.reason}` }}</p>
</div>
<div class="mt-space-md space-y-space-xs">
<div class="flex justify-between items-center font-code-sm text-code-sm">
<span class="text-outline">Inbound (RX)</span>
<span class="text-primary font-mono font-medium">{{ net.available ? formatRate(net.rxBytesPerSecond) : '—' }}</span>
</div>
<div class="flex justify-between items-center font-code-sm text-code-sm pt-1">
<span class="text-outline">Outbound (TX)</span>
<span class="text-secondary font-mono font-medium">{{ net.available ? formatRate(net.txBytesPerSecond) : '—' }}</span>
</div>
</div>
</div>
</div>
</section>
<!-- 2. Dual-Pane: Daemons & Fleet Status (example data — read-only) -->
<div v-pre class="space-y-space-sm">
<div class="rounded-xl border p-space-sm" style="border-color: rgb(var(--c-outline-variant) / .4)">
<span class="font-label-caps text-label-caps text-outline uppercase">Example data — read-only. No host changes are performed.</span>
</div>
<div class="grid grid-cols-1 lg:grid-cols-12 gap-gutter-lg">
<!-- Left Column: Daemon & Core Stack Runtime (7 cols) -->
<section class="lg:col-span-7 space-y-space-sm flex flex-col">
<div class="flex items-center justify-between">
<div class="flex items-center gap-space-sm">
<span aria-hidden="true" class="material-symbols-outlined text-primary text-lg">deployed_code</span>
<span class="font-headline-md text-headline-md text-on-surface font-semibold">System Daemons &amp; Services</span>
</div>
<button class="font-code-sm text-code-sm text-outline flex items-center gap-1 cursor-not-allowed" type="button" disabled title="Unavailable — no backend action exists">
<span class="">Manage All (5) (unavailable)</span>
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
<button class="font-label-caps text-label-caps text-outline uppercase cursor-not-allowed" type="button" disabled title="Unavailable — no backend action exists">
              Topology View (unavailable)
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
<button class="font-code-sm text-code-sm text-outline flex items-center gap-1 cursor-not-allowed" type="button" disabled title="Unavailable — no backend action exists">
<span aria-hidden="true" class="material-symbols-outlined text-sm">filter_list</span> Filter (unavailable)
          </button>
<span class="text-outline-variant">|</span>
<button class="font-code-sm text-code-sm text-outline cursor-not-allowed" type="button" disabled title="Unavailable — no backend action exists">
            Export JSON Logs (unavailable)
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
</div>
</div></main>
</section>
</template>