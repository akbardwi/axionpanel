<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { session } from './auth/session.js'
import { isDesignPreview } from './designMode.js'
import { formatBytes, formatUptime } from './system/host.js'
const route = useRoute()
const router = useRouter()
const preview = isDesignPreview()
const dark = ref(true)
const mobileOpen = ref(false)
const signingOut = ref(false)
watch(() => route.path, () => { mobileOpen.value = false })
// Fail closed: any loss of the authenticated session (logout, expiry) leaves protected views.
watch(() => session.state.status, (status) => {
  if (status === 'unauthenticated') hostState.value = null
  if (!preview && status === 'unauthenticated' && route.path !== '/login') router.replace('/login')
})
const displayName = computed(() => session.state.user?.username || (preview ? 'preview' : ''))
const displayRole = computed(() => session.state.user?.role || (preview ? 'Design preview' : ''))
const initial = computed(() => (displayName.value[0] || '?').toUpperCase())
async function signOut() {
  if (signingOut.value) return
  signingOut.value = true
  try { await session.logout() } finally { signingOut.value = false }
  router.replace('/login')
}
function toggleTheme() {
  dark.value = !dark.value
  document.documentElement.classList.toggle('dark', dark.value)
}
// The sidebar mirrors the read-only agent data the Overview already loads. The
// Overview broadcasts each result, so the shell never polls the agent twice.
const hostState = ref(null)
const hostLive = computed(() => Boolean(hostState.value?.connected))
const hostName = computed(() => hostState.value?.info?.hostname || (preview ? 'preview node' : 'unavailable'))
const hostOs = computed(() => hostState.value?.info?.os || (preview ? 'Design preview' : 'unavailable'))
const hostRam = computed(() => (hostState.value?.stats ? formatBytes(hostState.value.stats.mem_total_bytes) : '—'))
const hostUptime = computed(() => (hostState.value?.stats ? formatUptime(hostState.value.stats.uptime_seconds) : '—'))
function readHost(event) { hostState.value = event.detail ?? null }
onMounted(() => window.addEventListener('axp:host', readHost))
onUnmounted(() => window.removeEventListener('axp:host', readHost))
const isLogin = computed(() => route.path === '/login')
const nav = [
  { to: '/overview', icon: 'dashboard', label: 'Overview & Metrics' },
  { to: '/websites', icon: 'public', label: 'Websites' },
  { to: '/databases', icon: 'database', label: 'Databases' },
  { to: '/ssl', icon: 'lock', label: 'SSL Certificates' },
  { to: '/files', icon: 'folder_open', label: 'File Manager' },
  { to: '/cron', icon: 'schedule', label: 'Cron Jobs' },
  { to: '/containers', icon: 'deployed_code', label: 'Containers & Deploy' },
  { to: '/security', icon: 'verified_user', label: 'Security & Backups' },
  { to: '/terminal', icon: 'terminal', label: 'Terminal & Logs' },
  { to: '/nodes', icon: 'dns', label: 'Nodes' },
  { to: '/settings', icon: 'settings', label: 'Settings' },
]
</script>
<template>
  <div v-if="!isLogin && mobileOpen" class="fixed inset-0 z-40 lg:hidden" style="background: rgb(0 0 0 / .5)" @click="mobileOpen = false"></div>
  <button v-if="!isLogin" class="ax-btn ax-btn-ghost fixed top-3 left-3 z-[60] lg:hidden" aria-label="Open navigation" @click="mobileOpen = true">
    <span aria-hidden="true" class="material-symbols-outlined text-base">menu</span>
  </button>
  <aside v-if="!isLogin" class="fixed left-0 top-0 h-screen w-72 flex flex-col justify-between border-r z-50 transition-transform lg:translate-x-0"
    :class="mobileOpen ? 'translate-x-0' : '-translate-x-full'"
    style="background: rgb(var(--c-surface-container-low)); border-color: rgb(var(--c-outline-variant) / .3)">
    <div class="flex flex-col flex-1 min-h-0">
      <div class="h-16 px-4 flex items-center justify-between border-b" style="border-color: rgb(var(--c-outline-variant) / .2)">
        <div class="flex items-center gap-2">
          <div class="h-8 w-8 rounded-lg flex items-center justify-center" style="background: rgb(var(--c-surface-container-high))">
            <span aria-hidden="true" class="material-symbols-outlined" style="color: rgb(var(--c-primary))">bolt</span>
          </div>
          <span class="font-headline-md text-headline-md font-bold text-on-surface tracking-tight">Axion<span style="color: rgb(var(--c-primary))">Panel</span></span>
        </div>
        <span class="ax-pill ax-pill-dim">v0.1</span>
      </div>
      <div class="p-3 border-b" style="border-color: rgb(var(--c-outline-variant) / .2)">
        <label class="ax-label block mb-1.5">Target server node</label>
        <button disabled title="Node switching unavailable" class="w-full flex items-center justify-between p-2 rounded-lg text-left" style="background: rgb(var(--c-surface-container))">
          <div class="flex items-center gap-2 overflow-hidden">
            <span class="ax-dot" :class="hostLive ? 'ax-dot-ok' : 'ax-dot-warn'"></span>
            <div class="truncate">
              <p class="ax-mono text-xs text-on-surface truncate">{{ hostName }}</p>
              <p class="ax-mono text-[10px] text-outline truncate">{{ hostLive ? 'Local host · read-only' : 'Host unavailable' }}</p>
            </div>
          </div>
          <span aria-hidden="true" class="material-symbols-outlined text-sm text-outline">unfold_more</span>
        </button>
      </div>
      <nav class="flex-1 overflow-y-auto px-3 py-4 space-y-4">
        <div class="space-y-1">
          <div class="px-2 ax-label">Workspace</div>
          <router-link v-for="item in nav" :key="item.to" :to="item.to" class="flex items-center gap-3 px-3 py-2 rounded-lg text-body-md text-on-surface-variant transition-colors"
            style="background: transparent" active-class="nav-active">
            <span aria-hidden="true" class="material-symbols-outlined text-lg">{{ item.icon }}</span>{{ item.label }}
          </router-link>
          <router-link v-if="preview" to="/login" class="flex items-center gap-3 px-3 py-2 rounded-lg text-body-md text-on-surface-variant" active-class="nav-active">
            <span aria-hidden="true" class="material-symbols-outlined text-lg">login</span>Sign in (preview)
          </router-link>
        </div>
      </nav>
    </div>
    <div class="p-3 border-t" style="border-color: rgb(var(--c-outline-variant) / .2)">
      <div class="p-3 rounded-lg space-y-1.5" style="background: rgb(var(--c-surface-container))">
        <div class="flex items-center justify-between">
          <span class="ax-label">Host specs</span>
          <span class="ax-pill" :class="hostLive ? 'ax-pill-ok' : 'ax-pill-dim'">{{ hostLive ? 'LIVE' : 'UNAVAILABLE' }}</span>
        </div>
        <div class="grid grid-cols-2 gap-x-2 gap-y-1 ax-mono text-[11px] text-on-surface-variant">
          <div>OS: <span class="text-on-surface">{{ hostOs }}</span></div>
          <div class="text-right">vCPU: <span class="text-on-surface">{{ hostState?.metrics?.cpu?.logical_cpus ?? '—' }}</span></div>
          <div>Memory: <span class="text-on-surface">{{ hostRam }}</span></div>
          <div class="text-right">Uptime: <span class="text-on-surface">{{ hostUptime }}</span></div>
        </div>
        <p class="text-[10px] leading-4" style="color: rgb(var(--c-outline))">{{ preview ? 'Design preview · no host reads' : 'Read-only snapshot from Overview' }}</p>
      </div>
    </div>
  </aside>

  <header v-if="!isLogin" class="app-header fixed top-0 right-0 h-16 flex items-center justify-between px-6 z-40 border-b"
    :style="{ left: 0, background: 'rgb(var(--c-surface-container-low) / .85)', borderColor: 'rgb(var(--c-outline-variant) / .3)', backdropFilter: 'blur(12px)' }">
    <div class="flex items-center gap-3 flex-1 max-w-xl">
      <button class="w-full flex items-center justify-between px-3 py-1.5 rounded-lg border text-left" style="background: rgb(var(--c-surface-container)); border-color: rgb(var(--c-outline-variant) / .4)">
        <span class="flex items-center gap-2 text-body-sm text-on-surface-variant">
          <span aria-hidden="true" class="material-symbols-outlined text-base">search</span>Search resources, containers, logs...
        </span>
        <span class="ax-kbd">⌘K</span>
      </button>
    </div>
    <div class="flex items-center gap-3">
      <span v-if="preview" class="ax-pill ax-pill-warn hidden md:inline-flex" title="No server operations are executed in this design preview.">DESIGN PREVIEW</span>
      <span v-else class="ax-pill ax-pill-warn hidden md:inline-flex" title="Sign-in is real. Overview metrics read the local agent; other feature screens and controls are samples.">SAMPLE SCREENS</span>
      <span class="ax-pill hidden lg:inline-flex" :class="hostLive ? 'ax-pill-ok' : 'ax-pill-dim'">Host link: {{ hostLive ? 'live' : 'unavailable' }}</span>
      <button class="ax-btn ax-btn-ghost" title="Toggle theme" @click="toggleTheme">
        <span aria-hidden="true" class="material-symbols-outlined text-base">{{ dark ? 'light_mode' : 'dark_mode' }}</span>{{ dark ? 'Light' : 'Dark' }}
      </button>
      <button disabled class="ax-btn ax-btn-danger" title="Unavailable — no backend action exists"><span aria-hidden="true" class="material-symbols-outlined text-base">power_settings_new</span>Reboot / Power (unavailable)</button>
      <div class="flex items-center gap-2 pl-2">
        <div class="text-right hidden sm:block">
          <p class="text-body-sm font-semibold text-on-surface leading-tight" data-testid="session-username">{{ displayName }}</p>
          <p class="ax-mono text-[10px] text-outline leading-tight" data-testid="session-role">{{ displayRole }}</p>
        </div>
        <div class="w-8 h-8 rounded-full flex items-center justify-center text-xs font-semibold" aria-hidden="true" style="background: rgb(var(--c-primary) / .15); color: rgb(var(--c-primary))">{{ initial }}</div>
      </div>
      <button v-if="!preview" class="ax-btn ax-btn-ghost" :disabled="signingOut" @click="signOut"><span aria-hidden="true" class="material-symbols-outlined text-base">logout</span>{{ signingOut ? 'Signing out…' : 'Sign out' }}</button>
    </div>
  </header>

  <div :class="isLogin ? '' : 'lg:pl-72'">
    <div class="design-banner px-6 py-2 text-[11px] border-b" :style="{ background: 'rgb(var(--c-surface-container-lowest) / .5)', borderColor: 'rgb(var(--c-outline-variant) / .2)', color: 'rgb(var(--c-outline))' }" v-if="!isLogin">
      <template v-if="preview">Design preview — no server operations are executed. All values are example data.</template>
      <template v-else>Live metrics on Overview use read-only values from the local agent. Sample screens and other controls use example data; no host changes are performed.</template>
    </div>
    <router-view @signed-in="$router.push('/overview')" />
  </div>
</template>
