<script setup>
import { ref } from 'vue'
const notice = ref('')
const hosts = ref([
  { name: 'node-01', address: '203.0.113.10', version: '0.0.0-dev', seen: '8s ago', status: 'ok', role: 'Example · this server' },
  { name: 'node-02', address: '203.0.113.11', version: '0.0.0-dev', seen: '21s ago', status: 'ok', role: 'Example' },
  { name: 'node-03', address: '203.0.113.12', version: '0.0.0-dev', seen: '2h ago', status: 'warn', role: 'Example' },
])
function preview(event) {
  event.preventDefault()
  notice.value = 'Preview only — host enrollment is not implemented yet.'
}
</script>
<template>
<main class="w-full pt-16 min-h-screen" style="background: rgb(var(--c-surface))">
  <div v-if="notice" class="preview-notice" role="status">{{ notice }} <button class="ax-btn ax-btn-ghost" @click="notice = ''">Dismiss</button></div>
  <section class="p-6" @submit.prevent @click="preview">
    <div class="page-heading">
      <div>
        <h1 class="text-headline-lg font-headline-lg text-on-surface">Nodes</h1>
        <p class="ax-sub mt-1">Example data · independent managed hosts grouped in one panel. No distributed scheduler or consensus layer is designed for the MVP.</p>
      </div>
      <div class="page-actions">
        <button class="ax-btn ax-btn-ghost"><span aria-hidden="true" class="material-symbols-outlined text-base">refresh</span>Refresh</button>
        <button class="ax-btn ax-btn-primary"><span aria-hidden="true" class="material-symbols-outlined text-base">add</span>Enroll host</button>
      </div>
    </div>
    <div class="ax-card ax-card-pad">
      <div class="ax-hd"><span class="ax-title">Managed hosts</span><span class="ax-pill ax-pill-dim">3 example rows</span></div>
      <div class="table-scroll">
        <table class="ax-table">
          <thead><tr><th>Host</th><th>Address</th><th>Agent</th><th>Last seen</th><th>Role</th><th>State</th><th></th></tr></thead>
          <tbody>
            <tr v-for="host in hosts" :key="host.name">
              <td class="ax-mono text-on-surface">{{ host.name }}</td>
              <td class="ax-mono">{{ host.address }}</td>
              <td class="ax-mono">{{ host.version }}</td>
              <td class="ax-mono">{{ host.seen }}</td>
              <td>{{ host.role }}</td>
              <td><span class="ax-pill" :class="host.status === 'ok' ? 'ax-pill-ok' : 'ax-pill-warn'"><span class="ax-dot" :class="host.status === 'ok' ? 'ax-dot-ok' : 'ax-dot-warn'"></span>{{ host.status === 'ok' ? 'HEALTHY' : 'STALE' }}</span></td>
              <td><button class="ax-btn ax-btn-ghost">Manage</button></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
    <div class="grid-two mt-4">
      <div class="ax-card ax-card-pad">
        <div class="ax-hd"><span class="ax-title">Enrollment</span><span class="ax-pill ax-pill-info">Preview</span></div>
        <p class="ax-sub mb-3">Enrollment tokens are hashed, single-use and expire. Hosts authenticate to the panel with mTLS after enrollment.</p>
        <div class="ax-field"><label class="ax-label">Host address</label><input class="ax-input" placeholder="203.0.113.20"></div>
        <div class="ax-field"><label class="ax-label">One-time token</label><input class="ax-input" placeholder="paste token from host installer" disabled></div>
        <div class="panel-footer"><button class="ax-btn ax-btn-primary">Enroll host</button></div>
      </div>
      <div class="ax-card ax-card-pad">
        <div class="ax-hd"><span class="ax-title">Trust and offboarding</span></div>
        <ul class="text-body-sm text-on-surface-variant space-y-2 list-disc pl-5">
          <li>Agent certificates are issued per host and revocable.</li>
          <li>Offboarding revokes access and removes stored host credentials.</li>
          <li>Operations run per host; there is no cross-host transaction.</li>
        </ul>
      </div>
    </div>
  </section>
</main>
</template>
