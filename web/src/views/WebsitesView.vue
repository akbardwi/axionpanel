<script setup>
import { ref, reactive, computed } from 'vue'
const sites = ref([
  { domain: 'studio.example.com', runtime: 'PHP 8.3', root: '/var/www/studio/public', status: 'Active', size: '248 MB' },
  { domain: 'api.example.com', runtime: 'Reverse proxy', root: '127.0.0.1:3000', status: 'Active', size: '—' },
  { domain: 'archive.example.com', runtime: 'Static HTML', root: '/var/www/archive', status: 'Paused', size: '86 MB' }
])
const query = ref(''), drawer = ref(false), selected = ref(sites.value[0]), error = ref(''), feedback = ref('')
const form = reactive({ domain: '', runtime: 'PHP 8.3', root: '/var/www/example/public' })
const filtered = computed(() => sites.value.filter(s => s.domain.includes(query.value.toLowerCase())))
function createSite() {
  const domain = form.domain.trim().toLowerCase()
  if (!/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/.test(domain)) { error.value = 'Enter a valid hostname, for example app.example.com.'; return }
  if (sites.value.some(s => s.domain === domain)) { error.value = 'This example hostname already exists.'; return }
  if (!form.root.trim()) { error.value = 'Enter a document root or upstream address.'; return }
  const site = { ...form, domain, status: 'Active', size: '0 MB' }
  sites.value.push(site); selected.value = site; drawer.value = false; error.value = ''; form.domain = ''; feedback.value = 'Preview only — example website added. No server configuration was changed.'
}
function toggleSite(site) { site.status = site.status === 'Active' ? 'Paused' : 'Active'; feedback.value = 'Preview only — example status changed. No service was restarted.' }
</script>

<template>
  <main class="w-full pt-16 min-h-screen" style="background: rgb(var(--c-surface))">
  <section>
    <header class="page-heading"><div><p class="ax-label">Hosting / example resources</p><h1>Websites</h1><p class="ax-sub">Manage domains, runtimes, and document roots in this design preview.</p></div><button class="ax-btn ax-btn-primary" @click="drawer = true"><span aria-hidden="true" class="material-symbols-outlined">add</span>Create website · Preview only</button></header>
    <p v-if="feedback" class="ax-pill ax-pill-info" role="status">{{ feedback }}</p>
    <div class="website-layout">
      <section class="ax-card"><div class="ax-card-pad ax-hd"><div><h2 class="ax-title">Website inventory</h2><span class="ax-sub">{{ sites.length }} example websites · no live connections</span></div><label><span class="ax-label">Search domain</span><input v-model="query" class="ax-input" placeholder="Filter examples…" type="search"></label></div>
        <div class="table-scroll"><table class="ax-table"><thead><tr><th>Domain / root</th><th>Runtime</th><th>Status</th><th>Storage</th><th></th></tr></thead><tbody><tr v-for="site in filtered" :key="site.domain" :class="{ selected: selected === site }"><td><button class="domain" @click="selected = site">{{ site.domain }}</button><div class="ax-sub ax-mono">{{ site.root }}</div></td><td class="ax-mono">{{ site.runtime }}</td><td><span class="ax-pill" :class="site.status === 'Active' ? 'ax-pill-ok' : 'ax-pill-warn'">{{ site.status }}</span></td><td class="ax-mono">{{ site.size }}</td><td><button class="ax-btn ax-btn-ghost" @click="selected = site">Inspect</button></td></tr><tr v-if="!filtered.length"><td colspan="5"><div class="empty"><span aria-hidden="true" class="material-symbols-outlined">travel_explore</span><p>No matching example websites.</p><button class="ax-btn ax-btn-ghost" @click="query = ''">Clear search</button></div></td></tr></tbody></table></div>
        <footer class="panel-footer ax-sub">Example data · Select a domain to inspect its configuration.</footer>
      </section>
      <aside v-if="selected" class="ax-card ax-card-pad inspector"><p class="ax-label">Website inspector</p><h2 class="ax-title">{{ selected.domain }}</h2><span class="ax-pill ax-pill-info">Example configuration</span><dl><dt>Runtime</dt><dd>{{ selected.runtime }}</dd><dt>Document root / upstream</dt><dd>{{ selected.root }}</dd><dt>Access log</dt><dd>/var/log/nginx/example.access.log</dd><dt>TLS mode</dt><dd>Example certificate · HTTPS redirect</dd></dl><div class="ax-bar"><i style="width:24%;background:rgb(var(--c-primary))"></i></div><p class="ax-sub">Illustrative storage allocation, not measured usage.</p><button class="ax-btn" :class="selected.status === 'Active' ? 'ax-btn-danger' : 'ax-btn-primary'" @click="toggleSite(selected)">{{ selected.status === 'Active' ? 'Pause' : 'Resume' }} example · Preview only</button></aside>
    </div>
    <div v-if="drawer" class="backdrop" @click.self="drawer = false" @keydown.esc="drawer = false"><section class="drawer ax-card ax-card-pad" role="dialog" aria-modal="true" aria-labelledby="website-form-title"><div class="ax-hd"><div><p class="ax-label">Preview only</p><h2 id="website-form-title" class="ax-title">Create example website</h2></div><button class="ax-btn ax-btn-ghost" aria-label="Close website form" @click="drawer = false">×</button></div><p class="ax-sub">This adds a row to the prototype. DNS, files, and nginx remain untouched.</p><form @submit.prevent="createSite"><div class="ax-field"><label for="site-domain" class="ax-label">Domain</label><input id="site-domain" v-model="form.domain" autofocus class="ax-input" placeholder="app.example.com" required></div><div class="ax-field"><label for="site-runtime" class="ax-label">Runtime</label><select id="site-runtime" v-model="form.runtime" class="ax-select"><option>PHP 8.3</option><option>Static HTML</option><option>Reverse proxy</option></select></div><div class="ax-field"><label for="site-root" class="ax-label">Document root / upstream</label><input id="site-root" v-model="form.root" class="ax-input" required></div><p v-if="error" class="ax-pill ax-pill-err" role="alert">{{ error }}</p><div class="panel-footer"><button type="button" class="ax-btn ax-btn-ghost" @click="drawer = false">Cancel</button><button class="ax-btn ax-btn-primary">Add example · Preview only</button></div></form></section></div>
  </section>
  </main>
</template>

<style scoped>
.website-layout{display:grid;grid-template-columns:minmax(0,1fr) 290px;gap:20px}.domain{background:none;border:0;padding:0;color:rgb(var(--c-primary));font:600 13px 'Plus Jakarta Sans',sans-serif;cursor:pointer;text-align:left}.selected td{background:rgb(var(--c-primary)/.04)}.inspector h2{overflow-wrap:anywhere}.inspector dl{margin:24px 0}.inspector dt{font-size:11px;color:rgb(var(--c-outline));margin-top:18px}.inspector dd{font:12px 'JetBrains Mono',monospace;margin:6px 0;overflow-wrap:anywhere}.empty{text-align:center;padding:36px}.backdrop{position:fixed;inset:0;background:rgb(0 0 0/.55);z-index:60;display:flex;justify-content:flex-end}.drawer{width:min(460px,100%);height:100%;box-sizing:border-box;overflow:auto;border-radius:0}.drawer form{margin-top:30px}.ax-hd label{max-width:210px}.ax-pill[role=status]{margin-bottom:16px;white-space:normal}@media(max-width:1100px){.website-layout{grid-template-columns:1fr}.inspector dl{display:grid;grid-template-columns:1fr 2fr;gap:12px}.inspector dt,.inspector dd{margin:0}}@media(max-width:600px){.ax-hd{align-items:stretch;flex-direction:column}.ax-hd label{max-width:none}}button:focus-visible{outline:2px solid rgb(var(--c-primary));outline-offset:3px}
</style>
