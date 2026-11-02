<script setup>
import { ref, reactive, computed } from 'vue'
const mode = ref('issue'), error = ref(''), feedback = ref(''), filter = ref('all')
const certs = ref([
  { name: 'studio.example.com', issuer: "Let's Encrypt · example", hosts: 'studio.example.com', expires: '2026-05-14', days: 72, status: 'Valid', type: 'HTTP-01' },
  { name: 'api.example.com', issuer: "Let's Encrypt · example", hosts: 'api.example.com', expires: '2026-03-08', days: 5, status: 'Expiring', type: 'HTTP-01' }
])
const form = reactive({ name: '', hosts: '', email: 'admin@example.com', certificate: '', key: '' })
const rows = computed(() => filter.value === 'all' ? certs.value : certs.value.filter(c => c.status === filter.value))
function issueCert() {
  const name = form.name.trim().toLowerCase()
  const hosts = form.hosts.split(',').map(h => h.trim().toLowerCase()).filter(Boolean)
  if (!/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/.test(name)) { error.value = 'Enter a valid primary hostname.'; return }
  if (hosts.some(h => h.includes('*'))) { error.value = 'HTTP-01 cannot issue wildcard names. List concrete hostnames only.'; return }
  if (!hosts.includes(name)) { error.value = 'The primary hostname must be included in the SAN list.'; return }
  if (certs.value.some(c => c.name === name)) { error.value = 'An example certificate already covers this name.'; return }
  certs.value.push({ name, issuer: "Let's Encrypt · example", hosts: hosts.join(', '), expires: '2026-08-01', days: 91, status: 'Valid', type: 'HTTP-01' })
  reset('Preview only — example certificate issued. No ACME request was sent.')
}
function importCert() {
  const name = form.name.trim().toLowerCase()
  if (!name) { error.value = 'Name this certificate so it can be listed.'; return }
  if (!form.certificate.trim()) { error.value = 'Paste a PEM certificate to continue the preview.'; return }
  if (!form.key.trim()) { error.value = 'Paste a PEM private key placeholder (never use a real key here).' ; return }
  certs.value.push({ name, issuer: 'Imported · example', hosts: name, expires: '2026-06-20', days: 110, status: 'Valid', type: 'Imported' })
  reset('Preview only — example certificate imported. No key material was stored.')
}
function submitForm() { mode.value === 'issue' ? issueCert() : importCert() }
function reset(message) { form.name = ''; form.hosts = ''; form.certificate = ''; form.key = ''; error.value = ''; feedback.value = message }
function renew(cert) { cert.status = 'Renewal queued'; feedback.value = 'Preview only — renewal queued in this prototype. No ACME order was placed.' }
</script>
<template>
  <main class="w-full pt-16 min-h-screen" style="background: rgb(var(--c-surface))">
  <section><header class="page-heading"><div><p class="ax-label">Transport security / examples</p><h1>SSL Certificates</h1><p class="ax-sub">Track expiration and prototype certificate issuance with HTTP-01.</p></div><div class="page-actions"><select v-model="filter" class="ax-select auto" aria-label="Filter certificate status"><option value="all">All statuses</option><option>Valid</option><option>Expiring</option><option>Renewal queued</option></select></div></header>
    <p v-if="feedback" class="notice ax-pill ax-pill-info" role="status">{{ feedback }}</p>
    <div class="ssl-layout">
      <section class="ax-card"><div class="ax-card-pad ax-hd"><div><h2 class="ax-title">Expiration watch</h2><span class="ax-sub">Example data · dates are illustrative, not live certificate state.</span></div><span class="ax-pill ax-pill-warn"><span aria-hidden="true" class="material-symbols-outlined">schedule</span>1 expiring soon</span></div>
        <div class="table-scroll"><table class="ax-table"><thead><tr><th>Certificate</th><th>SAN hosts</th><th>Expires</th><th>Lifetime</th><th>Status</th><th></th></tr></thead><tbody><tr v-for="cert in rows" :key="cert.name"><td><div class="host ax-mono">{{ cert.name }}</div><div class="ax-sub ax-mono">{{ cert.issuer }}</div></td><td class="ax-mono">{{ cert.hosts }}</td><td class="ax-mono">{{ cert.expires }}</td><td><div class="days"><div class="ax-bar"><i :style="{ width: Math.min(100, cert.days / 0.91) + '%', background: cert.days < 14 ? 'rgb(var(--c-tertiary))' : 'rgb(var(--c-secondary))' }"></i></div><span class="ax-sub ax-mono">{{ cert.days }} days</span></div></td><td><span class="ax-pill" :class="cert.status === 'Valid' ? 'ax-pill-ok' : cert.status === 'Expiring' ? 'ax-pill-warn' : 'ax-pill-info'">{{ cert.status }}</span></td><td><button class="ax-btn ax-btn-ghost" :disabled="cert.status === 'Renewal queued'" @click="renew(cert)">Renew · Preview</button></td></tr><tr v-if="!rows.length"><td colspan="6"><div class="empty"><span aria-hidden="true" class="material-symbols-outlined">verified_user</span><p>No certificates match this filter.</p><button class="ax-btn ax-btn-ghost" @click="filter = 'all'">Show all</button></div></td></tr></tbody></table></div>
        <footer class="panel-footer ax-sub">Renewal and issuance are design previews only — no ACME or filesystem access.</footer>
      </section>
      <aside class="ax-card ax-card-pad"><div class="mode" role="tablist" aria-label="Certificate workflow"><button class="ax-btn" :class="mode === 'issue' ? 'ax-btn-primary' : 'ax-btn-ghost'" role="tab" :aria-selected="mode === 'issue'" @click="mode = 'issue'; error = ''">Issue new</button><button class="ax-btn" :class="mode === 'import' ? 'ax-btn-primary' : 'ax-btn-ghost'" role="tab" :aria-selected="mode === 'import'" @click="mode = 'import'; error = ''">Import PEM</button></div>
        <form @submit.prevent="submitForm"><div class="ax-field"><label for="cert-name" class="ax-label">Primary hostname</label><input id="cert-name" v-model="form.name" class="ax-input" placeholder="app.example.com" required></div>
          <template v-if="mode === 'issue'"><div class="ax-field"><label for="cert-hosts" class="ax-label">SAN hostnames (comma separated)</label><input id="cert-hosts" v-model="form.hosts" class="ax-input" placeholder="app.example.com, www.app.example.com"></div><div class="ax-field"><label for="cert-email" class="ax-label">ACME account email</label><input id="cert-email" v-model="form.email" type="email" class="ax-input"></div><p class="hint"><span aria-hidden="true" class="material-symbols-outlined">info</span>HTTP-01 challenge only · wildcards are intentionally unsupported.</p></template>
          <template v-else><div class="ax-field"><label for="cert-pem" class="ax-label">Certificate PEM</label><textarea id="cert-pem" v-model="form.certificate" class="ax-textarea" rows="4" placeholder="-----BEGIN CERTIFICATE----- (example paste)"></textarea></div><div class="ax-field"><label for="cert-key" class="ax-label">Private key PEM</label><textarea id="cert-key" v-model="form.key" class="ax-textarea" rows="3" placeholder="-----BEGIN PRIVATE KEY----- (placeholder only)"></textarea></div><p class="hint"><span aria-hidden="true" class="material-symbols-outlined">warning</span>Never paste a real private key into a design prototype.</p></template>
          <p v-if="error" class="error" role="alert">{{ error }}</p><button class="ax-btn ax-btn-primary">{{ mode === 'issue' ? 'Issue example certificate' : 'Import example certificate' }} · Preview only</button>
        </form><div class="ax-divider"></div><p class="ax-label">Challenge flow (HTTP-01)</p><ol class="flow"><li>Panel requests a certificate from the ACME server.</li><li>A token file is exposed at <span class="ax-mono">/.well-known/acme-challenge/</span>.</li><li>The CA validates port 80 over plain HTTP.</li><li>Certificate and key are installed on the matching vhost.</li></ol><p class="ax-sub">Steps shown for design review; this prototype performs none of them.</p>
      </aside>
    </div>
  </section>
  </main>
</template>
<style scoped>
.ssl-layout{display:grid;grid-template-columns:minmax(0,1fr) 330px;gap:20px}.days{display:flex;align-items:center;gap:8px}.days .ax-bar{max-width:80px}.host{color:rgb(var(--c-primary));font-weight:600}.mode{display:flex;gap:8px;margin-bottom:20px}aside form{margin-bottom:8px}.hint{display:flex;gap:6px;align-items:flex-start;font-size:11px;line-height:16px;color:rgb(var(--c-on-surface-variant));margin:12px 0}.hint .material-symbols-outlined{font-size:15px;color:rgb(var(--c-tertiary))}.error{color:rgb(var(--c-error));font-size:12px;margin:10px 0}.flow{margin:8px 0;padding-left:20px;font-size:12px;line-height:19px;color:rgb(var(--c-on-surface-variant))}.flow li{margin:5px 0}.flow .ax-mono{color:rgb(var(--c-primary))}.empty{text-align:center;padding:36px}.notice{margin-bottom:16px;white-space:normal}.ax-select.auto{width:auto}@media(max-width:1100px){.ssl-layout{grid-template-columns:1fr}}button:focus-visible{outline:2px solid rgb(var(--c-primary));outline-offset:3px}
</style>
