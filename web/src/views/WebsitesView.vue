<script setup>
import { computed, inject, onMounted, reactive, ref } from 'vue'
import { session } from '../auth/session.js'
import { isDesignPreview } from '../designMode.js'
import { createSitesClient } from '../lib/sitesClient.js'
import { createSitesWorkflow, siteStatus } from '../lib/sitesWorkflow.js'

const preview = isDesignPreview()
const injected = inject('sitesWorkflow', null)
const workflow = injected || createSitesWorkflow({
  client: createSitesClient({ getCSRF: () => session.state.csrfToken, onUnauthorized: () => session.check() }),
  isAdmin: () => !preview && session.state.user?.role === 'admin',
})
const state = workflow.state
const selectedId = ref(null)
const credentials = reactive({ password: '', factor: '', recovery: false })
const filtered = computed(() => state.sites.filter(site => site.domain.includes(state.query.trim().toLowerCase())))
const selected = computed(() => state.sites.find(site => site.id === selectedId.value))
const createDisabled = computed(() => preview || !workflow.canCreate() || state.planning)
const removalDisabled = computed(() => preview || !workflow.canRemove(state.removal) || state.confirmDomain !== state.removal?.domain)

async function verify() {
  // Credentials are used only by the existing sudo endpoint, never persisted or
  // reused for the mutation. The operator must explicitly submit again.
  const payload = { password: credentials.password }
  if (credentials.factor) payload[credentials.recovery ? 'recovery_code' : 'code'] = credentials.factor
  credentials.password = ''
  credentials.factor = ''
  try {
    const verified = await workflow.reauthenticate(payload)
    if (verified) {
      await session.check()
      state.confirmDomain = ''
    }
  } finally {
    delete payload.password
    delete payload.code
    delete payload.recovery_code
  }
}

onMounted(() => {
  if (preview) {
    state.loading = false
    state.capability = 'unsupported'
    return
  }
  workflow.load()
})
</script>

<template>
  <main class="w-full pt-16 min-h-screen" style="background: rgb(var(--c-surface))">
    <section>
      <header class="page-heading">
        <div><p class="ax-label">Hosting / local server</p><h1>Websites</h1><p class="ax-sub">Manage static website vhosts. The agent determines paths and the listener; DNS is managed separately.</p></div>
        <button class="ax-btn" :disabled="preview || state.loading || !!state.busy" @click="workflow.load()">Refresh inventory</button>
      </header>

      <p v-if="preview" class="notice ax-pill-warn" role="status">Website operations are unavailable in design preview. No inventory was fetched and no host changes can be made.</p>
      <p v-else-if="state.capability === 'loading'" class="notice" role="status">Checking the agent operation catalog…</p>
      <p v-else-if="state.capability === 'unsupported'" class="notice ax-pill-warn" role="status"><strong>Create unavailable.</strong> The agent has not registered site.plan. Website operations are opt-in and disabled by default. Existing panel inventory remains visible; an administrator must configure the agent before creation is available.</p>
      <p v-else-if="state.capability === 'unavailable'" class="notice ax-pill-warn" role="status"><strong>Create unavailable.</strong> Cannot verify the agent's website capabilities ({{ state.agentReason || 'unavailable' }}). Inventory is independent of the agent.</p>
      <p v-else-if="!workflow.supports('site.apply')" class="notice ax-pill-warn" role="status">Create unavailable: site.apply is not registered by the agent. Plans are read-only.</p>
      <p v-if="!injected && !preview && session.state.user?.role !== 'admin'" class="notice" role="status">Administrator access is required to create or remove websites.</p>
      <p v-if="state.inventoryError" class="notice ax-pill-err" role="alert">Inventory could not be refreshed: {{ state.inventoryError }} <span v-if="state.sites.length">Previously loaded rows may be stale.</span></p>
      <p v-if="state.error" class="notice ax-pill-err" role="alert">{{ state.error }}</p>
      <p v-if="state.reconciliation" class="notice ax-pill-warn" role="alert"><strong>Manual reconciliation required.</strong> The host may have changed. Inspect the durable job and host configuration before any retry. This screen does not replay unfinished operations.</p>
      <p v-if="state.notice" class="notice ax-pill-info" role="status">{{ state.notice }}</p>
      <p v-if="state.busy === 'create' || state.busy === 'remove'" class="notice" role="status" aria-live="polite">Waiting for the synchronous host job (up to 90 seconds). Do not resubmit or navigate away until the result is known.</p>

      <section v-if="state.result" class="ax-card ax-card-pad job-result" aria-labelledby="website-job-title" aria-live="polite">
        <h2 id="website-job-title" class="ax-title">Last job result</h2>
        <p><span class="ax-pill" :class="state.result.success ? 'ax-pill-ok' : 'ax-pill-err'">{{ state.result.job.status }}</span> <span class="ax-mono">{{ state.result.job.id }}</span></p>
        <p class="ax-sub">Domain: {{ state.result.site.domain }} · synchronous execution</p>
        <p v-if="state.result.job.error" class="ax-mono">{{ state.result.job.error }}</p>
        <p v-if="state.result.retainedContent">Site content was retained at {{ state.result.site.root }}. Removal does not delete files.</p>
      </section>

      <section v-if="state.needsSudo" class="ax-card ax-card-pad verification" aria-labelledby="website-verify-title">
        <h2 id="website-verify-title" class="ax-title">Verify administrator session</h2>
        <p class="ax-sub">Uses the panel's existing sudo verification. Submit credentials only here in the panel. Verification never automatically retries a website operation.</p>
        <form @submit.prevent="verify">
          <div class="ax-field"><label for="site-sudo-password" class="ax-label">Current password</label><input id="site-sudo-password" v-model="credentials.password" class="ax-input" type="password" autocomplete="current-password" required :disabled="!!state.busy"></div>
          <div class="ax-field"><label for="site-sudo-factor" class="ax-label">{{ credentials.recovery ? 'Recovery code' : 'Authenticator code' }} (if configured)</label><input id="site-sudo-factor" v-model="credentials.factor" class="ax-input" autocomplete="one-time-code" :type="credentials.recovery ? 'password' : 'text'" :inputmode="credentials.recovery ? 'text' : 'numeric'" :disabled="!!state.busy"></div>
          <label class="recovery-option"><input v-model="credentials.recovery" type="checkbox" :disabled="!!state.busy" @change="credentials.factor = ''"> Use a recovery code instead</label>
          <button class="ax-btn ax-btn-primary" :disabled="preview || !!state.busy">{{ state.busy === 'reauth' ? 'Verifying…' : 'Verify session' }}</button>
        </form>
      </section>

      <div class="website-layout">
        <section class="ax-card inventory" :aria-busy="state.loading">
          <div class="ax-card-pad ax-hd"><div><h2 class="ax-title">Website inventory</h2><p class="ax-sub">{{ state.sites.length }} recorded static websites · local server</p></div><label><span class="ax-label">Search domain</span><input v-model="state.query" class="ax-input" type="search" placeholder="Filter domains…"></label></div>
          <p v-if="state.loading" class="empty" role="status">Loading website inventory…</p>
          <div v-if="state.sites.length" class="table-scroll"><table class="ax-table"><thead><tr><th>Domain / document root</th><th>Listen</th><th>Status</th><th>Actions</th></tr></thead><tbody>
            <tr v-for="site in filtered" :key="site.id">
              <td><button class="domain" @click="selectedId = site.id">{{ site.domain }}</button><div class="ax-sub ax-mono path">{{ site.root || 'Not recorded' }}</div></td>
              <td class="ax-mono">{{ site.listen || 'Not recorded' }}</td>
              <td><span class="ax-pill" :class="'ax-pill-' + siteStatus(site).tone">{{ siteStatus(site).label }}</span><p v-if="siteStatus(site).notice" class="ax-sub status-notice">{{ siteStatus(site).notice }}</p></td>
              <td><button class="ax-btn ax-btn-ghost" @click="selectedId = site.id">Inspect</button><button class="ax-btn ax-btn-danger" :disabled="preview || !workflow.canRemove(site)" @click="workflow.selectRemoval(site)">Remove</button></td>
            </tr>
            <tr v-if="!filtered.length"><td colspan="4" class="empty">No matching websites. <button class="ax-btn ax-btn-ghost" @click="state.query = ''">Clear search</button></td></tr>
          </tbody></table></div>
          <div v-else-if="!state.loading && !state.inventoryError" class="empty"><h3>No websites yet</h3><p class="ax-sub">No static websites are recorded in the panel. Review a plan to create one.</p></div>
          <footer class="panel-footer ax-sub">Panel records only — status is the last recorded operation, not a live reachability check.</footer>
          <div v-if="selected" class="ax-card-pad inspector"><h3 class="ax-title">{{ selected.domain }}</h3><dl><dt>Kind</dt><dd>Static</dd><dt>Document root</dt><dd>{{ selected.root || 'Not recorded' }}</dd><dt>Listener</dt><dd>{{ selected.listen || 'Not recorded' }}</dd><dt>Last error</dt><dd>{{ selected.last_error || 'None recorded' }}</dd><dt>Content retained</dt><dd>{{ selected.retained_content ? 'Yes' : 'Not a completed removal' }}</dd></dl><p v-if="workflow.needsReconciliation(selected)" class="notice ax-pill-warn" role="alert">Manual reconciliation required. Inspect unfinished work before retrying.</p></div>
        </section>

        <section class="ax-card ax-card-pad creation" aria-labelledby="website-create-title">
          <p class="ax-label">Static website</p><h2 id="website-create-title" class="ax-title">Plan before creating</h2>
          <p class="ax-sub">The read-only plan does not change the host. Review it, then explicitly create the website. Paths and listener cannot be overridden.</p>
          <form @submit.prevent="workflow.makePlan()">
            <div class="ax-field"><label for="site-domain" class="ax-label">Domain</label><input id="site-domain" class="ax-input" :value="state.domain" @input="workflow.setDomain($event.target.value)" autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="app.example.com" required :disabled="preview || !!state.busy"></div>
            <button class="ax-btn" :disabled="preview || state.planning || !workflow.canPlan()">{{ state.planning ? 'Planning…' : 'Review plan' }}</button>
          </form>
          <div v-if="state.plan" class="plan">
            <h3 class="ax-title">Review plan</h3><p class="ax-sub">Host configuration has not changed by this plan.</p>
            <dl><dt>Domain</dt><dd>{{ state.plan.domain }}</dd><dt>Document root</dt><dd>{{ state.plan.root }}</dd><dt>Vhost</dt><dd>{{ state.plan.vhost }}</dd><dt>Listen</dt><dd>{{ state.plan.listen }}</dd><dt>Would do</dt><dd>{{ state.plan.would_do }}</dd><dt>Already applied</dt><dd>{{ state.plan.applied ? 'Yes' : 'No' }}</dd></dl>
            <p class="ax-sub">Creation configures a static vhost and its managed document root. It does not configure DNS. No content directory is silently adopted.</p>
          </div>
          <button class="ax-btn ax-btn-primary create-action" :disabled="createDisabled" @click="workflow.create()">Create website</button>
          <p class="ax-sub">Requires a current plan, administrator access, registered site.apply, and recent sudo verification.</p>
        </section>
      </div>

      <section v-if="state.removal" class="ax-card ax-card-pad removal" aria-labelledby="website-remove-title">
        <h2 id="website-remove-title" class="ax-title">Remove {{ state.removal.domain }}</h2>
        <p>Only the managed vhost will be removed. Site content is retained at <span class="ax-mono">{{ state.removal.root || 'its document root' }}</span>. Removing a vhost is not deleting content. A retained directory is not silently re-adopted by a later create.</p>
        <form @submit.prevent="workflow.remove()"><div class="ax-field"><label for="site-confirm-domain" class="ax-label">Type the exact domain: {{ state.removal.domain }}</label><input id="site-confirm-domain" v-model="state.confirmDomain" class="ax-input" autocomplete="off" autocapitalize="none" spellcheck="false" :disabled="!!state.busy" required></div><div class="actions"><button type="button" class="ax-btn ax-btn-ghost" :disabled="!!state.busy" @click="workflow.selectRemoval(null)">Cancel removal</button><button class="ax-btn ax-btn-danger" :disabled="removalDisabled">Remove vhost</button></div></form>
      </section>
    </section>
  </main>
</template>

<style scoped>
.website-layout{display:grid;grid-template-columns:minmax(0,1fr) minmax(280px,350px);gap:20px;align-items:start}.notice{padding:14px 18px;border:1px solid rgb(var(--c-outline-variant)/.3);border-radius:8px;margin:0 0 16px;line-height:1.6;overflow-wrap:anywhere}.job-result,.verification,.removal{margin-bottom:20px}.removal{margin-top:20px}.job-result p{margin-top:12px}.creation .ax-sub{line-height:1.6;margin:12px 0}.domain{background:none;border:0;padding:0;color:rgb(var(--c-primary));font:600 13px 'Plus Jakarta Sans',sans-serif;cursor:pointer;text-align:left}.path{max-width:300px;overflow-wrap:anywhere}.status-notice{max-width:260px;white-space:normal;margin-top:8px}.empty{text-align:center;padding:30px}.empty h3{font-weight:600;margin-bottom:8px}.inspector{border-top:1px solid rgb(var(--c-outline-variant)/.2)}dl{margin:16px 0;display:grid;grid-template-columns:minmax(90px,1fr) minmax(0,2fr);gap:12px}dt{font-size:11px;color:rgb(var(--c-outline))}dd{font:12px 'JetBrains Mono',monospace;margin:0;overflow-wrap:anywhere}.plan{margin-top:24px;border-top:1px solid rgb(var(--c-outline-variant)/.2);padding-top:20px}.create-action{margin-top:20px}.actions{display:flex;gap:10px;flex-wrap:wrap}.recovery-option{display:flex;gap:8px;align-items:center;margin-bottom:18px;font-size:12px}.verification form,.removal form{max-width:480px;margin-top:18px}.ax-hd label{max-width:210px}.table-scroll{overflow-x:auto}button:disabled{opacity:.45;cursor:not-allowed}button:focus-visible,input:focus-visible{outline:2px solid rgb(var(--c-primary));outline-offset:3px}@media(max-width:1250px){.website-layout{grid-template-columns:1fr}}@media(max-width:600px){.ax-hd{align-items:stretch;flex-direction:column}.ax-hd label{max-width:none}dl{grid-template-columns:1fr}.notice{padding:12px}.page-heading{gap:16px;flex-wrap:wrap}}
</style>
