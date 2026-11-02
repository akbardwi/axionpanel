<script setup>
import { ref, reactive, computed } from 'vue'
const tab = ref('databases'), query = ref(''), error = ref(''), feedback = ref('')
const databases = ref([{ name: 'studio_db', engine: 'MariaDB 11', size: '42 MB', owner: 'studio_app' }, { name: 'analytics', engine: 'PostgreSQL 16', size: '128 MB', owner: 'report_reader' }])
const users = ref([{ name: 'studio_app', host: 'localhost', grants: 'studio_db · Read / write' }, { name: 'report_reader', host: 'localhost', grants: 'analytics · Read only' }])
const form = reactive({ name: '', engine: 'MariaDB 11' })
const grant = reactive({ user: 'studio_app', database: 'studio_db', access: 'Read only' })
const filtered = computed(() => (tab.value === 'databases' ? databases.value : users.value).filter(x => x.name.includes(query.value.toLowerCase())))
function createResource() {
  const name = form.name.trim()
  if (!/^[a-z][a-z0-9_]{1,31}$/.test(name)) { error.value = 'Use 2–32 lowercase letters, numbers, or underscores; start with a letter.'; return }
  const list = tab.value === 'databases' ? databases.value : users.value
  if (list.some(x => x.name === name)) { error.value = 'That example name is already in use.'; return }
  list.push(tab.value === 'databases' ? { name, engine: form.engine, size: '0 MB', owner: 'Unassigned' } : { name, host: 'localhost', grants: 'No grants' })
  form.name = ''; error.value = ''; feedback.value = 'Preview only — example added in memory. No SQL was executed.'
}
function saveGrant() {
  const user = users.value.find(u => u.name === grant.user)
  if (!user || !databases.value.some(d => d.name === grant.database)) { error.value = 'Choose an existing example user and database.'; return }
  user.grants = grant.database + ' · ' + grant.access; error.value = ''; feedback.value = 'Preview only — example grants updated. No database privileges were changed.'
}
</script>
<template>
  <main class="w-full pt-16 min-h-screen" style="background: rgb(var(--c-surface))">
  <section><header class="page-heading"><div><p class="ax-label">Data services / example resources</p><h1>Databases</h1><p class="ax-sub">Explore schemas, isolated users, and explicit access grants.</p></div><span class="ax-pill ax-pill-info">Preview only · no SQL connection</span></header>
    <p v-if="feedback" class="notice ax-pill ax-pill-info" role="status">{{ feedback }}</p>
    <div class="db-layout"><section class="ax-card"><div class="ax-card-pad"><div class="ax-hd"><div class="tabs" role="tablist" aria-label="Database resources"><button v-for="name in ['databases', 'users']" :key="name" class="ax-btn" :class="tab === name ? 'ax-btn-primary' : 'ax-btn-ghost'" role="tab" :aria-selected="tab === name" @click="tab = name; query = ''; error = ''">{{ name === 'databases' ? 'Databases' : 'Users' }} <span class="ax-mono">{{ name === 'databases' ? databases.length : users.length }}</span></button></div><label><span class="ax-label">Search examples</span><input v-model="query" type="search" class="ax-input" placeholder="Filter by name"></label></div><p class="ax-sub">Example data only · Users are restricted to localhost. No passwords are collected in this prototype.</p></div>
      <div class="table-scroll"><table class="ax-table"><thead><tr><th>{{ tab === 'databases' ? 'Database' : 'User' }}</th><th>{{ tab === 'databases' ? 'Engine' : 'Host' }}</th><th>{{ tab === 'databases' ? 'Size' : 'Grants' }}</th><th v-if="tab === 'databases'">Owner</th></tr></thead><tbody><tr v-for="row in filtered" :key="row.name"><td><span class="resource ax-mono"><span aria-hidden="true" class="material-symbols-outlined">{{ tab === 'databases' ? 'database' : 'person' }}</span>{{ row.name }}</span></td><td class="ax-mono">{{ row.engine || row.host }}</td><td class="ax-mono">{{ row.size || row.grants }}</td><td v-if="tab === 'databases'"><span class="ax-pill ax-pill-dim">{{ row.owner }}</span></td></tr><tr v-if="!filtered.length"><td :colspan="tab === 'databases' ? 4 : 3" class="empty">No matching examples. <button class="ax-btn ax-btn-ghost" @click="query = ''">Clear search</button></td></tr></tbody></table></div>
      <div class="ax-card-pad"><p class="ax-label">Least privilege by default</p><p class="ax-sub">New example users start with no grants. Assign access to one database using the panel below.</p></div>
      <form class="grant-form" @submit.prevent="saveGrant"><h2 class="ax-title">Access grants</h2><div class="form-grid"><div class="ax-field"><label for="grant-user" class="ax-label">Example user</label><select id="grant-user" v-model="grant.user" class="ax-select"><option v-for="user in users" :key="user.name">{{ user.name }}</option></select></div><div class="ax-field"><label for="grant-db" class="ax-label">Database</label><select id="grant-db" v-model="grant.database" class="ax-select"><option v-for="db in databases" :key="db.name">{{ db.name }}</option></select></div><div class="ax-field"><label for="grant-access" class="ax-label">Privilege set</label><select id="grant-access" v-model="grant.access" class="ax-select"><option>Read only</option><option>Read / write</option><option>No access</option></select></div></div><button class="ax-btn ax-btn-ghost">Apply example grants · Preview only</button></form>
    </section>
    <aside class="ax-card ax-card-pad"><p class="ax-label">Create / {{ tab }}</p><h2 class="ax-title">New example {{ tab === 'databases' ? 'database' : 'user' }}</h2><form @submit.prevent="createResource"><div class="ax-field"><label for="db-name" class="ax-label">Name</label><input id="db-name" v-model="form.name" class="ax-input" :placeholder="tab === 'databases' ? 'app_database' : 'app_reader'" required></div><div v-if="tab === 'databases'" class="ax-field"><label for="db-engine" class="ax-label">Engine</label><select id="db-engine" v-model="form.engine" class="ax-select"><option>MariaDB 11</option><option>PostgreSQL 16</option></select></div><p v-else class="ax-sub">Host: localhost. Authentication setup is intentionally omitted; never enter real credentials here.</p><p v-if="error" class="error" role="alert">{{ error }}</p><button class="ax-btn ax-btn-primary">Create example · Preview only</button></form><div class="ax-divider"></div><span class="ax-pill ax-pill-warn">Design sandbox</span><p class="ax-sub">No engine is installed, no account is created, and nothing survives a reload.</p></aside></div>
  </section>
  </main>
</template>
<style scoped>
.db-layout{display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:20px}.tabs,.resource{display:flex;align-items:center;gap:8px}.resource{color:rgb(var(--c-primary))}.resource .material-symbols-outlined{font-size:19px}.grant-form{padding:20px;border-top:1px solid rgb(var(--c-outline-variant)/.3)}.grant-form h2{margin-top:0}aside form{margin-top:24px}.error{color:rgb(var(--c-error));font-size:12px}.notice{margin-bottom:16px;white-space:normal}.empty{padding:36px;text-align:center}@media(max-width:1050px){.db-layout{grid-template-columns:1fr}.ax-hd{flex-wrap:wrap}}button:focus-visible{outline:2px solid rgb(var(--c-primary));outline-offset:3px}
</style>
