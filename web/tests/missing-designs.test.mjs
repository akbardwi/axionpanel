import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
const root = new URL('../src/views/', import.meta.url);
function load(file, names) {
  const source = readFileSync(new URL(file + 'View.vue', root), 'utf8');
  assert.match(source, /<template>/);
  assert.match(source, /Preview only/i);
  assert.doesNotMatch(source, /localStorage|sessionStorage|fetch\(/);
  const code = source.match(/<script setup>([\s\S]*?)<\/script>/)[1].replace(/import .* from 'vue'\n?/, '');
  const context = { ref: value => ({ value }), reactive: value => value, computed: fn => ({ get value() { return fn(); } }), defineEmits: () => (...args) => context.events.push(args), events: [] };
  return vm.runInNewContext(code + '\n;({' + names + '})', context);
}
test('Settings saves tabbed preferences and simulates MFA/sessions', () => {
  const p = load('Settings', 'tab,form,feedback,save,toggles,sessions,revokeSession,mfa,setupMfa');
  assert.equal(p.tab.value, 'general');
  p.save(); assert.match(p.feedback.value, /Preview only/);
  p.tab.value = 'security'; p.setupMfa(); assert.match(p.mfa.value.status, /simulated/i);
  p.revokeSession(p.sessions.value[0]); assert.equal(p.sessions.value.length, 3);
  p.revokeSession(p.sessions.value[1]); assert.equal(p.sessions.value.length, 2);
  p.toggles.digest = !p.toggles.digest; p.save(); assert.match(p.feedback.value, /Preview only/);
});
test('Cron validates schedules, creates examples and simulates run history', () => {
  const p = load('Cron', 'jobs,form,error,createJob,runJob,history,toggleJob');
  p.form.name = 'Example cleanup'; p.form.command = 'echo preview'; p.form.schedule = 'invalid'; p.createJob(); assert.ok(p.error.value);
  p.form.schedule = '0 3 * * *'; p.createJob(); assert.equal(p.jobs.value.length, 3);
  p.runJob(p.jobs.value[2]); assert.match(p.history.value[0].output, /simulated/i);
  p.toggleJob(p.jobs.value[2]); assert.equal(p.jobs.value[2].enabled, false);
});
test('Files navigates only example tree and saves editor in memory', () => {
  const p = load('Files', 'cwd,entries,visible,openEntry,selected,content,saveFile,feedback,query');
  assert.equal(p.visible.value.length, 3);
  p.openEntry(p.entries.value.find(e => e.name === 'public')); assert.equal(p.cwd.value, '/var/www/studio/public');
  p.openEntry(p.visible.value.find(e => e.name === 'index.html')); p.content.value = '<h1>Preview</h1>'; p.saveFile(); assert.match(p.feedback.value, /Preview only/);
  assert.equal(p.selected.value.content, '<h1>Preview</h1>');
  p.query.value = 'not-a-file'; assert.equal(p.visible.value.length, 0);
});
test('SSL issues and imports examples with validation and lifecycle states', () => {
  const p = load('Ssl', 'certs,form,mode,error,submitForm,renew,feedback');
  p.mode.value = 'import'; p.form.name = 'test.example.com'; p.form.certificate = ''; p.submitForm(); assert.ok(p.error.value);
  p.form.certificate = '-----BEGIN CERTIFICATE-----'; p.submitForm(); assert.ok(p.error.value);
  p.form.key = '-----BEGIN PRIVATE KEY----- example only'; p.submitForm(); assert.equal(p.certs.value.length, 3); assert.equal(p.form.key, '');
  p.mode.value = 'issue'; p.form.name = 'wild.example.com'; p.form.hosts = '*.example.com'; p.submitForm(); assert.match(p.error.value, /wildcard/);
  p.mode.value = 'issue'; p.form.name = 'blog.example.com'; p.form.hosts = 'blog.example.com, www.blog.example.com'; p.submitForm(); assert.equal(p.certs.value.length, 4); assert.equal(p.certs.value[3].status, 'Valid');
  p.renew(p.certs.value[3]); assert.equal(p.certs.value[3].status, 'Renewal queued');
});
test('Databases creates databases/users and previews explicit grants', () => {
  const p = load('Databases', 'databases,users,form,error,createResource,tab,grant,saveGrant,feedback');
  p.form.name = 'invalid name'; p.createResource(); assert.ok(p.error.value);
  p.form.name = 'new_db'; p.createResource(); assert.equal(p.databases.value.length, 3);
  p.tab.value = 'users'; p.form.name = 'reader'; p.createResource(); assert.equal(p.users.value.length, 3);
  p.grant.user = 'reader'; p.grant.database = 'new_db'; p.saveGrant(); assert.match(p.feedback.value, /Preview only/);
});
test('Websites validates, creates examples, filters and toggles safely', () => {
  const p = load('Websites', 'sites,form,error,createSite,query,filtered,toggleSite');
  p.form.domain = 'bad domain'; p.createSite(); assert.ok(p.error.value);
  p.form.domain = 'new.example.com'; p.createSite(); assert.equal(p.sites.value.length, 4);
  p.query.value = 'new.example'; assert.equal(p.filtered.value.length, 1);
  p.toggleSite(p.filtered.value[0]); assert.equal(p.filtered.value[0].status, 'Paused');
});
