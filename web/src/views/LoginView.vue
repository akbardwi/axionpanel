<script setup>
import { ref, computed, nextTick } from 'vue'
import { session } from '../auth/session.js'
import { createLoginFlow } from '../auth/loginFlow.js'
import { isDesignPreview } from '../designMode.js'
const emit = defineEmits(['signed-in'])
const preview = isDesignPreview()
const flow = createLoginFlow(session)
const { stage, busy, error, factor, useRecovery, form } = flow
const showPassword = ref(false)
const factorInput = ref(null)
const sessionNotice = computed(() => (!error.value && session.state.error) || '')

async function submitPassword() {
  if (preview) { error.value = 'Sign-in is disabled in design preview builds.'; form.password = ''; return }
  showPassword.value = false
  const done = await flow.submitPassword()
  if (done) return emit('signed-in')
  if (stage.value === 'mfa') { await nextTick(); factorInput.value?.focus() }
}
async function submitMfa() {
  if (await flow.submitMfa()) emit('signed-in')
}
function toggleRecovery() { flow.toggleRecovery(); nextTick(() => factorInput.value?.focus()) }
</script>
<template>
  <main class="w-full pt-16 min-h-screen" style="background: rgb(var(--c-surface))">
    <section class="login-layout"><div class="context"><p class="ax-label">AxionPanel / sign in</p><h1>Sign in</h1><p class="intro">A deliberate entry point.<br>One password. A second factor when enabled.</p><p class="ax-sub">Sign in with your panel account. Your session is held in a secure, HttpOnly cookie set by the panel server.</p><div class="context-details"><div><span aria-hidden="true" class="material-symbols-outlined">lock</span><div><strong>Credentials stay out of the browser</strong><p class="ax-sub">Passwords and codes are cleared after each step and never written to browser storage.</p></div></div><div><span aria-hidden="true" class="material-symbols-outlined">verified_user</span><div><strong>Two-step verification</strong><p class="ax-sub">Accounts with MFA enabled confirm with an authenticator code or a one-time recovery code.</p></div></div></div><span v-if="preview" class="ax-pill ax-pill-warn">Design preview build · sign-in disabled</span></div>
      <section class="ax-card login-panel" aria-labelledby="login-step-title"><div class="step-strip"><span :class="{ current: stage === 'password' }">01 / Password</span><span :class="{ current: stage === 'mfa' }">02 / Verification</span></div><div class="login-content"><p class="ax-label">{{ stage === 'mfa' ? 'Second factor required' : 'Welcome back' }}</p><h2 id="login-step-title" class="ax-title">{{ stage === 'mfa' ? 'Verify your identity' : 'Sign in to AxionPanel' }}</h2>
        <p v-if="sessionNotice" class="notice ax-sub" role="status">{{ sessionNotice }}</p>
        <form v-if="stage !== 'mfa'" :aria-busy="busy" @submit.prevent="submitPassword"><div class="ax-field"><label for="login-username" class="ax-label">Username</label><input id="login-username" v-model="form.username" class="ax-input" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" maxlength="128" :disabled="busy" required></div><div class="ax-field"><label for="login-password" class="ax-label">Password</label><div class="password-field"><input id="login-password" v-model="form.password" class="ax-input" name="password" :type="showPassword ? 'text' : 'password'" autocomplete="current-password" maxlength="1024" :disabled="busy" required><button type="button" class="reveal" :aria-label="showPassword ? 'Hide password' : 'Show password'" @click="showPassword = !showPassword"><span aria-hidden="true" class="material-symbols-outlined">{{ showPassword ? 'visibility_off' : 'visibility' }}</span></button></div></div><p v-if="error" class="error" role="alert">{{ error }}</p><button class="ax-btn ax-btn-primary submit" :disabled="busy">{{ busy ? 'Signing in…' : 'Sign in' }}<span aria-hidden="true" class="material-symbols-outlined">arrow_forward</span></button></form>
        <form v-else :aria-busy="busy" @submit.prevent="submitMfa"><p class="ax-sub">{{ useRecovery ? 'Enter one of your saved recovery codes. Each code works once.' : 'Open your authenticator app and enter the current 6-digit code.' }}</p><div class="ax-field factor"><label for="login-factor" class="ax-label">{{ useRecovery ? 'Recovery code' : 'Authenticator code' }}</label><input v-if="!useRecovery" id="login-factor" ref="factorInput" v-model="factor" class="ax-input code" inputmode="numeric" maxlength="6" autocomplete="one-time-code" :disabled="busy" required><input v-else id="login-factor" ref="factorInput" v-model="factor" class="ax-input" inputmode="text" maxlength="64" autocomplete="off" autocapitalize="none" spellcheck="false" :disabled="busy" required></div><p v-if="error" class="error" role="alert">{{ error }}</p><button class="ax-btn ax-btn-primary submit" :disabled="busy">{{ busy ? 'Verifying…' : 'Verify' }}<span aria-hidden="true" class="material-symbols-outlined">arrow_forward</span></button><div class="mfa-actions"><button type="button" class="ax-btn ax-btn-ghost" :disabled="busy" @click="toggleRecovery">{{ useRecovery ? 'Use authenticator code' : 'Use a recovery code' }}</button><button type="button" class="ax-btn ax-btn-ghost" :disabled="busy" @click="flow.reset()">Back to password</button></div></form>
      </div><footer class="login-footer ax-sub"><span aria-hidden="true" class="material-symbols-outlined">shield</span>Session cookies are HttpOnly · Nothing stored in browser storage</footer></section>
    </section>
  </main>
</template>
<style scoped>
.login-layout{display:grid;grid-template-columns:minmax(0,1fr) 420px;gap:80px;max-width:1040px;margin:0 auto;padding:64px 32px}.context{padding-top:20px}.context h1{font-size:32px;margin:14px 0 28px}.intro{font-size:25px;line-height:1.5;letter-spacing:-.6px;font-weight:600;color:rgb(var(--c-on-surface));margin-bottom:20px}.context>.ax-sub{max-width:380px;font-size:13px;line-height:22px}.context-details{margin:36px 0;display:grid;gap:24px}.context-details>div{display:flex;gap:14px}.context-details strong{font-size:13px}.context-details .material-symbols-outlined{color:rgb(var(--c-primary))}.context-details p{margin:6px 0;max-width:300px}.login-panel{align-self:start;overflow:hidden}.step-strip{display:flex;justify-content:space-between;padding:20px 28px;border-bottom:1px solid rgb(var(--c-outline-variant)/.3);font:10px 'JetBrains Mono',monospace;color:rgb(var(--c-outline))}.current{color:rgb(var(--c-primary))}.login-content{padding:28px}.login-content form{margin-top:28px}.login-content h2{font-size:20px}.password-field{position:relative}.password-field input{padding-right:48px}.reveal{position:absolute;right:0;top:0;height:100%;width:44px;display:grid;place-items:center;background:none;border:0;color:rgb(var(--c-outline));cursor:pointer}.reveal span{font-size:19px}.submit{width:100%;justify-content:space-between;padding:12px 16px}.submit:disabled{opacity:.6;cursor:progress}.factor{margin-top:20px}.mfa-actions{display:flex;flex-wrap:wrap;justify-content:space-between;gap:8px;margin-top:12px}.login-footer{padding:16px 28px;border-top:1px solid rgb(var(--c-outline-variant)/.3);display:flex;align-items:center;gap:8px}.login-footer span{font-size:16px}.notice{margin-top:16px;padding:10px 12px;border-radius:6px;background:rgb(var(--c-surface-container))}.code{font-size:20px;letter-spacing:8px}.error{color:rgb(var(--c-error));font-size:12px}@media(max-width:1000px){.login-layout{grid-template-columns:1fr;gap:28px;max-width:480px;padding:32px 20px}.context{padding:0}.intro,.context-details{display:none}.context h1{margin-bottom:12px}}button:focus-visible{outline:2px solid rgb(var(--c-primary));outline-offset:3px}
</style>
