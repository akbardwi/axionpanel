<script setup>
import { ref } from 'vue'
const notice = ref('')
function previewAction(event) {
  const target = event.target.closest('button, a, input[type=checkbox]')
  if (!target) return
  event.preventDefault()
  notice.value = 'Preview only — no command was sent to a server.'
}
</script>
<template>
<section @click="previewAction" @submit.prevent>
<div v-if="notice" class="preview-notice" role="status">{{ notice }} <button class="ax-btn ax-btn-ghost" @click.stop="notice = ''">Dismiss</button></div>
<main v-pre class="w-full pt-16 bg-surface min-h-screen"><div class="flex flex-col w-full">
<!-- Sub-header Breadcrumb and Real-time Status Strip -->
<div class="px-gutter-lg py-space-md bg-surface-container-low flex flex-wrap items-center justify-between gap-space-md">
<div class="flex items-center gap-space-sm min-w-0">
<span class="font-code-sm text-code-sm text-outline font-mono">NODE://node-01</span>
<span class="text-outline text-xs">/</span>
<span class="font-code-sm text-code-sm text-primary font-mono uppercase tracking-wider">SecOps &amp; Disaster Recovery</span>
</div>
<div class="flex items-center gap-space-lg">
<div class="flex items-center gap-space-xs font-code-sm text-code-sm text-on-surface-variant">
<span class="h-2 w-2 rounded-full bg-secondary animate-pulse"></span>
<span>Audit Daemon: <span class="text-secondary font-mono">ENFORCING</span></span>
</div>
<div class="h-4 w-px bg-surface-container-highest"></div>
<div class="font-code-sm text-code-sm text-on-surface-variant">
        Last Synced: <span class="text-on-surface font-mono">02:44:19 UTC</span>
</div>
</div>
</div>
<div class="p-gutter-lg space-y-gutter-lg max-w-[1600px] w-full mx-auto">
<!-- Top Telemetry Banner & Score Overview -->
<div class="grid grid-cols-1 lg:grid-cols-12 gap-gutter-lg items-stretch">
<!-- Security Health Dial & Summary -->
<div class="lg:col-span-8 bg-surface-container-low rounded-xl p-space-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-space-xl shadow-xl relative overflow-hidden">
<div class="absolute -right-16 -top-16 w-64 h-64 bg-primary/5 rounded-full blur-3xl pointer-events-none"></div>
<div class="space-y-space-sm flex-1">
<div class="inline-flex items-center gap-space-xs px-space-sm py-0.5 rounded bg-secondary/10 text-secondary font-label-caps text-label-caps uppercase">
<span aria-hidden="true" class="material-symbols-outlined text-sm">shield</span>
            Policy Tier 1 Enforced
          </div>
<h1 class="font-headline-lg text-headline-lg text-on-surface font-bold tracking-tight">Security Center &amp; Automated Backups</h1>
<p class="font-body-md text-body-md text-on-surface-variant max-w-xl">
            Real-time packet inspection active on <code class="font-code-sm text-code-sm text-primary bg-surface-container-highest px-1.5 py-0.5 rounded">eth0</code>. Host isolation triggers, rate limiting, and encrypted remote storage mirroring are synchronized.
          </p>
<div class="pt-space-sm flex flex-wrap items-center gap-space-md">
<span class="inline-flex items-center gap-1.5 font-code-sm text-code-sm text-secondary bg-surface-container px-2.5 py-1 rounded">
<span class="h-1.5 w-1.5 rounded-full bg-secondary"></span> SSH Port Restrict: ACTIVE
            </span>
<span class="inline-flex items-center gap-1.5 font-code-sm text-code-sm text-secondary bg-surface-container px-2.5 py-1 rounded">
<span class="h-1.5 w-1.5 rounded-full bg-secondary"></span> Fail2Ban: ENGAGED
            </span>
<span class="inline-flex items-center gap-1.5 font-code-sm text-code-sm text-secondary bg-surface-container px-2.5 py-1 rounded">
<span class="h-1.5 w-1.5 rounded-full bg-secondary"></span> S3 Snapshot Sync: NOMINAL
            </span>
</div>
</div>
<div class="flex items-center gap-space-lg bg-surface-container p-space-lg rounded-xl shrink-0 self-stretch md:self-auto justify-between md:justify-start">
<div class="relative w-24 h-24 shrink-0">
<svg class="w-24 h-24 transform -rotate-90" viewbox="0 0 100 100">
<circle class="text-surface-container-highest" cx="50" cy="50" fill="transparent" r="42" stroke="currentColor" stroke-width="8"></circle>
<circle class="text-secondary" cx="50" cy="50" fill="transparent" r="42" stroke="currentColor" stroke-dasharray="264" stroke-dashoffset="10.56" stroke-linecap="round" stroke-width="8"></circle>
</svg>
<div class="absolute inset-0 flex flex-col items-center justify-center">
<span class="font-headline-lg text-headline-lg font-bold text-on-surface leading-none">96</span>
<span class="font-label-caps text-label-caps text-outline uppercase text-[9px] mt-0.5">/100</span>
</div>
</div>
<div>
<span class="font-label-caps text-label-caps text-secondary uppercase font-semibold">Security Score</span>
<p class="font-headline-md text-headline-md font-bold text-on-surface">Optimal</p>
<p class="font-code-sm text-code-sm text-outline">0 Critical Flags</p>
</div>
</div>
</div>
<!-- Quick Action Node Card -->
<div class="lg:col-span-4 bg-surface-container-low rounded-xl p-space-lg flex flex-col justify-between shadow-xl">
<div class="space-y-space-xs">
<div class="flex items-center justify-between">
<span class="font-label-caps text-label-caps text-outline uppercase tracking-wider">Fast Threat Mitigation</span>
<span class="font-code-sm text-code-sm text-primary">v2.4.9 Guard</span>
</div>
<h2 class="font-headline-md text-headline-md text-on-surface">Lockdown Controls</h2>
<p class="font-body-sm text-body-sm text-on-surface-variant">Instant zero-trust ingress quarantine and hot snapshot triggers.</p>
</div>
<div class="grid grid-cols-2 gap-space-sm pt-space-md">
<button class="flex flex-col items-start p-space-md rounded-lg bg-surface-container hover:bg-surface-container-high transition-all group text-left" id="triggerSnapshotBtn">
<span aria-hidden="true" class="material-symbols-outlined text-primary mb-space-xs group-hover:scale-110 transition-transform">cloud_upload</span>
<span class="font-body-md text-body-md font-semibold text-on-surface leading-tight">Backup Now</span>
<span class="font-code-sm text-code-sm text-outline">Backup job</span>
</button>
<button class="flex flex-col items-start p-space-md rounded-lg bg-surface-container hover:bg-error-container/20 transition-all group text-left" id="panicLockBtn">
<span aria-hidden="true" class="material-symbols-outlined text-error mb-space-xs group-hover:scale-110 transition-transform">shield_lock</span>
<span class="font-body-md text-body-md font-semibold text-error leading-tight">Strict Ingress</span>
<span class="font-code-sm text-code-sm text-outline">Drop External</span>
</button>
</div>
</div>
</div>
<!-- Section 1: UFW Firewall & Open Ports Manager -->
<div class="bg-surface-container-low rounded-xl p-space-lg shadow-xl space-y-space-lg">
<div class="flex flex-col sm:flex-row sm:items-center justify-between gap-space-md">
<div class="flex items-center gap-space-md">
<div class="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center text-primary shrink-0">
<span aria-hidden="true" class="material-symbols-outlined text-2xl">local_fire_department</span>
</div>
<div>
<div class="flex items-center gap-space-sm">
<h2 class="font-headline-md text-headline-md font-bold text-on-surface">Host Firewall &amp; Network Rules</h2>
<span class="font-label-caps text-label-caps px-2 py-0.5 rounded bg-secondary/15 text-secondary">FILTERING</span>
</div>
<p class="font-body-sm text-body-sm text-on-surface-variant">Manage inbound traffic policies, restricted port forwarding, and CIDR subnet blocks.</p>
</div>
</div>
<div class="flex items-center gap-space-md self-end sm:self-auto">
<!-- Toggle: Firewall Status -->
<div class="flex items-center gap-space-sm bg-surface-container px-space-md py-1.5 rounded-lg">
<span class="font-code-sm text-code-sm text-on-surface-variant font-medium">Firewall adapter:</span>
<label class="relative inline-flex items-center cursor-pointer">
<input checked="" class="sr-only peer" id="ufwToggle" type="checkbox"/>
<div class="w-11 h-6 bg-surface-container-highest peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-on-surface after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-secondary"></div>
</label>
<span class="font-code-sm text-code-sm text-secondary font-mono" id="ufwStatusText">ACTIVE</span>
</div>
<button class="flex items-center gap-space-xs px-space-md py-2 rounded-lg bg-primary text-on-primary font-body-sm text-body-sm font-semibold hover:shadow-lg hover:shadow-primary/20 transition-all" id="openFirewallModal">
<span aria-hidden="true" class="material-symbols-outlined text-base">add_moderator</span>
<span>Add Rule</span>
</button>
</div>
</div>
<!-- Rule Table -->
<div class="overflow-x-auto rounded-lg bg-surface-container-lowest">
<table class="w-full text-left border-collapse">
<thead>
<tr class="bg-surface-container-high/60 font-label-caps text-label-caps text-outline uppercase">
<th class="py-space-sm px-space-md">Target Service</th>
<th class="py-space-sm px-space-md">Port &amp; Proto</th>
<th class="py-space-sm px-space-md">Inbound Policy</th>
<th class="py-space-sm px-space-md">Allowed Origin</th>
<th class="py-space-sm px-space-md">Packets / 24h</th>
<th class="py-space-sm px-space-md text-right">Actions</th>
</tr>
</thead>
<tbody class="font-body-md text-body-md divide-y divide-surface-container-highest/40">
<tr class="hover:bg-surface-container-high/30 transition-colors">
<td class="py-space-md px-space-md">
<div class="flex items-center gap-space-sm">
<span aria-hidden="true" class="material-symbols-outlined text-base text-primary">terminal</span>
<span class="font-semibold text-on-surface">SSH Remote Daemon</span>
</div>
</td>
<td class="py-space-md px-space-md">
<span class="font-code-md text-code-md text-on-surface font-mono bg-surface-container px-2 py-0.5 rounded">22 / TCP</span>
</td>
<td class="py-space-md px-space-md">
<span class="inline-flex items-center gap-1 font-label-caps text-label-caps text-tertiary bg-tertiary/10 px-2 py-0.5 rounded">
<span class="h-1.5 w-1.5 rounded-full bg-tertiary"></span> RESTRICTED
                </span>
</td>
<td class="py-space-md px-space-md">
<span class="font-code-sm text-code-sm text-on-surface-variant font-mono">198.51.100.0/24 (VPC Office)</span>
</td>
<td class="py-space-md px-space-md font-code-sm text-code-sm text-outline font-mono">
                1,842 pkts
              </td>
<td class="py-space-md px-space-md text-right">
<div class="flex items-center justify-end gap-space-xs">
<button class="p-1 text-on-surface-variant hover:text-primary transition-colors" title="Edit Rule"><span aria-hidden="true" class="material-symbols-outlined text-base">edit</span></button>
<button class="p-1 text-on-surface-variant hover:text-error transition-colors" title="Delete Rule"><span aria-hidden="true" class="material-symbols-outlined text-base">delete</span></button>
</div>
</td>
</tr>
<tr class="hover:bg-surface-container-high/30 transition-colors">
<td class="py-space-md px-space-md">
<div class="flex items-center gap-space-sm">
<span aria-hidden="true" class="material-symbols-outlined text-base text-secondary">public</span>
<span class="font-semibold text-on-surface">HTTP Ingress Edge</span>
</div>
</td>
<td class="py-space-md px-space-md">
<span class="font-code-md text-code-md text-on-surface font-mono bg-surface-container px-2 py-0.5 rounded">80 / TCP</span>
</td>
<td class="py-space-md px-space-md">
<span class="inline-flex items-center gap-1 font-label-caps text-label-caps text-secondary bg-secondary/10 px-2 py-0.5 rounded">
<span class="h-1.5 w-1.5 rounded-full bg-secondary"></span> ALLOW ALL
                </span>
</td>
<td class="py-space-md px-space-md">
<span class="font-code-sm text-code-sm text-on-surface-variant font-mono">0.0.0.0/0 (Global Any)</span>
</td>
<td class="py-space-md px-space-md font-code-sm text-code-sm text-outline font-mono">
                489,120 pkts
              </td>
<td class="py-space-md px-space-md text-right">
<div class="flex items-center justify-end gap-space-xs">
<button class="p-1 text-on-surface-variant hover:text-primary transition-colors"><span aria-hidden="true" class="material-symbols-outlined text-base">edit</span></button>
<button class="p-1 text-on-surface-variant hover:text-error transition-colors"><span aria-hidden="true" class="material-symbols-outlined text-base">delete</span></button>
</div>
</td>
</tr>
<tr class="hover:bg-surface-container-high/30 transition-colors">
<td class="py-space-md px-space-md">
<div class="flex items-center gap-space-sm">
<span aria-hidden="true" class="material-symbols-outlined text-base text-secondary">lock</span>
<span class="font-semibold text-on-surface">HTTPS Secure Web</span>
</div>
</td>
<td class="py-space-md px-space-md">
<span class="font-code-md text-code-md text-on-surface font-mono bg-surface-container px-2 py-0.5 rounded">443 / TCP</span>
</td>
<td class="py-space-md px-space-md">
<span class="inline-flex items-center gap-1 font-label-caps text-label-caps text-secondary bg-secondary/10 px-2 py-0.5 rounded">
<span class="h-1.5 w-1.5 rounded-full bg-secondary"></span> ALLOW ALL
                </span>
</td>
<td class="py-space-md px-space-md">
<span class="font-code-sm text-code-sm text-on-surface-variant font-mono">0.0.0.0/0, ::/0</span>
</td>
<td class="py-space-md px-space-md font-code-sm text-code-sm text-outline font-mono">
                2,410,950 pkts
              </td>
<td class="py-space-md px-space-md text-right">
<div class="flex items-center justify-end gap-space-xs">
<button class="p-1 text-on-surface-variant hover:text-primary transition-colors"><span aria-hidden="true" class="material-symbols-outlined text-base">edit</span></button>
<button class="p-1 text-on-surface-variant hover:text-error transition-colors"><span aria-hidden="true" class="material-symbols-outlined text-base">delete</span></button>
</div>
</td>
</tr>
<tr class="hover:bg-surface-container-high/30 transition-colors">
<td class="py-space-md px-space-md">
<div class="flex items-center gap-space-sm">
<span aria-hidden="true" class="material-symbols-outlined text-base text-primary">database</span>
<span class="font-semibold text-on-surface">PostgreSQL Cluster Node</span>
</div>
</td>
<td class="py-space-md px-space-md">
<span class="font-code-md text-code-md text-on-surface font-mono bg-surface-container px-2 py-0.5 rounded">5432 / TCP</span>
</td>
<td class="py-space-md px-space-md">
<span class="inline-flex items-center gap-1 font-label-caps text-label-caps text-primary bg-primary/10 px-2 py-0.5 rounded">
<span class="h-1.5 w-1.5 rounded-full bg-primary"></span> INTERNAL VPC
                </span>
</td>
<td class="py-space-md px-space-md">
<span class="font-code-sm text-code-sm text-on-surface-variant font-mono">10.140.0.0/20 (Cluster Subnet)</span>
</td>
<td class="py-space-md px-space-md font-code-sm text-code-sm text-outline font-mono">
                98,404 pkts
              </td>
<td class="py-space-md px-space-md text-right">
<div class="flex items-center justify-end gap-space-xs">
<button class="p-1 text-on-surface-variant hover:text-primary transition-colors"><span aria-hidden="true" class="material-symbols-outlined text-base">edit</span></button>
<button class="p-1 text-on-surface-variant hover:text-error transition-colors"><span aria-hidden="true" class="material-symbols-outlined text-base">delete</span></button>
</div>
</td>
</tr>
<tr class="hover:bg-surface-container-high/30 transition-colors">
<td class="py-space-md px-space-md">
<div class="flex items-center gap-space-sm">
<span aria-hidden="true" class="material-symbols-outlined text-base text-error">memory</span>
<span class="font-semibold text-on-surface">Redis Cache In-Memory</span>
</div>
</td>
<td class="py-space-md px-space-md">
<span class="font-code-md text-code-md text-on-surface font-mono bg-surface-container px-2 py-0.5 rounded">6379 / TCP</span>
</td>
<td class="py-space-md px-space-md">
<span class="inline-flex items-center gap-1 font-label-caps text-label-caps text-error bg-error/10 px-2 py-0.5 rounded">
<span class="h-1.5 w-1.5 rounded-full bg-error"></span> DENIED EXT
                </span>
</td>
<td class="py-space-md px-space-md">
<span class="font-code-sm text-code-sm text-error/80 font-mono">Blocked at Kernel Level</span>
</td>
<td class="py-space-md px-space-md font-code-sm text-code-sm text-outline font-mono">
                12 dropped
              </td>
<td class="py-space-md px-space-md text-right">
<div class="flex items-center justify-end gap-space-xs">
<button class="p-1 text-on-surface-variant hover:text-primary transition-colors"><span aria-hidden="true" class="material-symbols-outlined text-base">edit</span></button>
<button class="p-1 text-on-surface-variant hover:text-error transition-colors"><span aria-hidden="true" class="material-symbols-outlined text-base">delete</span></button>
</div>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<!-- Section 2 & Section 3: Dual Column Grid -->
<div class="grid grid-cols-1 lg:grid-cols-12 gap-gutter-lg">
<!-- Section 2: Intrusion Prevention & Fail2ban / SSH Guard (7 cols) -->
<div class="lg:col-span-7 bg-surface-container-low rounded-xl p-space-lg shadow-xl space-y-space-lg flex flex-col justify-between">
<div class="space-y-space-md">
<div class="flex flex-col sm:flex-row sm:items-center justify-between gap-space-sm">
<div class="flex items-center gap-space-md">
<div class="h-10 w-10 rounded-lg bg-error-container/20 flex items-center justify-center text-error shrink-0">
<span aria-hidden="true" class="material-symbols-outlined text-2xl">fingerprint</span>
</div>
<div>
<div class="flex items-center gap-space-sm">
<h2 class="font-headline-md text-headline-md font-bold text-on-surface">Intrusion Prevention</h2>
<span class="font-label-caps text-label-caps text-secondary bg-secondary/10 px-1.5 py-0.5 rounded">ACTIVE</span>
</div>
<p class="font-body-sm text-body-sm text-on-surface-variant">Live audit tail on <code class="font-code-sm text-code-sm text-primary">/var/log/auth.log</code> via Fail2ban &amp; SSHGuard.</p>
</div>
</div>
<div class="bg-surface-container px-space-md py-1 rounded-lg text-right">
<span class="font-label-caps text-label-caps text-error uppercase">Banned 24h</span>
<p class="font-headline-md text-headline-md font-bold text-error leading-tight font-mono">38 <span class="font-body-sm text-body-sm text-outline">IPs</span></p>
</div>
</div>
<!-- Banned IPs Table -->
<div class="overflow-x-auto rounded-lg bg-surface-container-lowest">
<table class="w-full text-left border-collapse">
<thead>
<tr class="bg-surface-container-high/60 font-label-caps text-label-caps text-outline uppercase">
<th class="py-space-sm px-space-md">Offending IP &amp; Origin</th>
<th class="py-space-sm px-space-md">Attack Signature</th>
<th class="py-space-sm px-space-md">Banned At</th>
<th class="py-space-sm px-space-md text-right">Mitigation</th>
</tr>
</thead>
<tbody class="font-body-md text-body-md divide-y divide-surface-container-highest/40" id="bannedIpList">
<tr class="hover:bg-surface-container-high/30 transition-colors">
<td class="py-space-md px-space-md">
<div class="flex items-center gap-space-sm">
<span class="font-code-sm text-code-sm px-1.5 py-0.5 rounded bg-surface-container-highest font-mono text-on-surface">RU</span>
<span class="font-code-md text-code-md font-mono text-on-surface">185.220.101.5</span>
</div>
</td>
<td class="py-space-md px-space-md">
<span class="font-code-sm text-code-sm text-error bg-error/10 px-2 py-0.5 rounded font-mono">SSH Brute Force (5x invalid)</span>
</td>
<td class="py-space-md px-space-md font-code-sm text-code-sm text-outline font-mono">
                    12m ago (02:32:11)
                  </td>
<td class="py-space-md px-space-md text-right">
<button class="unban-btn px-2.5 py-1 rounded bg-surface-container hover:bg-surface-container-highest text-on-surface-variant hover:text-on-surface font-code-sm text-code-sm transition-colors" data-ip="185.220.101.5">Unban</button>
</td>
</tr>
<tr class="hover:bg-surface-container-high/30 transition-colors">
<td class="py-space-md px-space-md">
<div class="flex items-center gap-space-sm">
<span class="font-code-sm text-code-sm px-1.5 py-0.5 rounded bg-surface-container-highest font-mono text-on-surface">CN</span>
<span class="font-code-md text-code-md font-mono text-on-surface">222.186.42.138</span>
</div>
</td>
<td class="py-space-md px-space-md">
<span class="font-code-sm text-code-sm text-tertiary bg-tertiary/10 px-2 py-0.5 rounded font-mono">Port Scan (TCP SYN Flood)</span>
</td>
<td class="py-space-md px-space-md font-code-sm text-code-sm text-outline font-mono">
                    48m ago (01:56:02)
                  </td>
<td class="py-space-md px-space-md text-right">
<button class="unban-btn px-2.5 py-1 rounded bg-surface-container hover:bg-surface-container-highest text-on-surface-variant hover:text-on-surface font-code-sm text-code-sm transition-colors" data-ip="222.186.42.138">Unban</button>
</td>
</tr>
<tr class="hover:bg-surface-container-high/30 transition-colors">
<td class="py-space-md px-space-md">
<div class="flex items-center gap-space-sm">
<span class="font-code-sm text-code-sm px-1.5 py-0.5 rounded bg-surface-container-highest font-mono text-on-surface">NL</span>
<span class="font-code-md text-code-md font-mono text-on-surface">94.102.61.12</span>
</div>
</td>
<td class="py-space-md px-space-md">
<span class="font-code-sm text-code-sm text-error bg-error/10 px-2 py-0.5 rounded font-mono">SSH Root Login Attempt</span>
</td>
<td class="py-space-md px-space-md font-code-sm text-code-sm text-outline font-mono">
                    2h 14m ago
                  </td>
<td class="py-space-md px-space-md text-right">
<button class="unban-btn px-2.5 py-1 rounded bg-surface-container hover:bg-surface-container-highest text-on-surface-variant hover:text-on-surface font-code-sm text-code-sm transition-colors" data-ip="94.102.61.12">Unban</button>
</td>
</tr>
</tbody>
</table>
</div>
</div>
<div class="flex items-center justify-between pt-space-xs font-code-sm text-code-sm text-outline">
<div class="flex items-center gap-1.5">
<span class="h-2 w-2 rounded-full bg-secondary"></span> Jail: sshd, recidive, nginx-req-limit
          </div>
<button class="text-primary hover:underline font-medium">Export Ban Registry (.csv)</button>
</div>
</div>
<!-- Section 3: SSH Key & Access Management (5 cols) -->
<div class="lg:col-span-5 bg-surface-container-low rounded-xl p-space-lg shadow-xl space-y-space-lg flex flex-col justify-between">
<div class="space-y-space-md">
<div class="flex items-center justify-between">
<div class="flex items-center gap-space-md">
<div class="h-10 w-10 rounded-lg bg-secondary/10 flex items-center justify-center text-secondary shrink-0">
<span aria-hidden="true" class="material-symbols-outlined text-2xl">key</span>
</div>
<div>
<h2 class="font-headline-md text-headline-md font-bold text-on-surface">SSH Key Access</h2>
<p class="font-body-sm text-body-sm text-on-surface-variant">Authorized identities &amp; hardened login policies.</p>
</div>
</div>
<button class="flex items-center gap-1 px-space-sm py-1.5 rounded-lg bg-surface-container hover:bg-surface-container-high text-primary font-body-sm text-body-sm transition-colors" id="addSshKeyBtn">
<span aria-hidden="true" class="material-symbols-outlined text-sm">add</span>
<span>New Key</span>
</button>
</div>
<!-- Hardened Config Highlights -->
<div class="p-space-md rounded-lg bg-surface-container space-y-space-xs">
<div class="flex items-center justify-between">
<span class="font-body-sm text-body-sm text-on-surface font-semibold">Root Password Authentication</span>
<span class="font-label-caps text-label-caps text-secondary bg-secondary/15 px-2 py-0.5 rounded">DISABLED</span>
</div>
<p class="font-code-sm text-code-sm text-outline">
<code>PermitRootLogin no</code> &amp; <code>PasswordAuthentication no</code> are enforced in <span class="text-on-surface-variant">/etc/ssh/sshd_config</span>.
            </p>
</div>
<!-- Key Items -->
<div class="space-y-space-xs">
<span class="font-label-caps text-label-caps text-outline uppercase">Authorized Public Keys (2)</span>
<div class="p-space-md rounded-lg bg-surface-container hover:bg-surface-container-high transition-colors space-y-space-xs">
<div class="flex items-center justify-between">
<div class="flex items-center gap-space-sm">
<span aria-hidden="true" class="material-symbols-outlined text-secondary text-lg">laptop_mac</span>
<span class="font-code-md text-code-md font-bold text-on-surface">alex-macbook-pro.pub</span>
</div>
<span class="font-label-caps text-label-caps bg-surface-container-highest text-primary px-1.5 py-0.5 rounded">ED25519</span>
</div>
<div class="flex items-center justify-between font-code-sm text-code-sm text-outline">
<span class="truncate max-w-[200px]">SHA256:d8f4...x9qK</span>
<span>Added 12d ago</span>
</div>
</div>
<div class="p-space-md rounded-lg bg-surface-container hover:bg-surface-container-high transition-colors space-y-space-xs">
<div class="flex items-center justify-between">
<div class="flex items-center gap-space-sm">
<span aria-hidden="true" class="material-symbols-outlined text-primary text-lg">terminal</span>
<span class="font-code-md text-code-md font-bold text-on-surface">ci-cd-deployer-key</span>
</div>
<span class="font-label-caps text-label-caps bg-surface-container-highest text-on-surface-variant px-1.5 py-0.5 rounded">RSA 4096</span>
</div>
<div class="flex items-center justify-between font-code-sm text-code-sm text-outline">
<span class="truncate max-w-[200px]">SHA256:aa91...01wV</span>
<span>Added 44d ago</span>
</div>
</div>
</div>
</div>
<div class="p-space-sm rounded-lg bg-surface-container-lowest flex items-center justify-between font-code-sm text-code-sm text-on-surface-variant">
<span>Active SSH Sessions: <strong class="text-secondary font-mono">1 User</strong> (alex.root)</span>
<button class="text-error hover:underline">Revoke Others</button>
</div>
</div>
</div>
<!-- Section 4: Automated Backup & Disaster Recovery -->
<div class="bg-surface-container-low rounded-xl p-space-lg shadow-xl space-y-space-lg">
<div class="flex flex-col md:flex-row md:items-center justify-between gap-space-md">
<div class="flex items-center gap-space-md">
<div class="h-10 w-10 rounded-lg bg-tertiary/10 flex items-center justify-center text-tertiary shrink-0">
<span aria-hidden="true" class="material-symbols-outlined text-2xl">backup</span>
</div>
<div>
<div class="flex items-center gap-space-sm">
<h2 class="font-headline-md text-headline-md font-bold text-on-surface">Automated Backup &amp; Disaster Recovery</h2>
<span class="font-label-caps text-label-caps px-2 py-0.5 rounded bg-secondary/15 text-secondary">ENCRYPTION: AES-256</span>
</div>
<p class="font-body-sm text-body-sm text-on-surface-variant">Dual-tier block synchronization to local persistent NVMe and remote object storage.</p>
</div>
</div>
<div class="flex flex-wrap items-center gap-space-sm">
<button class="flex items-center gap-space-xs px-space-md py-2 rounded-lg bg-surface-container hover:bg-surface-container-high border border-outline-variant/40 text-on-surface font-body-sm text-body-sm font-semibold transition-all" id="manualSnapshotBtn">
<span aria-hidden="true" class="material-symbols-outlined text-base text-primary">add_circle</span>
<span>Trigger Manual Snapshot</span>
</button>
</div>
</div>
<!-- Backup Config & Destination Cards -->
<div class="grid grid-cols-1 md:grid-cols-3 gap-space-md">
<div class="p-space-md rounded-lg bg-surface-container space-y-space-xs">
<div class="flex items-center justify-between">
<span class="font-label-caps text-label-caps text-outline uppercase">Storage Target</span>
<span aria-hidden="true" class="material-symbols-outlined text-primary text-base">cloud_sync</span>
</div>
<p class="font-code-md text-code-md font-mono text-on-surface truncate">s3://axion-backups-asia/daily</p>
<div class="flex items-center gap-2 pt-1 font-code-sm text-code-sm text-secondary">
<span class="h-1.5 w-1.5 rounded-full bg-secondary"></span> Remote Bucket Synchronized
          </div>
</div>
<div class="p-space-md rounded-lg bg-surface-container space-y-space-xs">
<div class="flex items-center justify-between">
<span class="font-label-caps text-label-caps text-outline uppercase">Cron Schedule</span>
<span aria-hidden="true" class="material-symbols-outlined text-tertiary text-base">schedule</span>
</div>
<p class="font-headline-md text-headline-md font-bold text-on-surface font-mono">02:00 UTC <span class="font-body-sm text-body-sm text-on-surface-variant font-normal">Daily</span></p>
<div class="font-code-sm text-code-sm text-outline">
            Retention Window: <span class="text-on-surface font-mono">14 Days Rolling</span>
</div>
</div>
<div class="p-space-md rounded-lg bg-surface-container space-y-space-xs">
<div class="flex items-center justify-between">
<span class="font-label-caps text-label-caps text-outline uppercase">Local Vault</span>
<span aria-hidden="true" class="material-symbols-outlined text-secondary text-base">hard_drive</span>
</div>
<p class="font-code-md text-code-md font-mono text-on-surface truncate">/mnt/nvme-backup-vol</p>
<div class="flex justify-between items-center font-code-sm text-code-sm pt-1">
<span class="text-outline">NVMe Usage: 28.4 / 100 GB</span>
<span class="text-primary font-mono">28%</span>
</div>
</div>
</div>
<!-- Snapshots List Table -->
<div class="space-y-space-xs">
<div class="flex items-center justify-between px-space-xs">
<span class="font-label-caps text-label-caps text-outline uppercase">Available Restore Snapshots</span>
<span class="font-code-sm text-code-sm text-outline">Total 7 Stored</span>
</div>
<div class="overflow-x-auto rounded-lg bg-surface-container-lowest">
<table class="w-full text-left border-collapse">
<thead>
<tr class="bg-surface-container-high/60 font-label-caps text-label-caps text-outline uppercase">
<th class="py-space-sm px-space-md">Snapshot Identifier</th>
<th class="py-space-sm px-space-md">Size</th>
<th class="py-space-sm px-space-md">Integrity Hash</th>
<th class="py-space-sm px-space-md">Status</th>
<th class="py-space-sm px-space-md">Created At</th>
<th class="py-space-sm px-space-md text-right">Actions</th>
</tr>
</thead>
<tbody class="font-body-md text-body-md divide-y divide-surface-container-highest/40" id="snapshotTableBody">
<tr class="hover:bg-surface-container-high/30 transition-colors">
<td class="py-space-md px-space-md">
<div class="flex items-center gap-space-sm">
<span aria-hidden="true" class="material-symbols-outlined text-primary text-base">save</span>
<div>
<p class="font-code-md text-code-md font-bold text-on-surface font-mono">snapshot-full-20260518-0200</p>
<p class="font-code-sm text-code-sm text-outline">Selected files + database dumps + named volumes</p>
</div>
</div>
</td>
<td class="py-space-md px-space-md font-code-sm text-code-sm font-mono text-on-surface">
                  14.8 GB
                </td>
<td class="py-space-md px-space-md">
<span class="inline-flex items-center gap-1 font-label-caps text-label-caps text-secondary bg-secondary/10 px-2 py-0.5 rounded">
<span aria-hidden="true" class="material-symbols-outlined text-xs">verified</span> SHA-256 OK
                  </span>
</td>
<td class="py-space-md px-space-md">
<span class="inline-flex items-center gap-1.5 font-label-caps text-label-caps text-secondary">
<span class="h-2 w-2 rounded-full bg-secondary"></span> COMPLETED
                  </span>
</td>
<td class="py-space-md px-space-md font-code-sm text-code-sm text-on-surface-variant font-mono">
                  Today, 02:00:14 UTC
                </td>
<td class="py-space-md px-space-md text-right">
<div class="flex items-center justify-end gap-space-xs">
<button class="px-space-sm py-1 rounded bg-secondary/15 hover:bg-secondary/25 text-secondary font-code-sm text-code-sm font-semibold transition-colors flex items-center gap-1" title="Restore snapshot">
<span aria-hidden="true" class="material-symbols-outlined text-sm">settings_backup_restore</span>
<span>Restore Backup</span>
</button>
<button class="p-1 text-on-surface-variant hover:text-primary transition-colors" title="Download Archive">
<span aria-hidden="true" class="material-symbols-outlined text-base">download</span>
</button>
<button class="p-1 text-on-surface-variant hover:text-error transition-colors" title="Delete Snapshot">
<span aria-hidden="true" class="material-symbols-outlined text-base">delete</span>
</button>
</div>
</td>
</tr>
<tr class="hover:bg-surface-container-high/30 transition-colors">
<td class="py-space-md px-space-md">
<div class="flex items-center gap-space-sm">
<span aria-hidden="true" class="material-symbols-outlined text-secondary text-base">database</span>
<div>
<p class="font-code-md text-code-md font-bold text-on-surface font-mono">snapshot-db-postgres-20260518</p>
<p class="font-code-sm text-code-sm text-outline">pg_dumpall WAL stream compressed</p>
</div>
</div>
</td>
<td class="py-space-md px-space-md font-code-sm text-code-sm font-mono text-on-surface">
                  1.2 GB
                </td>
<td class="py-space-md px-space-md">
<span class="inline-flex items-center gap-1 font-label-caps text-label-caps text-secondary bg-secondary/10 px-2 py-0.5 rounded">
<span aria-hidden="true" class="material-symbols-outlined text-xs">verified</span> SHA-256 OK
                  </span>
</td>
<td class="py-space-md px-space-md">
<span class="inline-flex items-center gap-1.5 font-label-caps text-label-caps text-secondary">
<span class="h-2 w-2 rounded-full bg-secondary"></span> COMPLETED
                  </span>
</td>
<td class="py-space-md px-space-md font-code-sm text-code-sm text-on-surface-variant font-mono">
                  Today, 02:04:40 UTC
                </td>
<td class="py-space-md px-space-md text-right">
<div class="flex items-center justify-end gap-space-xs">
<button class="px-space-sm py-1 rounded bg-secondary/15 hover:bg-secondary/25 text-secondary font-code-sm text-code-sm font-semibold transition-colors flex items-center gap-1">
<span aria-hidden="true" class="material-symbols-outlined text-sm">settings_backup_restore</span>
<span>Restore Backup</span>
</button>
<button class="p-1 text-on-surface-variant hover:text-primary transition-colors"><span aria-hidden="true" class="material-symbols-outlined text-base">download</span></button>
<button class="p-1 text-on-surface-variant hover:text-error transition-colors"><span aria-hidden="true" class="material-symbols-outlined text-base">delete</span></button>
</div>
</td>
</tr>
</tbody>
</table>
</div>
</div>
</div>
</div>
<!-- Interactive Modal: Add Firewall Rule (Hidden by default) -->
<div class="fixed inset-0 z-50 bg-surface-container-lowest/80 backdrop-blur-sm hidden items-center justify-center p-space-md" id="firewallModal">
<div class="bg-surface-container-low border border-outline-variant/40 rounded-xl max-w-lg w-full p-space-lg shadow-2xl space-y-space-md animate-fade-in">
<div class="flex items-center justify-between pb-space-sm border-b border-outline-variant/20">
<div class="flex items-center gap-space-sm">
<span aria-hidden="true" class="material-symbols-outlined text-primary">add_moderator</span>
<h3 class="font-headline-md text-headline-md font-bold text-on-surface">Add Inbound Firewall Rule</h3>
</div>
<button class="p-1 text-outline hover:text-on-surface transition-colors" id="closeFirewallModal">
<span aria-hidden="true" class="material-symbols-outlined">close</span>
</button>
</div>
<form class="space-y-space-md" id="newRuleForm">
<div class="space-y-space-xs">
<label class="block font-label-caps text-label-caps text-outline uppercase">Rule / Service Name</label>
<input class="w-full px-space-md py-2 rounded-lg bg-surface-container text-on-surface border border-outline-variant/50 focus:border-primary focus:outline-none font-body-sm text-body-sm" placeholder="e.g. Grafana Monitoring" required="" type="text"/>
</div>
<div class="grid grid-cols-2 gap-space-md">
<div class="space-y-space-xs">
<label class="block font-label-caps text-label-caps text-outline uppercase">Port Range</label>
<input class="w-full px-space-md py-2 rounded-lg bg-surface-container text-on-surface border border-outline-variant/50 focus:border-primary focus:outline-none font-code-md text-code-md" placeholder="3000" required="" type="text"/>
</div>
<div class="space-y-space-xs">
<label class="block font-label-caps text-label-caps text-outline uppercase">Protocol</label>
<select class="w-full px-space-md py-2 rounded-lg bg-surface-container text-on-surface border border-outline-variant/50 focus:border-primary focus:outline-none font-code-md text-code-md">
<option value="TCP">TCP</option>
<option value="UDP">UDP</option>
<option value="BOTH">TCP / UDP</option>
</select>
</div>
</div>
<div class="space-y-space-xs">
<label class="block font-label-caps text-label-caps text-outline uppercase">Inbound Policy Action</label>
<select class="w-full px-space-md py-2 rounded-lg bg-surface-container text-on-surface border border-outline-variant/50 focus:border-primary focus:outline-none font-body-sm text-body-sm">
<option value="ALLOW">ALLOW - Whitelist traffic</option>
<option value="DENY">DENY - Reject &amp; drop packets</option>
<option value="LIMIT">LIMIT - Rate limit connections</option>
</select>
</div>
<div class="space-y-space-xs">
<label class="block font-label-caps text-label-caps text-outline uppercase">Source IP / CIDR Subnet</label>
<input class="w-full px-space-md py-2 rounded-lg bg-surface-container text-on-surface border border-outline-variant/50 focus:border-primary focus:outline-none font-code-md text-code-md" required="" type="text" value="0.0.0.0/0"/>
<span class="font-code-sm text-code-sm text-outline">Enter <code class="text-primary font-mono">0.0.0.0/0</code> to expose globally or a specific CIDR (e.g., 10.0.0.0/24).</span>
</div>
<div class="pt-space-sm flex items-center justify-end gap-space-sm">
<button class="px-space-md py-2 rounded-lg bg-surface-container hover:bg-surface-container-high text-on-surface-variant font-body-sm text-body-sm transition-colors" id="cancelRuleBtn" type="button">Cancel</button>
<button class="px-space-md py-2 rounded-lg bg-primary text-on-primary font-body-sm text-body-sm font-semibold hover:shadow-lg hover:shadow-primary/20 transition-all" type="submit">Apply Rule to Kernel</button>
</div>
</form>
</div>
</div>
<!-- Interactive Modal: Add SSH Key -->
<div class="fixed inset-0 z-50 bg-surface-container-lowest/80 backdrop-blur-sm hidden items-center justify-center p-space-md" id="sshKeyModal">
<div class="bg-surface-container-low border border-outline-variant/40 rounded-xl max-w-lg w-full p-space-lg shadow-2xl space-y-space-md">
<div class="flex items-center justify-between pb-space-sm border-b border-outline-variant/20">
<div class="flex items-center gap-space-sm">
<span aria-hidden="true" class="material-symbols-outlined text-secondary">vpn_key</span>
<h3 class="font-headline-md text-headline-md font-bold text-on-surface">Add SSH Public Key</h3>
</div>
<button class="p-1 text-outline hover:text-on-surface transition-colors" id="closeSshModal">
<span aria-hidden="true" class="material-symbols-outlined">close</span>
</button>
</div>
<form class="space-y-space-md" id="newSshForm">
<div class="space-y-space-xs">
<label class="block font-label-caps text-label-caps text-outline uppercase">Key Name Identifier</label>
<input class="w-full px-space-md py-2 rounded-lg bg-surface-container text-on-surface border border-outline-variant/50 focus:border-secondary focus:outline-none font-body-sm text-body-sm" placeholder="e.g. workstation-ed25519" required="" type="text"/>
</div>
<div class="space-y-space-xs">
<label class="block font-label-caps text-label-caps text-outline uppercase">Public Key Payload (.pub format)</label>
<textarea class="w-full px-space-md py-2 rounded-lg bg-surface-container text-on-surface border border-outline-variant/50 focus:border-secondary focus:outline-none font-code-sm text-code-sm font-mono" placeholder="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host" required="" rows="4"></textarea>
</div>
<div class="pt-space-sm flex items-center justify-end gap-space-sm">
<button class="px-space-md py-2 rounded-lg bg-surface-container hover:bg-surface-container-high text-on-surface-variant font-body-sm text-body-sm transition-colors" id="cancelSshBtn" type="button">Cancel</button>
<button class="px-space-md py-2 rounded-lg bg-secondary text-on-secondary font-body-sm text-body-sm font-semibold hover:shadow-lg hover:shadow-secondary/20 transition-all" type="submit">Authorize Key</button>
</div>
</form>
</div>
</div>
<!-- Notification Toast Container -->
<div class="fixed bottom-6 right-6 z-50 transform translate-y-24 opacity-0 transition-all duration-300 pointer-events-none" id="toastNotification">
<div class="flex items-center gap-space-sm px-space-md py-space-sm rounded-lg bg-surface-container-high text-on-surface shadow-2xl border border-outline-variant/40">
<span aria-hidden="true" class="material-symbols-outlined text-secondary text-lg" id="toastIcon">check_circle</span>
<span class="font-body-sm text-body-sm" id="toastMessage">Action completed successfully</span>
</div>
</div>
</div>
</main>
</section>
</template>
