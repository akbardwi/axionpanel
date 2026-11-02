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
<div class="px-gutter-lg py-margin space-y-gutter-lg max-w-[1600px] mx-auto w-full">
<!-- Top Operational Metrics & Actions Header -->
<div class="flex flex-col xl:flex-row xl:items-center justify-between gap-space-lg bg-surface-container-low p-space-lg rounded-xl shadow-md relative overflow-hidden">
<div class="absolute -right-16 -top-16 w-64 h-64 bg-primary/5 rounded-full blur-3xl pointer-events-none"></div>
<div class="flex flex-col gap-space-xs">
<div class="flex items-center gap-space-sm">
<span class="font-label-caps text-label-caps text-primary tracking-widest uppercase bg-primary/10 px-2 py-0.5 rounded">DOCKER ENGINE &amp; ORCHESTRATION</span>
<span class="inline-flex items-center gap-1.5 font-label-caps text-label-caps text-secondary bg-secondary/10 px-2 py-0.5 rounded">
<span class="h-1.5 w-1.5 rounded-full bg-secondary animate-pulse"></span>
            DAEMON 26.1.1 ACTIVE
          </span>
</div>
<h1 class="font-headline-lg text-headline-lg font-bold text-on-surface tracking-tight">Application &amp; Container Fleet</h1>
<p class="font-body-sm text-body-sm text-on-surface-variant">Real-time container virtualization, GitOps automation pipeline, and declarative workloads.</p>
</div>
<!-- Quick Telemetry Counters -->
<div class="flex flex-wrap items-center gap-space-md">
<div class="grid grid-cols-5 gap-space-xs bg-surface-container-lowest p-1.5 rounded-lg shadow-inner">
<div class="px-space-md py-1 text-center bg-surface-container rounded">
<span class="block font-code-sm text-code-sm text-on-surface-variant font-mono uppercase">Running</span>
<span class="font-code-lg text-code-lg font-bold text-secondary font-mono">14</span>
</div>
<div class="px-space-md py-1 text-center bg-surface-container rounded">
<span class="block font-code-sm text-code-sm text-on-surface-variant font-mono uppercase">Stopped</span>
<span class="font-code-lg text-code-lg font-bold text-tertiary font-mono">2</span>
</div>
<div class="px-space-md py-1 text-center bg-surface-container rounded">
<span class="block font-code-sm text-code-sm text-on-surface-variant font-mono uppercase">Failed</span>
<span class="font-code-lg text-code-lg font-bold text-outline font-mono">0</span>
</div>
<div class="px-space-md py-1 text-center bg-surface-container rounded">
<span class="block font-code-sm text-code-sm text-on-surface-variant font-mono uppercase">Volumes</span>
<span class="font-code-lg text-code-lg font-bold text-on-surface font-mono">6</span>
</div>
<div class="px-space-md py-1 text-center bg-surface-container rounded">
<span class="block font-code-sm text-code-sm text-on-surface-variant font-mono uppercase">Networks</span>
<span class="font-code-lg text-code-lg font-bold text-primary font-mono">3</span>
</div>
</div>
<div class="flex items-center gap-space-sm">
<button class="flex items-center gap-space-xs px-space-md py-2.5 rounded-lg bg-surface-container hover:bg-surface-container-high text-on-surface font-body-sm text-body-sm transition-all shadow-sm" type="button">
<span aria-hidden="true" class="material-symbols-outlined text-base text-primary">data_object</span>
<span>Compose Stack</span>
</button>
<button class="flex items-center gap-space-xs px-space-md py-2.5 rounded-lg bg-primary-container text-on-primary font-body-sm text-body-sm font-semibold hover:brightness-110 transition-all shadow-sm" type="button">
<span aria-hidden="true" class="material-symbols-outlined text-base">add_circle</span>
<span>+ Deploy New App</span>
</button>
</div>
</div>
</div>
<!-- One-Click App Store Banner / Fast Launchers -->
<div class="flex flex-col gap-space-md bg-surface-container-low p-space-lg rounded-xl shadow-md">
<div class="flex items-center justify-between">
<div class="flex items-center gap-space-sm">
<span aria-hidden="true" class="material-symbols-outlined text-primary text-xl">rocket_launch</span>
<span class="font-headline-md text-headline-md font-semibold text-on-surface">1-Click Fast Application Blueprints</span>
<span class="font-code-sm text-code-sm text-outline px-2 py-0.5 rounded bg-surface-container-highest">Curated Stacks</span>
</div>
<a class="font-code-sm text-code-sm text-primary hover:underline flex items-center gap-1" href="#">
          Explore Hub Catalog (48+) <span aria-hidden="true" class="material-symbols-outlined text-sm">arrow_forward</span>
</a>
</div>
<div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-space-sm">
<!-- Blueprint 1: PostgreSQL -->
<div class="flex flex-col justify-between p-space-md bg-surface-container hover:bg-surface-container-high rounded-lg transition-all group shadow-sm">
<div class="flex items-start justify-between">
<div class="w-8 h-8 rounded bg-primary/10 flex items-center justify-center text-primary group-hover:scale-105 transition-transform">
<span aria-hidden="true" class="material-symbols-outlined text-lg">database</span>
</div>
<span class="font-code-sm text-code-sm text-secondary bg-secondary/10 px-1.5 py-0.2 rounded font-mono">v16.2</span>
</div>
<div class="my-space-sm">
<h4 class="font-headline-md text-headline-md text-on-surface text-sm font-semibold truncate">PostgreSQL</h4>
<p class="font-code-sm text-code-sm text-outline truncate">Relational DB</p>
</div>
<button class="w-full py-1 px-2 rounded bg-surface-container-highest hover:bg-primary-container hover:text-on-primary font-code-sm text-code-sm text-on-surface-variant transition-colors flex items-center justify-center gap-1" type="button">
<span aria-hidden="true" class="material-symbols-outlined text-xs">bolt</span> Launch
          </button>
</div>
<!-- Blueprint 2: Redis -->
<div class="flex flex-col justify-between p-space-md bg-surface-container hover:bg-surface-container-high rounded-lg transition-all group shadow-sm">
<div class="flex items-start justify-between">
<div class="w-8 h-8 rounded bg-error-container/30 flex items-center justify-center text-error group-hover:scale-105 transition-transform">
<span aria-hidden="true" class="material-symbols-outlined text-lg">memory</span>
</div>
<span class="font-code-sm text-code-sm text-secondary bg-secondary/10 px-1.5 py-0.2 rounded font-mono">v7.2</span>
</div>
<div class="my-space-sm">
<h4 class="font-headline-md text-headline-md text-on-surface text-sm font-semibold truncate">Redis In-Memory</h4>
<p class="font-code-sm text-code-sm text-outline truncate">Key-Value Cache</p>
</div>
<button class="w-full py-1 px-2 rounded bg-surface-container-highest hover:bg-primary-container hover:text-on-primary font-code-sm text-code-sm text-on-surface-variant transition-colors flex items-center justify-center gap-1" type="button">
<span aria-hidden="true" class="material-symbols-outlined text-xs">bolt</span> Launch
          </button>
</div>
<!-- Blueprint 3: Strapi -->
<div class="flex flex-col justify-between p-space-md bg-surface-container hover:bg-surface-container-high rounded-lg transition-all group shadow-sm">
<div class="flex items-start justify-between">
<div class="w-8 h-8 rounded bg-primary-fixed-dim/20 flex items-center justify-center text-primary-fixed-dim group-hover:scale-105 transition-transform">
<span aria-hidden="true" class="material-symbols-outlined text-lg">view_quilt</span>
</div>
<span class="font-code-sm text-code-sm text-outline bg-surface-container-highest px-1.5 py-0.2 rounded font-mono">v4.20</span>
</div>
<div class="my-space-sm">
<h4 class="font-headline-md text-headline-md text-on-surface text-sm font-semibold truncate">Strapi CMS</h4>
<p class="font-code-sm text-code-sm text-outline truncate">Headless Node</p>
</div>
<button class="w-full py-1 px-2 rounded bg-surface-container-highest hover:bg-primary-container hover:text-on-primary font-code-sm text-code-sm text-on-surface-variant transition-colors flex items-center justify-center gap-1" type="button">
<span aria-hidden="true" class="material-symbols-outlined text-xs">bolt</span> Launch
          </button>
</div>
<!-- Blueprint 4: Next.js -->
<div class="flex flex-col justify-between p-space-md bg-surface-container hover:bg-surface-container-high rounded-lg transition-all group shadow-sm">
<div class="flex items-start justify-between">
<div class="w-8 h-8 rounded bg-surface-bright flex items-center justify-center text-on-surface group-hover:scale-105 transition-transform">
<span aria-hidden="true" class="material-symbols-outlined text-lg">code_blocks</span>
</div>
<span class="font-code-sm text-code-sm text-secondary bg-secondary/10 px-1.5 py-0.2 rounded font-mono">v14.2</span>
</div>
<div class="my-space-sm">
<h4 class="font-headline-md text-headline-md text-on-surface text-sm font-semibold truncate">Next.js Web</h4>
<p class="font-code-sm text-code-sm text-outline truncate">SSR React Node</p>
</div>
<button class="w-full py-1 px-2 rounded bg-surface-container-highest hover:bg-primary-container hover:text-on-primary font-code-sm text-code-sm text-on-surface-variant transition-colors flex items-center justify-center gap-1" type="button">
<span aria-hidden="true" class="material-symbols-outlined text-xs">bolt</span> Launch
          </button>
</div>
<!-- Blueprint 5: WordPress -->
<div class="flex flex-col justify-between p-space-md bg-surface-container hover:bg-surface-container-high rounded-lg transition-all group shadow-sm">
<div class="flex items-start justify-between">
<div class="w-8 h-8 rounded bg-primary/20 flex items-center justify-center text-primary group-hover:scale-105 transition-transform">
<span aria-hidden="true" class="material-symbols-outlined text-lg">web</span>
</div>
<span class="font-code-sm text-code-sm text-outline bg-surface-container-highest px-1.5 py-0.2 rounded font-mono">v6.5</span>
</div>
<div class="my-space-sm">
<h4 class="font-headline-md text-headline-md text-on-surface text-sm font-semibold truncate">WordPress + DB</h4>
<p class="font-code-sm text-code-sm text-outline truncate">Full LAMP Stack</p>
</div>
<button class="w-full py-1 px-2 rounded bg-surface-container-highest hover:bg-primary-container hover:text-on-primary font-code-sm text-code-sm text-on-surface-variant transition-colors flex items-center justify-center gap-1" type="button">
<span aria-hidden="true" class="material-symbols-outlined text-xs">bolt</span> Launch
          </button>
</div>
<!-- Blueprint 6: Meilisearch -->
<div class="flex flex-col justify-between p-space-md bg-surface-container hover:bg-surface-container-high rounded-lg transition-all group shadow-sm">
<div class="flex items-start justify-between">
<div class="w-8 h-8 rounded bg-tertiary/20 flex items-center justify-center text-tertiary group-hover:scale-105 transition-transform">
<span aria-hidden="true" class="material-symbols-outlined text-lg">manage_search</span>
</div>
<span class="font-code-sm text-code-sm text-secondary bg-secondary/10 px-1.5 py-0.2 rounded font-mono">v1.7</span>
</div>
<div class="my-space-sm">
<h4 class="font-headline-md text-headline-md text-on-surface text-sm font-semibold truncate">Meilisearch</h4>
<p class="font-code-sm text-code-sm text-outline truncate">Lightning Search</p>
</div>
<button class="w-full py-1 px-2 rounded bg-surface-container-highest hover:bg-primary-container hover:text-on-primary font-code-sm text-code-sm text-on-surface-variant transition-colors flex items-center justify-center gap-1" type="button">
<span aria-hidden="true" class="material-symbols-outlined text-xs">bolt</span> Launch
          </button>
</div>
<!-- Blueprint 7: Ollama AI -->
<div class="flex flex-col justify-between p-space-md bg-surface-container hover:bg-surface-container-high rounded-lg transition-all group shadow-sm">
<div class="flex items-start justify-between">
<div class="w-8 h-8 rounded bg-secondary/20 flex items-center justify-center text-secondary group-hover:scale-105 transition-transform">
<span aria-hidden="true" class="material-symbols-outlined text-lg">neurology</span>
</div>
<span class="font-code-sm text-code-sm text-primary bg-primary/10 px-1.5 py-0.2 rounded font-mono">LLM</span>
</div>
<div class="my-space-sm">
<h4 class="font-headline-md text-headline-md text-on-surface text-sm font-semibold truncate">Ollama AI</h4>
<p class="font-code-sm text-code-sm text-outline truncate">Local Inference</p>
</div>
<button class="w-full py-1 px-2 rounded bg-surface-container-highest hover:bg-primary-container hover:text-on-primary font-code-sm text-code-sm text-on-surface-variant transition-colors flex items-center justify-center gap-1" type="button">
<span aria-hidden="true" class="material-symbols-outlined text-xs">bolt</span> Launch
          </button>
</div>
</div>
</div>
<!-- Main Dynamic Section: Split Table & Deployment CI/CD Pipeline -->
<div class="grid grid-cols-1 xl:grid-cols-12 gap-space-lg">
<!-- Left Column: Active Containers (8 Cols on XL) -->
<div class="xl:col-span-8 flex flex-col gap-space-md">
<!-- Filter and Search Header -->
<div class="flex flex-wrap items-center justify-between gap-space-sm bg-surface-container-low p-space-md rounded-xl shadow-md">
<div class="flex items-center gap-space-sm">
<span class="font-headline-md text-headline-md font-semibold text-on-surface">Active Deployments</span>
<span class="font-code-sm text-code-sm px-2 py-0.5 rounded-full bg-secondary/20 text-secondary font-mono">5 Monitored</span>
</div>
<div class="flex items-center gap-space-sm">
<div class="relative flex items-center">
<span aria-hidden="true" class="material-symbols-outlined absolute left-2 text-outline text-base">filter_list</span>
<input class="bg-surface-container-lowest text-on-surface font-code-sm text-code-sm pl-8 pr-3 py-1.5 rounded-lg border-0 focus:outline-none focus:ring-1 focus:ring-primary w-48 sm:w-64 placeholder:text-outline/70" placeholder="Filter by name, port, tag..." type="text"/>
</div>
<button class="p-1.5 rounded-lg bg-surface-container hover:bg-surface-container-high text-on-surface-variant transition-colors" type="button">
<span aria-hidden="true" class="material-symbols-outlined text-base">refresh</span>
</button>
</div>
</div>
<!-- Container Deployment Cards -->
<div class="space-y-space-sm">
<!-- Card 1: production-api -->
<div class="bg-surface-container-low hover:bg-surface-container/60 rounded-xl p-space-md transition-all shadow-md group">
<div class="flex flex-col md:flex-row md:items-center justify-between gap-space-md">
<div class="flex items-start gap-space-md min-w-0">
<div class="p-2.5 rounded-lg bg-surface-container-lowest text-primary shrink-0 group-hover:scale-105 transition-transform">
<span aria-hidden="true" class="material-symbols-outlined text-xl">api</span>
</div>
<div class="min-w-0">
<div class="flex flex-wrap items-center gap-space-xs mb-1">
<span class="font-code-lg text-code-lg font-bold text-on-surface tracking-tight">production-api</span>
<span class="inline-flex items-center gap-1 font-label-caps text-label-caps px-2 py-0.5 rounded bg-secondary/15 text-secondary">
<span class="h-1.5 w-1.5 rounded-full bg-secondary animate-pulse"></span>
                      RUNNING (UP 18D)
                    </span>
<span class="inline-flex items-center gap-1 font-label-caps text-label-caps px-2 py-0.5 rounded bg-primary/10 text-primary">
<span aria-hidden="true" class="material-symbols-outlined text-xs">lock</span> AUTO SSL
                    </span>
</div>
<div class="flex flex-wrap items-center gap-x-space-md gap-y-1 font-code-sm text-code-sm text-outline">
<span class="text-on-surface-variant font-mono">Node.js 20 / Fastify</span>
<span>•</span>
<span class="text-primary font-mono flex items-center gap-1">
<span aria-hidden="true" class="material-symbols-outlined text-xs">link</span> api.axion.io
                    </span>
<span>•</span>
<span class="font-mono">Port: 3000 → 443</span>
</div>
</div>
</div>
<!-- Metrics & Inline Controls -->
<div class="flex items-center justify-between md:justify-end gap-space-lg shrink-0 pt-space-xs md:pt-0">
<div class="flex items-center gap-space-md">
<div class="text-right">
<span class="block font-code-sm text-code-sm text-outline">CPU</span>
<span class="font-code-md text-code-md font-mono text-on-surface font-semibold">4.2%</span>
</div>
<div class="w-16 h-1.5 bg-surface-container-highest rounded-full overflow-hidden">
<div class="h-full bg-primary" style="width: 21%"></div>
</div>
<div class="text-right">
<span class="block font-code-sm text-code-sm text-outline">Memory</span>
<span class="font-code-md text-code-md font-mono text-secondary font-semibold">210 MB</span>
</div>
</div>
<div class="flex items-center gap-1">
<button class="p-1.5 rounded bg-surface-container hover:bg-surface-container-highest text-on-surface-variant hover:text-on-surface transition-colors" title="Restart Container">
<span aria-hidden="true" class="material-symbols-outlined text-base">restart_alt</span>
</button>
<button class="p-1.5 rounded bg-surface-container hover:bg-surface-container-highest text-on-surface-variant hover:text-primary transition-colors" title="View Logs">
<span aria-hidden="true" class="material-symbols-outlined text-base">subject</span>
</button>
<button class="p-1.5 rounded bg-surface-container hover:bg-surface-container-highest text-on-surface-variant hover:text-secondary transition-colors" title="Terminal Shell Exec">
<span aria-hidden="true" class="material-symbols-outlined text-base">terminal</span>
</button>
<button class="p-1.5 rounded bg-surface-container hover:bg-surface-container-highest text-on-surface-variant hover:text-on-surface transition-colors" title="Settings">
<span aria-hidden="true" class="material-symbols-outlined text-base">more_vert</span>
</button>
</div>
</div>
</div>
</div>
<!-- Card 2: nextjs-web-frontend -->
<div class="bg-surface-container-low hover:bg-surface-container/60 rounded-xl p-space-md transition-all shadow-md group">
<div class="flex flex-col md:flex-row md:items-center justify-between gap-space-md">
<div class="flex items-start gap-space-md min-w-0">
<div class="p-2.5 rounded-lg bg-surface-container-lowest text-on-surface shrink-0 group-hover:scale-105 transition-transform">
<span aria-hidden="true" class="material-symbols-outlined text-xl">language</span>
</div>
<div class="min-w-0">
<div class="flex flex-wrap items-center gap-space-xs mb-1">
<span class="font-code-lg text-code-lg font-bold text-on-surface tracking-tight">nextjs-web-frontend</span>
<span class="inline-flex items-center gap-1 font-label-caps text-label-caps px-2 py-0.5 rounded bg-secondary/15 text-secondary">
<span class="h-1.5 w-1.5 rounded-full bg-secondary animate-pulse"></span>
                      RUNNING (UP 4D)
                    </span>
<span class="inline-flex items-center gap-1 font-label-caps text-label-caps px-2 py-0.5 rounded bg-secondary/10 text-secondary font-mono">
<span aria-hidden="true" class="material-symbols-outlined text-xs">alt_route</span> GIT: MAIN
                    </span>
</div>
<div class="flex flex-wrap items-center gap-x-space-md gap-y-1 font-code-sm text-code-sm text-outline">
<span class="text-on-surface-variant font-mono">Next.js 14 Standalone</span>
<span>•</span>
<span class="text-primary font-mono flex items-center gap-1">
<span aria-hidden="true" class="material-symbols-outlined text-xs">link</span> axion.io
                    </span>
<span>•</span>
<span class="font-mono">Port: 3001 → 443</span>
</div>
</div>
</div>
<!-- Metrics & Controls -->
<div class="flex items-center justify-between md:justify-end gap-space-lg shrink-0 pt-space-xs md:pt-0">
<div class="flex items-center gap-space-md">
<div class="text-right">
<span class="block font-code-sm text-code-sm text-outline">CPU</span>
<span class="font-code-md text-code-md font-mono text-on-surface font-semibold">1.8%</span>
</div>
<div class="w-16 h-1.5 bg-surface-container-highest rounded-full overflow-hidden">
<div class="h-full bg-primary" style="width: 14%"></div>
</div>
<div class="text-right">
<span class="block font-code-sm text-code-sm text-outline">Memory</span>
<span class="font-code-md text-code-md font-mono text-secondary font-semibold">345 MB</span>
</div>
</div>
<div class="flex items-center gap-1">
<button class="p-1.5 rounded bg-surface-container hover:bg-surface-container-highest text-on-surface-variant hover:text-on-surface transition-colors" title="Restart Container">
<span aria-hidden="true" class="material-symbols-outlined text-base">restart_alt</span>
</button>
<button class="p-1.5 rounded bg-surface-container hover:bg-surface-container-highest text-on-surface-variant hover:text-primary transition-colors" title="View Logs">
<span aria-hidden="true" class="material-symbols-outlined text-base">subject</span>
</button>
<button class="p-1.5 rounded bg-surface-container hover:bg-surface-container-highest text-on-surface-variant hover:text-secondary transition-colors" title="Terminal Shell Exec">
<span aria-hidden="true" class="material-symbols-outlined text-base">terminal</span>
</button>
<button class="p-1.5 rounded bg-surface-container hover:bg-surface-container-highest text-on-surface-variant hover:text-on-surface transition-colors" title="Settings">
<span aria-hidden="true" class="material-symbols-outlined text-base">more_vert</span>
</button>
</div>
</div>
</div>
</div>
<!-- Card 3: postgres-cluster-01 -->
<div class="bg-surface-container-low hover:bg-surface-container/60 rounded-xl p-space-md transition-all shadow-md group">
<div class="flex flex-col md:flex-row md:items-center justify-between gap-space-md">
<div class="flex items-start gap-space-md min-w-0">
<div class="p-2.5 rounded-lg bg-surface-container-lowest text-primary shrink-0 group-hover:scale-105 transition-transform">
<span aria-hidden="true" class="material-symbols-outlined text-xl">database</span>
</div>
<div class="min-w-0">
<div class="flex flex-wrap items-center gap-space-xs mb-1">
<span class="font-code-lg text-code-lg font-bold text-on-surface tracking-tight">postgres-cluster-01</span>
<span class="inline-flex items-center gap-1 font-label-caps text-label-caps px-2 py-0.5 rounded bg-secondary/15 text-secondary">
<span class="h-1.5 w-1.5 rounded-full bg-secondary animate-pulse"></span>
                      HEALTHY (UP 42D)
                    </span>
<span class="font-label-caps text-label-caps px-2 py-0.5 rounded bg-surface-container-highest text-on-surface-variant font-mono">
                      VOL: 24GB
                    </span>
</div>
<div class="flex flex-wrap items-center gap-x-space-md gap-y-1 font-code-sm text-code-sm text-outline">
<span class="text-on-surface-variant font-mono">postgres:16-alpine</span>
<span>•</span>
<span class="font-mono">Port: 5432 (Isolated VPC)</span>
<span>•</span>
<span class="font-mono text-outline">Mount: /var/lib/postgresql/data</span>
</div>
</div>
</div>
<!-- Metrics & Controls -->
<div class="flex items-center justify-between md:justify-end gap-space-lg shrink-0 pt-space-xs md:pt-0">
<div class="flex items-center gap-space-md">
<div class="text-right">
<span class="block font-code-sm text-code-sm text-outline">CPU</span>
<span class="font-code-md text-code-md font-mono text-on-surface font-semibold">8.1%</span>
</div>
<div class="w-16 h-1.5 bg-surface-container-highest rounded-full overflow-hidden">
<div class="h-full bg-primary" style="width: 42%"></div>
</div>
<div class="text-right">
<span class="block font-code-sm text-code-sm text-outline">Memory</span>
<span class="font-code-md text-code-md font-mono text-secondary font-semibold">720 MB</span>
</div>
</div>
<div class="flex items-center gap-1">
<button class="p-1.5 rounded bg-surface-container hover:bg-surface-container-highest text-on-surface-variant hover:text-on-surface transition-colors" title="Restart Container">
<span aria-hidden="true" class="material-symbols-outlined text-base">restart_alt</span>
</button>
<button class="p-1.5 rounded bg-surface-container hover:bg-surface-container-highest text-on-surface-variant hover:text-primary transition-colors" title="View Logs">
<span aria-hidden="true" class="material-symbols-outlined text-base">subject</span>
</button>
<button class="p-1.5 rounded bg-surface-container hover:bg-surface-container-highest text-on-surface-variant hover:text-secondary transition-colors" title="Terminal Shell Exec">
<span aria-hidden="true" class="material-symbols-outlined text-base">terminal</span>
</button>
<button class="p-1.5 rounded bg-surface-container hover:bg-surface-container-highest text-on-surface-variant hover:text-on-surface transition-colors" title="Settings">
<span aria-hidden="true" class="material-symbols-outlined text-base">more_vert</span>
</button>
</div>
</div>
</div>
</div>
<!-- Card 4: redis-cache -->
<div class="bg-surface-container-low hover:bg-surface-container/60 rounded-xl p-space-md transition-all shadow-md group">
<div class="flex flex-col md:flex-row md:items-center justify-between gap-space-md">
<div class="flex items-start gap-space-md min-w-0">
<div class="p-2.5 rounded-lg bg-surface-container-lowest text-error shrink-0 group-hover:scale-105 transition-transform">
<span aria-hidden="true" class="material-symbols-outlined text-xl">storage</span>
</div>
<div class="min-w-0">
<div class="flex flex-wrap items-center gap-space-xs mb-1">
<span class="font-code-lg text-code-lg font-bold text-on-surface tracking-tight">redis-cache</span>
<span class="inline-flex items-center gap-1 font-label-caps text-label-caps px-2 py-0.5 rounded bg-secondary/15 text-secondary">
<span class="h-1.5 w-1.5 rounded-full bg-secondary animate-pulse"></span>
                      RUNNING (UP 42D)
                    </span>
<span class="font-label-caps text-label-caps px-2 py-0.5 rounded bg-surface-container-highest text-outline font-mono">
                      INTERNAL ONLY
                    </span>
</div>
<div class="flex flex-wrap items-center gap-x-space-md gap-y-1 font-code-sm text-code-sm text-outline">
<span class="text-on-surface-variant font-mono">redis:7-alpine</span>
<span>•</span>
<span class="font-mono">Port: 6379 (Mesh bridge)</span>
<span>•</span>
<span class="font-mono text-secondary">AOF Persistence ON</span>
</div>
</div>
</div>
<!-- Metrics & Controls -->
<div class="flex items-center justify-between md:justify-end gap-space-lg shrink-0 pt-space-xs md:pt-0">
<div class="flex items-center gap-space-md">
<div class="text-right">
<span class="block font-code-sm text-code-sm text-outline">CPU</span>
<span class="font-code-md text-code-md font-mono text-on-surface font-semibold">0.4%</span>
</div>
<div class="w-16 h-1.5 bg-surface-container-highest rounded-full overflow-hidden">
<div class="h-full bg-primary" style="width: 4%"></div>
</div>
<div class="text-right">
<span class="block font-code-sm text-code-sm text-outline">Memory</span>
<span class="font-code-md text-code-md font-mono text-secondary font-semibold">140 MB</span>
</div>
</div>
<div class="flex items-center gap-1">
<button class="p-1.5 rounded bg-surface-container hover:bg-surface-container-highest text-on-surface-variant hover:text-on-surface transition-colors" title="Restart Container">
<span aria-hidden="true" class="material-symbols-outlined text-base">restart_alt</span>
</button>
<button class="p-1.5 rounded bg-surface-container hover:bg-surface-container-highest text-on-surface-variant hover:text-primary transition-colors" title="View Logs">
<span aria-hidden="true" class="material-symbols-outlined text-base">subject</span>
</button>
<button class="p-1.5 rounded bg-surface-container hover:bg-surface-container-highest text-on-surface-variant hover:text-secondary transition-colors" title="Terminal Shell Exec">
<span aria-hidden="true" class="material-symbols-outlined text-base">terminal</span>
</button>
<button class="p-1.5 rounded bg-surface-container hover:bg-surface-container-highest text-on-surface-variant hover:text-on-surface transition-colors" title="Settings">
<span aria-hidden="true" class="material-symbols-outlined text-base">more_vert</span>
</button>
</div>
</div>
</div>
</div>
<!-- Card 5: worker-bullmq -->
<div class="bg-surface-container-low hover:bg-surface-container/60 rounded-xl p-space-md transition-all shadow-md group">
<div class="flex flex-col md:flex-row md:items-center justify-between gap-space-md">
<div class="flex items-start gap-space-md min-w-0">
<div class="p-2.5 rounded-lg bg-surface-container-lowest text-tertiary shrink-0 group-hover:scale-105 transition-transform">
<span aria-hidden="true" class="material-symbols-outlined text-xl">fork_right</span>
</div>
<div class="min-w-0">
<div class="flex flex-wrap items-center gap-space-xs mb-1">
<span class="font-code-lg text-code-lg font-bold text-on-surface tracking-tight">worker-bullmq</span>
<span class="inline-flex items-center gap-1 font-label-caps text-label-caps px-2 py-0.5 rounded bg-secondary/15 text-secondary">
<span class="h-1.5 w-1.5 rounded-full bg-secondary"></span>
                      ACTIVE (12 CONSUMERS)
                    </span>
<span class="font-label-caps text-label-caps px-2 py-0.5 rounded bg-tertiary/10 text-tertiary font-mono">
                      ASYNC JOBS
                    </span>
</div>
<div class="flex flex-wrap items-center gap-x-space-md gap-y-1 font-code-sm text-code-sm text-outline">
<span class="text-on-surface-variant font-mono">TypeScript / BullMQ v5</span>
<span>•</span>
<span class="font-mono">Throughput: 840 jobs/min</span>
<span>•</span>
<span class="font-mono text-outline">Queue: tasks-critical</span>
</div>
</div>
</div>
<!-- Metrics & Controls -->
<div class="flex items-center justify-between md:justify-end gap-space-lg shrink-0 pt-space-xs md:pt-0">
<div class="flex items-center gap-space-md">
<div class="text-right">
<span class="block font-code-sm text-code-sm text-outline">CPU</span>
<span class="font-code-md text-code-md font-mono text-on-surface font-semibold">2.9%</span>
</div>
<div class="w-16 h-1.5 bg-surface-container-highest rounded-full overflow-hidden">
<div class="h-full bg-primary" style="width: 18%"></div>
</div>
<div class="text-right">
<span class="block font-code-sm text-code-sm text-outline">Memory</span>
<span class="font-code-md text-code-md font-mono text-secondary font-semibold">95 MB</span>
</div>
</div>
<div class="flex items-center gap-1">
<button class="p-1.5 rounded bg-surface-container hover:bg-surface-container-highest text-on-surface-variant hover:text-on-surface transition-colors" title="Restart Container">
<span aria-hidden="true" class="material-symbols-outlined text-base">restart_alt</span>
</button>
<button class="p-1.5 rounded bg-surface-container hover:bg-surface-container-highest text-on-surface-variant hover:text-primary transition-colors" title="View Logs">
<span aria-hidden="true" class="material-symbols-outlined text-base">subject</span>
</button>
<button class="p-1.5 rounded bg-surface-container hover:bg-surface-container-highest text-on-surface-variant hover:text-secondary transition-colors" title="Terminal Shell Exec">
<span aria-hidden="true" class="material-symbols-outlined text-base">terminal</span>
</button>
<button class="p-1.5 rounded bg-surface-container hover:bg-surface-container-highest text-on-surface-variant hover:text-on-surface transition-colors" title="Settings">
<span aria-hidden="true" class="material-symbols-outlined text-base">more_vert</span>
</button>
</div>
</div>
</div>
</div>
</div>
</div>
<!-- Right Column: GitOps CI/CD Pipeline & Hardware Distribution (4 Cols on XL) -->
<div class="xl:col-span-4 flex flex-col gap-space-md">
<!-- Git CI/CD Card -->
<div class="bg-surface-container-low p-space-lg rounded-xl shadow-md flex flex-col gap-space-md">
<div class="flex items-center justify-between">
<div class="flex items-center gap-space-sm">
<span aria-hidden="true" class="material-symbols-outlined text-primary text-xl">commit</span>
<span class="font-headline-md text-headline-md font-semibold text-on-surface">Git Continuous Delivery</span>
</div>
<span class="h-2 w-2 rounded-full bg-secondary"></span>
</div>
<!-- Connected Repo Info -->
<div class="bg-surface-container p-space-md rounded-lg space-y-space-xs shadow-inner">
<div class="flex items-center justify-between">
<span class="font-code-sm text-code-sm text-outline">Repository</span>
<span class="font-code-sm text-code-sm font-semibold text-primary font-mono flex items-center gap-1">
<span aria-hidden="true" class="material-symbols-outlined text-xs">code</span> org/axion-repo
              </span>
</div>
<div class="flex items-center justify-between">
<span class="font-code-sm text-code-sm text-outline">Target Branch</span>
<span class="font-code-sm text-code-sm text-on-surface font-mono">refs/heads/main</span>
</div>
<div class="flex items-center justify-between">
<span class="font-code-sm text-code-sm text-outline">Webhook Listener</span>
<span class="font-code-sm text-code-sm text-secondary font-mono">active: push events</span>
</div>
<div class="flex items-center justify-between">
<span class="font-code-sm text-code-sm text-outline">Build System</span>
<span class="font-code-sm text-code-sm text-on-surface-variant font-mono">Nixpacks 1.18</span>
</div>
</div>
<!-- Secret Config Preview -->
<div class="space-y-space-xs">
<div class="flex items-center justify-between">
<span class="font-label-caps text-label-caps text-outline uppercase">Environment Secrets (5)</span>
<button class="font-code-sm text-code-sm text-primary hover:underline">+ Add Key</button>
</div>
<div class="space-y-1 font-mono text-xs">
<div class="flex items-center justify-between bg-surface-container-lowest px-2.5 py-1.5 rounded">
<span class="text-on-surface font-semibold">DATABASE_URL</span>
<span class="text-outline">••••••••••••••••</span>
</div>
<div class="flex items-center justify-between bg-surface-container-lowest px-2.5 py-1.5 rounded">
<span class="text-on-surface font-semibold">JWT_SIGNING_KEY</span>
<span class="text-outline">••••••••••••••••</span>
</div>
<div class="flex items-center justify-between bg-surface-container-lowest px-2.5 py-1.5 rounded">
<span class="text-on-surface font-semibold">REDIS_PRIVATE_HOST</span>
<span class="text-outline">10.0.4.12:6379</span>
</div>
</div>
</div>
<!-- Manual Re-deploy Action -->
<button class="w-full flex items-center justify-center gap-space-xs py-2 px-space-md rounded-lg bg-surface-container hover:bg-surface-container-high text-on-surface font-body-sm text-body-sm transition-colors" type="button">
<span aria-hidden="true" class="material-symbols-outlined text-base text-primary">play_arrow</span>
<span>Trigger Webhook Manual Build</span>
</button>
</div>
<!-- Resource Distribution Visualization -->
<div class="bg-surface-container-low p-space-lg rounded-xl shadow-md flex flex-col gap-space-md">
<div class="flex items-center justify-between">
<span class="font-headline-md text-headline-md font-semibold text-on-surface">Resource Allotment</span>
<span class="font-code-sm text-code-sm text-outline font-mono">8 GB Host Total</span>
</div>
<!-- RAM Multi-Bar Visualization -->
<div class="space-y-space-xs">
<div class="flex justify-between items-center font-code-sm text-code-sm">
<span class="text-on-surface-variant">Allocated Memory</span>
<span class="font-mono text-on-surface font-semibold">1,510 MB / 8,192 MB (18.4%)</span>
</div>
<!-- Segmented Progress Bar -->
<div class="w-full h-3 bg-surface-container-lowest rounded-full overflow-hidden flex p-0.5 gap-0.5">
<div class="h-full bg-primary rounded-l-full" style="width: 48%;" title="PostgreSQL: 720MB"></div>
<div class="h-full bg-secondary" style="width: 23%;" title="Next.js: 345MB"></div>
<div class="h-full bg-tertiary" style="width: 14%;" title="Fastify API: 210MB"></div>
<div class="h-full bg-error" style="width: 9%;" title="Redis: 140MB"></div>
<div class="h-full bg-primary-fixed" style="width: 6%;" title="BullMQ: 95MB"></div>
</div>
<!-- Legend Grid -->
<div class="grid grid-cols-2 gap-y-1.5 pt-space-xs font-code-sm text-code-sm">
<div class="flex items-center gap-1.5 text-on-surface-variant">
<span class="h-2 w-2 rounded-full bg-primary"></span>
<span class="truncate">Postgres (720M)</span>
</div>
<div class="flex items-center gap-1.5 text-on-surface-variant">
<span class="h-2 w-2 rounded-full bg-secondary"></span>
<span class="truncate">Next.js (345M)</span>
</div>
<div class="flex items-center gap-1.5 text-on-surface-variant">
<span class="h-2 w-2 rounded-full bg-tertiary"></span>
<span class="truncate">Fastify (210M)</span>
</div>
<div class="flex items-center gap-1.5 text-on-surface-variant">
<span class="h-2 w-2 rounded-full bg-error"></span>
<span class="truncate">Redis (140M)</span>
</div>
</div>
</div>
<!-- Inline Node Capacity Graph SVG -->
<div class="p-space-md bg-surface-container rounded-lg flex items-center justify-between">
<div class="space-y-0.5">
<span class="font-label-caps text-label-caps text-outline uppercase">Total vCPU Allotment</span>
<p class="font-headline-md text-headline-md font-bold text-on-surface">17.4% <span class="font-body-sm text-body-sm font-normal text-secondary">Nominal</span></p>
<span class="font-code-sm text-code-sm text-outline">Load Avg: 0.42, 0.38, 0.31</span>
</div>
<!-- Dynamic Mini Area Sparkline -->
<svg class="w-28 h-12 text-primary" fill="none" viewbox="0 0 112 48" xmlns="http://www.w3.org/2000/svg">
<path d="M0 40 L16 34 L32 38 L48 24 L64 28 L80 16 L96 22 L112 12 L112 48 L0 48 Z" fill="currentColor" fill-opacity="0.15"></path>
<path d="M0 40 L16 34 L32 38 L48 24 L64 28 L80 16 L96 22 L112 12" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2"></path>
</svg>
</div>
</div>
</div>
</div>
<!-- Live Recessed Build & Docker Daemon Stream Ticker -->
<div class="bg-surface-container-lowest rounded-xl p-space-md shadow-inner flex flex-col md:flex-row items-start md:items-center justify-between gap-space-md">
<div class="flex items-center gap-space-sm font-code-sm text-code-sm text-outline overflow-hidden">
<span aria-hidden="true" class="material-symbols-outlined text-secondary text-sm shrink-0">terminal</span>
<span class="text-secondary font-mono shrink-0">docker-event.log:</span>
<span class="truncate font-mono text-on-surface-variant">
          [CONTAINER-EVENT] 2026-05-18T14:32:01Z production-api healthcheck: status 200 OK - latency 12ms (healthy)
        </span>
</div>
<div class="flex items-center gap-space-md shrink-0">
<span class="font-code-sm text-code-sm text-outline font-mono">Stream: WebSocket Sync</span>
<button class="font-code-sm text-code-sm text-primary hover:underline">Full Log Viewer →</button>
</div>
</div>
</div>
</div></main>
</section>
</template>
