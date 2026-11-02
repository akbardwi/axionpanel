"""Generate the four supplied Stitch views; originals stay untouched in docs/design/reference.
Run manually when importing updated exports. No external script or inline event handler
from the supplied HTML is executed. All original data is explicitly example data.
"""
from pathlib import Path
import re
root = Path(__file__).resolve().parents[1]
source = root / 'docs/design/reference'
out = root / 'web/src/views'
out.mkdir(parents=True, exist_ok=True)
for folder, name in [('server_overview_metrics','Overview'),('containers_deploy','Containers'),('security_backups','Security'),('terminal_logs','Terminal')]:
    html = (source / folder / 'code.html').read_text()
    start = html.index('<main')
    end = html.index('</main>', start) + len('</main>')
    html = html[start:end]
    html = re.sub(r'<script\b[^>]*>.*?</script>', '', html, flags=re.S)
    html = re.sub(r'\s+on\w+="[^"]*"', '', html)
    # Stop Vue interpolation on literal shell output, and prevent form navigation.
    html = re.sub(r'<main\b', '<main @click="previewAction" @submit.prevent v-pre', html, count=1)
    # v-pre blocks all Vue handlers too; put delegation on the surrounding section instead.
    html = html.replace('<main @click="previewAction" @submit.prevent v-pre', '<main v-pre')
    html = re.sub(r'<img\b[^>]*>', '', html)
    html = html.replace('<span class="material-symbols-outlined', '<span aria-hidden="true" class="material-symbols-outlined')
    html = html.replace('NexusVPS', 'AxionPanel').replace('Nexus Mesh Cluster', 'Managed Nodes')
    html = html.replace('Nexus', 'Axion').replace('nexus', 'axion')
    html = re.sub(r'Raft Consensus:.*?</strong>', 'Example host group · independent managed nodes', html, flags=re.S) # no Raft implementation claim
    html = html.replace('sgp-core-node-01', 'node-01').replace('103.14.88.24', '203.0.113.10')
    html = html.replace('sgp-core-node', 'node').replace('root@axion-node', 'root@node-01')
    html = html.replace('May 18', 'Nov 02').replace('2025', '2026')
    html = re.sub(r'<span[^>]*>UFW</span>', '<span>nftables</span>', html)
    html = html.replace('UFW Firewall &amp; Network Rules', 'Host Firewall &amp; Network Rules')
    html = html.replace('UFW Daemon:', 'Firewall adapter:').replace('UFW (Uncomplicated Firewall)', 'Host Firewall')
    # No hypervisor snapshots, security scores or encryption promises in the implementation preview.
    html = html.replace('Create Snapshot', 'Create Backup').replace('Hot Snapshot', 'Backup job')
    html = html.replace('Full Host OS + Docker Volumes', 'Selected files + database dumps + named volumes')
    html = html.replace('Restore Instance', 'Restore Backup').replace('SECURITY SCORE', 'EXAMPLE SCORE')
    html = html.replace('WS/TLS 1.3 SECURE', 'TERMINAL DESIGN PREVIEW')
    html = html.replace('STREAM ACTIVE', 'EXAMPLE STREAM').replace('CONNECTED (PORT 2222)', 'NOT CONNECTED')
    html = html.replace('Updated Realtime (1s tick)', 'Example telemetry · not live')
    html = re.sub(r'(?i)fitbit', 'security', html)
    # The source ligature 'security_jumping_jacks' is not in our bundled Material Symbols font.
    html = html.replace('security_jumping_jacks', 'shield_lock')
    script = '''<script setup>
import { ref } from 'vue'
const notice = ref('')
function previewAction(event) {
  const target = event.target.closest('button, a, input[type=checkbox]')
  if (!target) return
  event.preventDefault()
  notice.value = 'Preview only — no command was sent to a server.'
}
</script>
'''
    wrapped = '''<template>
<section @click="previewAction" @submit.prevent>
<div v-if="notice" class="preview-notice" role="status">{{ notice }} <button class="ax-btn ax-btn-ghost" @click.stop="notice = ''">Dismiss</button></div>
''' + html + '\n</section>\n</template>\n'
    (out / (name + 'View.vue')).write_text(script + wrapped)
# Tailwind config from the exact semantic palette created during the review.
config = (root / 'docs/design/screens/assets/tailwind-config.js').read_text()
config = config.replace('tailwind.config = {', 'export default {\n  content: [\'./index.html\', \'./src/**/*.{vue,js}\'],')
(root / 'web/tailwind.config.js').write_text(config)
css = (root / 'docs/design/screens/assets/axion.css').read_text()
(root / 'web/src/style.css').write_text('@tailwind base;\n@tailwind components;\n@tailwind utilities;\n' + css)
print('Generated 4 source-derived views, Tailwind configuration and token CSS.')
