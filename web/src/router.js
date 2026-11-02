import { createRouter, createWebHashHistory } from 'vue-router'
import Overview from './views/OverviewView.vue'
import Containers from './views/ContainersView.vue'
import Security from './views/SecurityView.vue'
import Terminal from './views/TerminalView.vue'
import Nodes from './views/NodesView.vue'
import Websites from './views/WebsitesView.vue'
import Databases from './views/DatabasesView.vue'
import Ssl from './views/SslView.vue'
import Files from './views/FilesView.vue'
import Cron from './views/CronView.vue'
import Login from './views/LoginView.vue'
import Settings from './views/SettingsView.vue'
export default createRouter({ history: createWebHashHistory(), routes: [
  { path: '/', redirect: '/overview' },
  { path: '/overview', component: Overview },
  { path: '/websites', component: Websites },
  { path: '/databases', component: Databases },
  { path: '/ssl', component: Ssl },
  { path: '/files', component: Files },
  { path: '/cron', component: Cron },
  { path: '/containers', component: Containers },
  { path: '/security', component: Security },
  { path: '/terminal', component: Terminal },
  { path: '/nodes', component: Nodes },
  { path: '/login', component: Login },
  { path: '/settings', component: Settings },
  { path: '/:pathMatch(.*)*', redirect: '/overview' },
] })
