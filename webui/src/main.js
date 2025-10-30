import { createApp } from 'vue'
import { createRouter, createWebHistory } from 'vue-router'
import App from './App.vue'
import Dashboard from './views/Dashboard.vue'
import DomainSearch from './views/DomainSearch.vue'
import TrafficAnalytics from './views/TrafficAnalytics.vue'
import ThreatHunting from './views/ThreatHunting.vue'
import DnsQueries from './views/DnsQueries.vue'
import DnsEvents from './views/DnsEvents.vue'

const routes = [
  { path: '/', component: Dashboard },
  { path: '/domains', component: DomainSearch },
  { path: '/dns-queries', component: DnsQueries },
  { path: '/dns-events', component: DnsEvents },
  { path: '/traffic', component: TrafficAnalytics },
  { path: '/threats', component: ThreatHunting }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

const app = createApp(App)
app.use(router)
app.mount('#app')

