import { createApp } from 'vue'
import { createRouter, createWebHistory } from 'vue-router'
import App from './App.vue'
import Dashboard from './views/Dashboard.vue'
import DomainSearch from './views/DomainSearch.vue'
import TrafficAnalytics from './views/TrafficAnalytics.vue'
import ThreatHunting from './views/ThreatHunting.vue'
import DnsQueries from './views/DnsQueries.vue'
import DnsEvents from './views/DnsEvents.vue'
import Login from './views/Login.vue'
import UserManagement from './views/UserManagement.vue'
import Settings from './views/Settings.vue'
import ThreatFeeds from './views/ThreatFeeds.vue'
import ThreatAlerts from './views/ThreatAlerts.vue'
import ThreatWhitelist from './views/ThreatWhitelist.vue'
import api from './api.js'

const routes = [
  { path: '/login', component: Login, meta: { requiresAuth: false } },
  { 
    path: '/', 
    component: Dashboard, 
    meta: { requiresAuth: true } 
  },
  { 
    path: '/domains', 
    component: DomainSearch, 
    meta: { requiresAuth: true } 
  },
  { 
    path: '/dns-queries', 
    component: DnsQueries, 
    meta: { requiresAuth: true } 
  },
  { 
    path: '/dns-events', 
    component: DnsEvents, 
    meta: { requiresAuth: true } 
  },
  { 
    path: '/traffic', 
    component: TrafficAnalytics, 
    meta: { requiresAuth: true } 
  },
  { 
    path: '/threats', 
    component: ThreatHunting, 
    meta: { requiresAuth: true } 
  },
  { 
    path: '/users', 
    component: UserManagement, 
    meta: { requiresAuth: true, requiresAdmin: true } 
  },
  { 
    path: '/settings', 
    component: Settings, 
    meta: { requiresAuth: true } 
  },
  { 
    path: '/threat-feeds', 
    component: ThreatFeeds, 
    meta: { requiresAuth: true, requiresAdmin: true } 
  },
  { 
    path: '/threat-alerts', 
    component: ThreatAlerts, 
    meta: { requiresAuth: true } 
  },
  { 
    path: '/threat-whitelist', 
    component: ThreatWhitelist, 
    meta: { requiresAuth: true, requiresAdmin: true } 
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

// Route guard
router.beforeEach(async (to, from, next) => {
  const token = localStorage.getItem('auth_token')
  const isLoginPage = to.path === '/login'
  
  // If trying to access login page and already logged in, redirect to home
  if (isLoginPage && token) {
    return next('/')
  }
  
  // If route requires auth and no token, redirect to login
  if (to.meta.requiresAuth && !token) {
    return next('/login')
  }
  
  // If route requires admin, check user permissions
  if (to.meta.requiresAdmin && token) {
    try {
      const userStr = localStorage.getItem('user')
      let user = userStr ? JSON.parse(userStr) : null
      
      // If no user in localStorage, fetch it
      if (!user) {
        user = await api.getCurrentUser()
      }
      
      if (!user || !user.is_admin) {
        return next('/')
      }
    } catch (err) {
      // If error fetching user, redirect to login
      return next('/login')
    }
  }
  
  next()
})

const app = createApp(App)
app.use(router)
app.mount('#app')

