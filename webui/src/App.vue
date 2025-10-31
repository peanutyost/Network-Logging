<template>
  <div id="app">
    <nav v-if="isAuthenticated" class="navbar">
      <div class="nav-container">
        <h1 class="nav-title">Network Traffic DNS Logger</h1>
        <ul class="nav-links">
          <li><router-link to="/">Dashboard</router-link></li>
          <li><router-link to="/domains">Domain Search</router-link></li>
          <li><router-link to="/dns-queries">DNS Queries</router-link></li>
          <li><router-link to="/dns-events">DNS Events</router-link></li>
          <li><router-link to="/traffic">Traffic Analytics</router-link></li>
          <li><router-link to="/threats">Threat Hunting</router-link></li>
          <li v-if="isAdmin"><router-link to="/users">User Management</router-link></li>
        </ul>
        <div class="nav-right">
          <div v-if="currentUser" class="user-info">
            <span class="username">{{ currentUser.username }}</span>
            <span v-if="currentUser.is_admin" class="admin-badge">Admin</span>
          </div>
          <TimezoneSelector />
          <button @click="handleLogout" class="logout-button">Logout</button>
        </div>
      </div>
    </nav>
    <main class="main-content">
      <router-view />
    </main>
  </div>
</template>

<script>
import TimezoneSelector from './components/TimezoneSelector.vue'
import api from './api.js'

export default {
  name: 'App',
  components: {
    TimezoneSelector
  },
  data() {
    return {
      currentUser: null,
      authToken: localStorage.getItem('auth_token')
    }
  },
  computed: {
    isAuthenticated() {
      return !!this.authToken
    },
    isAdmin() {
      return this.currentUser?.is_admin || false
    }
  },
  watch: {
    $route() {
      this.loadCurrentUser()
    }
  },
  mounted() {
    this.loadCurrentUser()
  },
  methods: {
    async loadCurrentUser() {
      // Check for token in localStorage and update reactive state
      this.authToken = localStorage.getItem('auth_token')
      
      if (this.isAuthenticated) {
        try {
          const userStr = localStorage.getItem('user')
          if (userStr) {
            this.currentUser = JSON.parse(userStr)
          } else {
            this.currentUser = await api.getCurrentUser()
          }
        } catch (err) {
          // Ignore errors, user might not be logged in
          this.currentUser = null
          this.authToken = null
        }
      } else {
        this.currentUser = null
      }
    },
    handleLogout() {
      api.logout()
      this.currentUser = null
      this.authToken = null
      this.$router.push('/login')
    }
  },
  created() {
    // Listen for storage events to update auth state across tabs
    window.addEventListener('storage', (e) => {
      if (e.key === 'auth_token') {
        this.authToken = e.newValue
        if (!e.newValue) {
          this.currentUser = null
        } else {
          this.loadCurrentUser()
        }
      }
    })
    
    // Listen for auth state changes (login/logout in same tab)
    window.addEventListener('auth-state-changed', () => {
      this.loadCurrentUser()
    })
  }
}
</script>

<style>
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
  background-color: #f5f5f5;
}

.navbar {
  background-color: #2c3e50;
  color: white;
  padding: 1rem 0;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.nav-container {
  max-width: 1400px;
  margin: 0 auto;
  padding: 0 2rem;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.nav-right {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.user-info {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  color: white;
}

.username {
  font-weight: 500;
}

.admin-badge {
  background: rgba(255, 255, 255, 0.2);
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  font-size: 0.85rem;
  font-weight: 500;
}

.logout-button {
  padding: 0.5rem 1rem;
  background: rgba(255, 255, 255, 0.1);
  color: white;
  border: 1px solid rgba(255, 255, 255, 0.3);
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.9rem;
  transition: background 0.3s;
}

.logout-button:hover {
  background: rgba(255, 255, 255, 0.2);
}

.nav-title {
  font-size: 1.5rem;
}

.nav-links {
  display: flex;
  list-style: none;
  gap: 2rem;
}

.nav-links a {
  color: white;
  text-decoration: none;
  transition: opacity 0.3s;
}

.nav-links a:hover,
.nav-links a.router-link-active {
  opacity: 0.8;
  border-bottom: 2px solid white;
}

.main-content {
  max-width: 1200px;
  margin: 2rem auto;
  padding: 0 2rem;
}
</style>

