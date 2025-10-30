<template>
  <div class="dashboard">
    <h1>Dashboard</h1>
    
    <div class="stats-grid">
      <div class="stat-card">
        <h3>DNS Queries</h3>
        <p class="stat-value">{{ formatNumber(stats.dns_queries) }}</p>
        <p class="stat-label">Last {{ stats.period_hours }} hours</p>
      </div>
      
      <div class="stat-card">
        <h3>Total Traffic</h3>
        <p class="stat-value">{{ formatBytes(stats.total_bytes) }}</p>
        <p class="stat-label">Last {{ stats.period_hours }} hours</p>
      </div>
      
      <div class="stat-card">
        <h3>Traffic Flows</h3>
        <p class="stat-value">{{ formatNumber(stats.flow_count) }}</p>
        <p class="stat-label">Last {{ stats.period_hours }} hours</p>
      </div>
      
      <div class="stat-card">
        <h3>Active Connections</h3>
        <p class="stat-value">{{ formatNumber(stats.active_connections) }}</p>
        <p class="stat-label">Last hour</p>
      </div>
    </div>

    <div class="top-domains-section">
      <h2>Top Domains</h2>
      <table class="domains-table">
        <thead>
          <tr>
            <th>Domain</th>
            <th>Total Bytes</th>
            <th>Bytes Sent</th>
            <th>Bytes Received</th>
            <th>Packets</th>
            <th>Last Seen</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="domain in topDomains" :key="domain.domain">
            <td>{{ domain.domain }}</td>
            <td>{{ formatBytes(domain.total_bytes) }}</td>
            <td>{{ formatBytes(domain.bytes_sent) }}</td>
            <td>{{ formatBytes(domain.bytes_received) }}</td>
            <td>{{ formatNumber(domain.total_packets) }}</td>
            <td>{{ formatDate(domain.last_seen) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script>
import api from '../api.js'
import { format, parseISO } from 'date-fns'

export default {
  name: 'Dashboard',
  data() {
    return {
      stats: {
        dns_queries: 0,
        total_bytes: 0,
        flow_count: 0,
        active_connections: 0,
        period_hours: 24
      },
      topDomains: [],
      loading: false
    }
  },
  mounted() {
    this.loadData()
    // Refresh every 30 seconds
    this.interval = setInterval(this.loadData, 30000)
  },
  beforeUnmount() {
    if (this.interval) {
      clearInterval(this.interval)
    }
  },
  methods: {
    async loadData() {
      try {
        this.loading = true
        const [stats, topDomains] = await Promise.all([
          api.getDashboardStats(24),
          api.getTopDomains(10)
        ])
        this.stats = stats
        this.topDomains = topDomains
      } catch (error) {
        console.error('Error loading dashboard data:', error)
      } finally {
        this.loading = false
      }
    },
    formatNumber(num) {
      return new Intl.NumberFormat().format(num)
    },
    formatBytes(bytes) {
      if (bytes === 0) return '0 B'
      const k = 1024
      const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
      const i = Math.floor(Math.log(bytes) / Math.log(k))
      return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i]
    },
    formatDate(dateString) {
      if (!dateString) return 'N/A'
      try {
        return format(parseISO(dateString), 'MMM dd, yyyy HH:mm')
      } catch {
        return dateString
      }
    }
  }
}
</script>

<style scoped>
.dashboard {
  padding: 2rem 0;
}

h1 {
  margin-bottom: 2rem;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 1.5rem;
  margin-bottom: 3rem;
}

.stat-card {
  background: white;
  padding: 1.5rem;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.stat-card h3 {
  color: #666;
  font-size: 0.9rem;
  margin-bottom: 0.5rem;
}

.stat-value {
  font-size: 2rem;
  font-weight: bold;
  color: #2c3e50;
  margin-bottom: 0.25rem;
}

.stat-label {
  color: #999;
  font-size: 0.85rem;
}

.top-domains-section {
  background: white;
  padding: 2rem;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.top-domains-section h2 {
  margin-bottom: 1.5rem;
}

.domains-table {
  width: 100%;
  border-collapse: collapse;
}

.domains-table th,
.domains-table td {
  padding: 0.75rem;
  text-align: left;
  border-bottom: 1px solid #eee;
}

.domains-table th {
  background-color: #f8f9fa;
  font-weight: 600;
  color: #555;
}

.domains-table tr:hover {
  background-color: #f8f9fa;
}
</style>

