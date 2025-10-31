<template>
  <div class="traffic-analytics">
    <h1>Traffic Analytics</h1>
    
    <div class="controls">
      <input
        type="date"
        v-model="startDate"
        @change="loadData"
      />
      <input
        type="date"
        v-model="endDate"
        @change="loadData"
      />
    </div>

    <div v-if="loading" class="loading">Loading...</div>

    <div class="top-domains">
      <h2>Top Domains by Traffic</h2>
      <table class="analytics-table">
        <thead>
          <tr>
            <th>Domain</th>
            <th>Total Bytes</th>
            <th>Sent</th>
            <th>Received</th>
            <th>Packets</th>
            <th>Connections</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="domain in topDomains" :key="domain.domain">
            <td>{{ domain.domain }}</td>
            <td>{{ formatBytes(domain.total_bytes) }}</td>
            <td>{{ formatBytes(domain.bytes_sent) }}</td>
            <td>{{ formatBytes(domain.bytes_received) }}</td>
            <td>{{ formatNumber(domain.total_packets) }}</td>
            <td>{{ formatNumber(domain.query_count) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script>
import api from '../api.js'

export default {
  name: 'TrafficAnalytics',
  data() {
    return {
      topDomains: [],
      loading: false,
      startDate: null,
      endDate: null
    }
  },
  mounted() {
    this.loadData()
  },
  methods: {
    async loadData() {
      this.loading = true
      try {
        const startTime = this.startDate ? new Date(this.startDate) : null
        const endTime = this.endDate ? new Date(this.endDate) : null
        this.topDomains = await api.getTopDomains(50, startTime, endTime)
      } catch (error) {
        console.error('Error loading analytics data:', error)
      } finally {
        this.loading = false
      }
    },
    formatBytes(bytes) {
      if (bytes === null || bytes === undefined || isNaN(bytes) || bytes === 0) return '0 B'
      const k = 1024
      const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
      const i = Math.floor(Math.log(bytes) / Math.log(k))
      return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i]
    },
    formatNumber(num) {
      return new Intl.NumberFormat().format(num || 0)
    }
  }
}
</script>

<style scoped>
.traffic-analytics {
  padding: 2rem 0;
}

.controls {
  display: flex;
  gap: 1rem;
  margin-bottom: 2rem;
}

.controls input {
  padding: 0.5rem;
  border: 1px solid #ddd;
  border-radius: 4px;
}

.top-domains {
  background: white;
  padding: 2rem;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.analytics-table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 1rem;
}

.analytics-table th,
.analytics-table td {
  padding: 0.75rem;
  text-align: left;
  border-bottom: 1px solid #eee;
}

.analytics-table th {
  background-color: #f8f9fa;
  font-weight: 600;
}

.loading {
  text-align: center;
  padding: 2rem;
  color: #666;
}
</style>

