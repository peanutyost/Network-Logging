<template>
  <div class="dns-queries">
    <h1>DNS Queries</h1>

    <div class="controls">
      <label>
        Limit:
        <input type="number" v-model.number="limit" min="1" max="1000" @change="loadData" />
      </label>
      <button @click="loadData" :disabled="loading">Refresh</button>
    </div>

    <div v-if="loading" class="loading">Loading...</div>

    <table v-else class="queries-table">
      <thead>
        <tr>
          <th>Domain</th>
          <th>Query Type</th>
          <th>Resolved IPs</th>
          <th>First Seen</th>
          <th>Last Seen</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="row in rows" :key="row.id">
          <td>{{ row.domain }}</td>
          <td>{{ row.query_type }}</td>
          <td>{{ (row.resolved_ips || []).join(', ') }}</td>
          <td>{{ formatDate(row.first_seen || row.query_timestamp) }}</td>
          <td>{{ formatDate(row.last_seen) }}</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script>
import api from '../api.js'
import { format, parseISO } from 'date-fns'

export default {
  name: 'DnsQueries',
  data() {
    return {
      rows: [],
      loading: false,
      limit: 200,
      interval: null
    }
  },
  mounted() {
    this.loadData()
    this.interval = setInterval(this.loadData, 30000)
  },
  beforeUnmount() {
    if (this.interval) clearInterval(this.interval)
  },
  methods: {
    async loadData() {
      try {
        this.loading = true
        this.rows = await api.getRecentDns(this.limit)
      } catch (e) {
        console.error('Error loading DNS queries', e)
      } finally {
        this.loading = false
      }
    },
    formatDate(dateString) {
      if (!dateString) return 'N/A'
      try {
        return format(parseISO(dateString), 'MMM dd, yyyy HH:mm:ss')
      } catch {
        return dateString
      }
    }
  }
}
</script>

<style scoped>
.dns-queries {
  padding: 2rem 0;
}
.controls {
  display: flex;
  gap: 1rem;
  align-items: center;
  margin-bottom: 1rem;
}
.queries-table {
  width: 100%;
  border-collapse: collapse;
}
.queries-table th, .queries-table td {
  padding: 0.75rem;
  border-bottom: 1px solid #eee;
  text-align: left;
}
.queries-table th {
  background-color: #f8f9fa;
}
.loading { padding: 1rem; color: #666; }
</style>
