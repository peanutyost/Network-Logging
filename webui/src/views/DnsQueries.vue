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

    <div v-if="selectedDomain" class="domain-detail-view">
      <button @click="selectedDomain = null" class="back-button">← Back to List</button>
      <DomainDetail :domain="selectedDomain" />
    </div>

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
        <tr 
          v-for="row in rows" 
          :key="row.id"
          @click="selectDomain(row.domain)"
          class="clickable-row"
        >
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
import { formatDateInTimezone } from '../utils/timezone.js'
import DomainDetail from '../components/DomainDetail.vue'

export default {
  name: 'DnsQueries',
  components: {
    DomainDetail
  },
  data() {
    return {
      rows: [],
      loading: false,
      limit: 200,
      interval: null,
      selectedDomain: null
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
    formatDate(dateString, formatString = 'MMM dd, yyyy HH:mm:ss') {
      return formatDateInTimezone(dateString, formatString)
    },
    selectDomain(domain) {
      this.selectedDomain = domain
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
.clickable-row {
  cursor: pointer;
}
.clickable-row:hover {
  background-color: #f8f9fa;
}
.domain-detail-view {
  margin-top: 2rem;
}
.back-button {
  padding: 0.5rem 1rem;
  background-color: #6c757d;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  margin-bottom: 1rem;
  font-size: 0.9rem;
}
.back-button:hover {
  background-color: #5a6268;
}
.loading { padding: 1rem; color: #666; }
</style>
