<template>
  <div class="dns-events">
    <h1>DNS Events</h1>

    <div class="filters">
      <input v-model="filters.domain" placeholder="Domain contains..." />
      <input v-model="filters.source_ip" placeholder="Source IP" />
      <select v-model="filters.event_type">
        <option value="">All</option>
        <option value="query">Query</option>
        <option value="response">Response</option>
      </select>
      <button @click="loadData" :disabled="loading">Apply</button>
    </div>

    <div class="limit-controls">
      <label>
        Limit:
        <input type="number" v-model.number="limit" min="1" max="5000" @change="loadData" />
      </label>
      <button @click="refresh" :disabled="loading">Refresh</button>
    </div>

    <div v-if="loading" class="loading">Loading...</div>

    <div v-if="selectedDomain" class="domain-detail-view">
      <button @click="selectedDomain = null" class="back-button">← Back to Events</button>
      <DomainDetail :domain="selectedDomain" />
    </div>

    <table v-else class="events-table">
      <thead>
        <tr>
          <th>Time</th>
          <th>Type</th>
          <th>Domain</th>
          <th>QType</th>
          <th>Source IP</th>
          <th>Destination IP</th>
          <th>Resolved IPs</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="e in events" :key="e.id">
          <td>{{ formatDate(e.event_timestamp) }}</td>
          <td>{{ e.event_type }}</td>
          <td 
            v-if="e.domain"
            @click.stop="selectDomain(e.domain)"
            class="clickable-domain"
          >
            {{ e.domain }}
          </td>
          <td v-else>{{ e.domain }}</td>
          <td>{{ e.query_type }}</td>
          <td>{{ e.source_ip }}</td>
          <td>{{ e.destination_ip }}</td>
          <td>{{ formatIps(e.resolved_ips) }}</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script>
import api from '../api.js'
import { formatDateInTimezone, getTimezone } from '../utils/timezone.js'
import DomainDetail from '../components/DomainDetail.vue'

export default {
  name: 'DnsEvents',
  components: {
    DomainDetail
  },
  data() {
    return {
      events: [],
      loading: false,
      limit: 500,
      filters: {
        domain: '',
        source_ip: '',
        event_type: ''
      },
      selectedDomain: null,
      currentTimezone: getTimezone()
    }
  },
  mounted() {
    this.loadData()
    window.addEventListener('timezone-changed', this.handleTimezoneChange)
  },
  beforeUnmount() {
    window.removeEventListener('timezone-changed', this.handleTimezoneChange)
  },
  methods: {
    handleTimezoneChange(event) {
      this.currentTimezone = event.detail?.timezone || getTimezone()
      this.$forceUpdate()
    },
    async loadData() {
      this.loading = true
      try {
        this.events = await api.getDnsEvents({
          limit: this.limit,
          domain: this.filters.domain || null,
          source_ip: this.filters.source_ip || null,
          event_type: this.filters.event_type || null
        })
      } catch (e) {
        console.error('Error loading DNS events', e)
        this.events = []
      } finally {
        this.loading = false
      }
    },
    refresh() {
      this.loadData()
    },
    formatDate(s, formatString = 'MMM dd, yyyy HH:mm:ss') {
      return formatDateInTimezone(s, formatString, this.currentTimezone)
    },
    formatIps(v) {
      if (!v) return ''
      if (Array.isArray(v)) return v.join(', ')
      try { const j = typeof v === 'string' ? JSON.parse(v) : v; return Array.isArray(j) ? j.join(', ') : String(j) } catch { return String(v) }
    },
    selectDomain(domain) {
      if (domain) {
        this.selectedDomain = domain
      }
    }
  }
}
</script>

<style scoped>
.dns-events { padding: 2rem 0; }
.filters, .limit-controls { display: flex; gap: 1rem; align-items: center; margin-bottom: 1rem; }
.events-table { width: 100%; border-collapse: collapse; }
.events-table th, .events-table td { padding: 0.75rem; border-bottom: 1px solid #eee; text-align: left; }
.events-table th { background-color: #f8f9fa; }
.clickable-domain {
  cursor: pointer;
  color: #3498db;
  text-decoration: underline;
}
.clickable-domain:hover {
  color: #2980b9;
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
