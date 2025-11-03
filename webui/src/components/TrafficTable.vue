<template>
  <div class="traffic-table">
    <table v-if="stats && stats.length > 0">
      <thead>
        <tr>
          <th>Client IP</th>
          <th>Total Bytes</th>
          <th>Bytes Sent</th>
          <th>Bytes Received</th>
          <th>Packets</th>
          <th>Flows</th>
          <th>Last Seen</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="stat in stats" :key="`${stat.domain}-${stat.client_ip}`">
          <td>{{ stat.client_ip }}</td>
          <td>{{ formatBytes(stat.total_bytes) }}</td>
          <td>{{ formatBytes(stat.bytes_sent) }}</td>
          <td>{{ formatBytes(stat.bytes_received) }}</td>
          <td>{{ formatNumber(stat.total_packets) }}</td>
          <td>{{ formatNumber(stat.flow_count) }}</td>
          <td>{{ formatDate(stat.last_seen) }}</td>
        </tr>
      </tbody>
    </table>
    <div v-else class="no-data">No traffic data available</div>
  </div>
</template>

<script>
import api from '../api.js'
import { formatDateInTimezone, getTimezone } from '../utils/timezone.js'

export default {
  name: 'TrafficTable',
  props: {
    domain: {
      type: String,
      required: true
    },
    startTime: {
      type: Date,
      default: null
    },
    endTime: {
      type: Date,
      default: null
    }
  },
  data() {
    return {
      stats: [],
      loading: false,
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
  watch: {
    domain() {
      this.loadData()
    },
    startTime() {
      this.loadData()
    },
    endTime() {
      this.loadData()
    }
  },
  methods: {
    handleTimezoneChange(event) {
      this.currentTimezone = event.detail?.timezone || getTimezone()
      this.$forceUpdate()
    },
    async loadData() {
      if (!this.domain) return
      
      this.loading = true
      try {
        const response = await api.getStatsPerDomainPerClient(
          1000, // Large limit to get all clients for this domain
          0,
          this.startTime,
          this.endTime,
          this.domain
        )
        this.stats = response.stats || []
      } catch (error) {
        console.error('Error loading traffic table data:', error)
        this.stats = []
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
    },
    formatDate(dateString, formatString = 'MMM dd, yyyy HH:mm') {
      return formatDateInTimezone(dateString, formatString, this.currentTimezone)
    }
  }
}
</script>

<style scoped>
.traffic-table {
  margin-top: 1rem;
}

table {
  width: 100%;
  border-collapse: collapse;
}

th, td {
  padding: 0.75rem;
  text-align: left;
  border-bottom: 1px solid #eee;
}

th {
  background-color: #f8f9fa;
  font-weight: 600;
}

.no-data {
  text-align: center;
  padding: 2rem;
  color: #666;
}
</style>

