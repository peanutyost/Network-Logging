<template>
  <div class="traffic-table">
    <table v-if="flows && flows.length > 0">
      <thead>
        <tr>
          <th>Source IP</th>
          <th>Destination IP</th>
          <th>Port</th>
          <th>Protocol</th>
          <th>Bytes Sent</th>
          <th>Bytes Received</th>
          <th>Packets</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="flow in flows" :key="flow.id">
          <td>{{ flow.source_ip }}</td>
          <td>{{ flow.destination_ip }}</td>
          <td>{{ flow.destination_port }}</td>
          <td>{{ flow.protocol }}</td>
          <td>{{ formatBytes(flow.bytes_sent) }}</td>
          <td>{{ formatBytes(flow.bytes_received) }}</td>
          <td>{{ formatNumber(flow.packet_count) }}</td>
        </tr>
      </tbody>
    </table>
    <div v-else class="no-data">No traffic data available</div>
  </div>
</template>

<script>
import api from '../api.js'

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
      flows: []
    }
  },
  mounted() {
    this.loadData()
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
    async loadData() {
      try {
        this.flows = await api.getTrafficByDomain(this.domain, this.startTime, this.endTime)
      } catch (error) {
        console.error('Error loading traffic table data:', error)
        this.flows = []
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
      return new Intl.NumberFormat().format(num)
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

