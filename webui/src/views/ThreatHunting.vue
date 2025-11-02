<template>
  <div class="threat-hunting">
    <h1>Threat Hunting</h1>
    
    <div class="controls">
      <label>
        Days to look back:
        <input
          type="number"
          v-model="days"
          @change="loadData"
          min="1"
          max="365"
        />
      </label>
      <button @click="loadData" class="refresh-button">Refresh</button>
      <button @click="exportCSV" class="export-button">Export CSV</button>
      <label class="filter-checkbox">
        <input
          type="checkbox"
          v-model="filterRfc1918"
          @change="applyFilter"
        />
        Filter RFC 1918 IPs
      </label>
    </div>

    <div v-if="loading" class="loading">Loading orphaned IPs...</div>

    <div class="orphaned-ips">
      <h2>Orphaned IPs (No DNS Match)</h2>
      <p class="description">
        IP addresses that have received traffic but have no DNS entry in the last {{ days }} days.
      </p>
      
      <table class="threat-table">
        <thead>
          <tr>
            <th>Destination IP</th>
            <th>Total Bytes</th>
            <th>Bytes Sent</th>
            <th>Bytes Received</th>
            <th>Packets</th>
            <th>Connections</th>
            <th>First Seen</th>
            <th>Last Seen</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="ip in filteredOrphanedIPs" :key="ip.destination_ip">
            <td>{{ ip.destination_ip }}</td>
            <td>{{ formatBytes(ip.total_bytes) }}</td>
            <td>{{ formatBytes(ip.total_bytes_sent) }}</td>
            <td>{{ formatBytes(ip.total_bytes_received) }}</td>
            <td>{{ formatNumber(ip.total_packets) }}</td>
            <td>{{ formatNumber(ip.connection_count) }}</td>
            <td>{{ formatDate(ip.first_seen) }}</td>
            <td>{{ formatDate(ip.last_seen) }}</td>
          </tr>
        </tbody>
      </table>
      
      <div v-if="filteredOrphanedIPs.length === 0" class="no-data">
        <span v-if="orphanedIPs.length === 0">
          No orphaned IPs found in the last {{ days }} days.
        </span>
        <span v-else>
          No orphaned IPs found after filtering ({{ orphanedIPs.length }} total IPs).
        </span>
      </div>
    </div>
  </div>
</template>

<script>
import api from '../api.js'
import { formatDateInTimezone, getTimezone } from '../utils/timezone.js'

export default {
  name: 'ThreatHunting',
  data() {
    return {
      orphanedIPs: [],
      loading: false,
      days: 7,
      currentTimezone: getTimezone(),
      filterRfc1918: false
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
        this.orphanedIPs = await api.getOrphanedIPs(this.days)
      } catch (error) {
        console.error('Error loading orphaned IPs:', error)
      } finally {
        this.loading = false
      }
    },
    exportCSV() {
      if (this.filteredOrphanedIPs.length === 0) return
      
      const headers = ['Destination IP', 'Total Bytes', 'Bytes Sent', 'Bytes Received', 'Packets', 'Connections', 'First Seen', 'Last Seen']
      const rows = this.filteredOrphanedIPs.map(ip => [
        ip.destination_ip,
        ip.total_bytes,
        ip.total_bytes_sent,
        ip.total_bytes_received,
        ip.total_packets,
        ip.connection_count,
        this.formatDate(ip.first_seen),
        this.formatDate(ip.last_seen)
      ])
      
      const csv = [headers, ...rows].map(row => row.join(',')).join('\n')
      const blob = new Blob([csv], { type: 'text/csv' })
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      const filterSuffix = this.filterRfc1918 ? '-filtered' : ''
      a.download = `orphaned-ips-${new Date().toISOString().split('T')[0]}${filterSuffix}.csv`
      a.click()
      window.URL.revokeObjectURL(url)
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
    },
    isRfc1918(ip) {
      if (!ip) return false
      try {
        // Simple regex check for RFC 1918 IPv4 ranges
        // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        const ipStr = String(ip).trim()
        
        // Check 10.0.0.0/8
        if (ipStr.startsWith('10.')) return true
        
        // Check 192.168.0.0/16
        if (ipStr.startsWith('192.168.')) return true
        
        // Check 172.16.0.0/12 (172.16.0.0 to 172.31.255.255)
        if (ipStr.startsWith('172.')) {
          const parts = ipStr.split('.')
          if (parts.length >= 2) {
            const secondOctet = parseInt(parts[1], 10)
            if (secondOctet >= 16 && secondOctet <= 31) {
              return true
            }
          }
        }
        
        // Also check loopback (127.0.0.0/8) and link-local (169.254.0.0/16)
        if (ipStr.startsWith('127.')) return true
        if (ipStr.startsWith('169.254.')) return true
        
        return false
      } catch (e) {
        return false
      }
    },
    applyFilter() {
      // Filter is applied via computed property
      this.$forceUpdate()
    }
  },
  computed: {
    filteredOrphanedIPs() {
      if (!this.filterRfc1918) {
        return this.orphanedIPs
      }
      return this.orphanedIPs.filter(ip => !this.isRfc1918(ip.destination_ip))
    }
  }
}
</script>

<style scoped>
.threat-hunting {
  padding: 2rem 0;
}

.controls {
  display: flex;
  gap: 1rem;
  align-items: center;
  margin-bottom: 2rem;
}

.controls label {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.filter-checkbox {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-left: auto;
  padding: 0.5rem 1rem;
  background-color: #f8f9fa;
  border-radius: 4px;
  cursor: pointer;
}

.filter-checkbox input[type="checkbox"] {
  width: 18px;
  height: 18px;
  cursor: pointer;
}

.controls input[type="number"] {
  padding: 0.5rem;
  border: 1px solid #ddd;
  border-radius: 4px;
  width: 80px;
}

.refresh-button,
.export-button {
  padding: 0.5rem 1.5rem;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 1rem;
}

.refresh-button {
  background-color: #2c3e50;
  color: white;
}

.export-button {
  background-color: #27ae60;
  color: white;
}

.orphaned-ips {
  background: white;
  padding: 2rem;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.description {
  color: #666;
  margin-bottom: 1rem;
}

.threat-table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 1rem;
}

.threat-table th,
.threat-table td {
  padding: 0.75rem;
  text-align: left;
  border-bottom: 1px solid #eee;
}

.threat-table th {
  background-color: #f8f9fa;
  font-weight: 600;
}

.no-data {
  text-align: center;
  padding: 2rem;
  color: #666;
}
</style>

