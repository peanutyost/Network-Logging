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
      <div class="filter-group">
        <label class="filter-checkbox">
          <input
            type="checkbox"
            v-model="filterRfc1918"
            @change="applyFilter"
          />
          Filter RFC 1918 IPs
        </label>
        <label class="filter-checkbox">
          <input
            type="checkbox"
            v-model="filterMulticast"
            @change="applyFilter"
          />
          Filter Multicast IPs
        </label>
      </div>
    </div>

    <div v-if="loading" class="loading">Loading...</div>

    <div class="top-domains">
      <div class="domains-header">
        <h2>External Domains by Traffic (Per Client)</h2>
        <div class="page-size-selector">
          <label>
            Items per page:
            <select v-model.number="itemsPerPage" @change="onPageSizeChange" class="page-size-select">
              <option :value="25">25</option>
              <option :value="50">50</option>
              <option :value="100">100</option>
              <option :value="200">200</option>
            </select>
          </label>
        </div>
      </div>
      
      <div v-if="loading" class="loading">Loading...</div>
      
      <table v-else class="analytics-table">
        <thead>
          <tr>
            <th>Domain</th>
            <th>Client IP</th>
            <th>Total Bytes</th>
            <th>Sent</th>
            <th>Received</th>
            <th>Packets</th>
            <th>Flows</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="stat in filteredStats" :key="`${stat.domain}-${stat.client_ip}`">
            <td>{{ stat.domain }}</td>
            <td>{{ stat.client_ip }}</td>
            <td>{{ formatBytes(stat.total_bytes) }}</td>
            <td>{{ formatBytes(stat.bytes_sent) }}</td>
            <td>{{ formatBytes(stat.bytes_received) }}</td>
            <td>{{ formatNumber(stat.total_packets) }}</td>
            <td>{{ formatNumber(stat.flow_count) }}</td>
          </tr>
        </tbody>
      </table>
      
      <div v-if="!loading && filteredStats.length === 0" class="no-data">
        No external domains found{{ filterRfc1918 || filterMulticast ? ' (after filtering)' : '' }}.
      </div>
      
      <div v-if="totalPages > 1" class="pagination">
        <button 
          @click="goToPage(1)" 
          :disabled="currentPage === 1"
          class="pagination-btn"
        >
          First
        </button>
        <button 
          @click="goToPage(currentPage - 1)" 
          :disabled="currentPage === 1"
          class="pagination-btn"
        >
          Previous
        </button>
        
        <span class="page-info">
          Page {{ currentPage }} of {{ totalPages }} ({{ totalCount }} total)
        </span>
        
        <button 
          @click="goToPage(currentPage + 1)" 
          :disabled="currentPage >= totalPages"
          class="pagination-btn"
        >
          Next
        </button>
        <button 
          @click="goToPage(totalPages)" 
          :disabled="currentPage >= totalPages"
          class="pagination-btn"
        >
          Last
        </button>
      </div>
    </div>
  </div>
</template>

<script>
import api from '../api.js'

export default {
  name: 'TrafficAnalytics',
  data() {
    return {
      stats: [],
      loading: false,
      startDate: null,
      endDate: null,
      filterRfc1918: false,
      filterMulticast: false,
      currentPage: 1,
      itemsPerPage: 50,
      totalCount: 0
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
        const offset = (this.currentPage - 1) * this.itemsPerPage
        
        const response = await api.getStatsPerDomainPerClient(this.itemsPerPage, offset, startTime, endTime, null)
        this.stats = response.stats || []
        this.totalCount = response.total || 0
      } catch (error) {
        console.error('Error loading analytics data:', error)
        this.stats = []
        this.totalCount = 0
      } finally {
        this.loading = false
      }
    },
    goToPage(page) {
      if (page < 1 || page > this.totalPages) return
      this.currentPage = page
      this.loadData()
    },
    onPageSizeChange() {
      // Reset to first page when changing page size
      this.currentPage = 1
      this.loadData()
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
    isRfc1918(ip) {
      if (!ip) return false
      try {
        const ipStr = String(ip).trim()
        if (ipStr.startsWith('10.')) return true
        if (ipStr.startsWith('192.168.')) return true
        if (ipStr.startsWith('172.')) {
          const parts = ipStr.split('.')
          if (parts.length >= 2) {
            const secondOctet = parseInt(parts[1], 10)
            if (secondOctet >= 16 && secondOctet <= 31) return true
          }
        }
        if (ipStr.startsWith('127.')) return true
        if (ipStr.startsWith('169.254.')) return true
        return false
      } catch (e) {
        return false
      }
    },
    isMulticast(ip) {
      if (!ip) return false
      try {
        const ipStr = String(ip).trim()
        if (ipStr === '255.255.255.255') return true
        if (ipStr.includes('.')) {
          const parts = ipStr.split('.')
          if (parts.length >= 1) {
            const firstOctet = parseInt(parts[0], 10)
            if (firstOctet >= 224 && firstOctet <= 239) return true
          }
        }
        if (ipStr.includes(':')) {
          if (ipStr.toLowerCase().startsWith('ff')) return true
        }
        return false
      } catch (e) {
        return false
      }
    },
    applyFilter() {
      this.$forceUpdate()
    }
  },
  computed: {
    filteredStats() {
      let filtered = this.stats
      
      // Filter out entries where domain is actually an IP address (we only want external domains)
      // Also filter by RFC1918 and multicast if enabled
      filtered = filtered.filter(item => {
        const domainOrIp = item.domain
        if (!domainOrIp) return false
        
        // Check if it's an IP address (may have /32 or other CIDR notation)
        // IPv4: matches pattern like 192.168.1.1 or 192.168.1.1/32
        // IPv6: matches pattern with colons, may have /128
        const isIP = /^(\d{1,3}\.){3}\d{1,3}(\/\d+)?$/.test(domainOrIp) || /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(\/\d+)?$/i.test(domainOrIp)
        
        if (isIP) {
          // It's an IP address - exclude it (we only want domains)
          return false
        }
        
        // It's a domain name - keep it for external domains
        // Optionally filter client IPs by RFC1918/multicast if enabled
        if (this.filterRfc1918 || this.filterMulticast) {
          const clientIp = item.client_ip
          if (clientIp) {
            if (this.filterRfc1918 && this.isRfc1918(clientIp)) {
              return false
            }
            if (this.filterMulticast && this.isMulticast(clientIp)) {
              return false
            }
          }
        }
        
        return true
      })
      
      return filtered
    },
    totalPages() {
      return Math.ceil(this.totalCount / this.itemsPerPage) || 1
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
  align-items: center;
  margin-bottom: 2rem;
  flex-wrap: wrap;
}

.controls input {
  padding: 0.5rem;
  border: 1px solid #ddd;
  border-radius: 4px;
}

.filter-group {
  display: flex;
  gap: 1rem;
  align-items: center;
  margin-left: auto;
}

.filter-checkbox {
  display: flex;
  align-items: center;
  gap: 0.5rem;
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

.domains-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1rem;
}

.page-size-selector {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.page-size-select {
  padding: 0.5rem;
  border: 1px solid #ddd;
  border-radius: 4px;
}

.pagination {
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 1rem;
  margin-top: 2rem;
  padding: 1rem;
}

.pagination-btn {
  padding: 0.5rem 1rem;
  border: 1px solid #ddd;
  border-radius: 4px;
  background-color: white;
  cursor: pointer;
  font-size: 0.9rem;
}

.pagination-btn:hover:not(:disabled) {
  background-color: #f8f9fa;
}

.pagination-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.page-info {
  padding: 0.5rem 1rem;
  color: #666;
  font-size: 0.9rem;
}

.no-data {
  text-align: center;
  padding: 2rem;
  color: #666;
}
</style>

