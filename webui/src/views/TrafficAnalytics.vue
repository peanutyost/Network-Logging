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
        <h2>Traffic Analytics (Grouped by Destination & Source)</h2>
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
      
      <div v-else-if="!loading && allStats.length === 0" class="no-data">
        No traffic data available. Try adjusting the date range or check if packet capture is running.
      </div>
      
      <table v-else-if="!loading && paginatedStats.length > 0" class="analytics-table">
        <thead>
          <tr>
            <th style="width: 30px;"></th>
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
          <template v-for="group in paginatedStats" :key="`${group.domain}-${group.client_ip}`">
            <tr 
              class="group-row" 
              :class="{ 'expanded': expandedGroups.has(`${group.domain}-${group.client_ip}`) }"
              @click="toggleGroup(group)"
            >
              <td class="expand-icon">
                <span v-if="group.flows && group.flows.length > 0">
                  {{ expandedGroups.has(`${group.domain}-${group.client_ip}`) ? '▼' : '▶' }}
                </span>
              </td>
              <td>{{ group.domain }}</td>
              <td>{{ group.client_ip }}</td>
              <td>{{ formatBytes(group.total_bytes) }}</td>
              <td>{{ formatBytes(group.bytes_sent) }}</td>
              <td>{{ formatBytes(group.bytes_received) }}</td>
              <td>{{ formatNumber(group.total_packets) }}</td>
              <td>{{ formatNumber(group.flow_count) }}</td>
            </tr>
            <tr 
              v-if="expandedGroups.has(`${group.domain}-${group.client_ip}`) && group.flows && group.flows.length > 0" 
              class="detail-row"
            >
              <td colspan="8" class="detail-cell">
                <table class="flows-table">
                  <thead>
                    <tr>
                      <th>Server IP</th>
                      <th>Port</th>
                      <th>Protocol</th>
                      <th>Total Bytes</th>
                      <th>Sent</th>
                      <th>Received</th>
                      <th>Packets</th>
                      <th>Last Seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="flow in group.flows" :key="`${flow.server_ip}-${flow.server_port}-${flow.protocol}`">
                      <td>{{ flow.server_ip }}</td>
                      <td>{{ flow.server_port }}</td>
                      <td>{{ flow.protocol }}</td>
                      <td>{{ formatBytes(flow.total_bytes) }}</td>
                      <td>{{ formatBytes(flow.bytes_sent) }}</td>
                      <td>{{ formatBytes(flow.bytes_received) }}</td>
                      <td>{{ formatNumber(flow.total_packets) }}</td>
                      <td>{{ formatDate(flow.last_seen) }}</td>
                    </tr>
                  </tbody>
                </table>
              </td>
            </tr>
          </template>
        </tbody>
      </table>
      
      <div v-else-if="!loading && paginatedStats.length === 0 && filteredStats.length === 0 && allStats.length > 0" class="no-data">
        No external domains found{{ filterRfc1918 || filterMulticast ? ' (after filtering)' : '' }}.
      </div>
      <div v-else-if="!loading && paginatedStats.length === 0 && filteredStats.length > 0" class="no-data">
        No results on this page. Please go to a previous page.
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
      allStats: [], // Store all loaded stats before filtering
      loading: false,
      startDate: null,
      endDate: null,
      filterRfc1918: false,
      filterMulticast: false,
      currentPage: 1,
      itemsPerPage: 50,
      expandedGroups: new Set() // Track which groups are expanded
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
        
        // Load data in chunks (API limit is 1000 per request)
        // We'll load multiple pages to get as much data as possible for client-side filtering
        const allStats = []
        const pageSize = 1000
        let offset = 0
        let hasMore = true
        
        while (hasMore) {
          const response = await api.getStatsPerDomainPerClient(pageSize, offset, startTime, endTime, null)
          const stats = response.stats || []
          allStats.push(...stats)
          
          // If we got fewer results than requested, we've reached the end
          if (stats.length < pageSize) {
            hasMore = false
          } else {
            offset += pageSize
            // Limit to reasonable number of pages to avoid infinite loops
            if (offset >= 10000) {
              hasMore = false
            }
          }
        }
        
        this.allStats = allStats
        
        // Reset to first page when data is reloaded
        this.currentPage = 1
        
        // Clear expanded groups when data is reloaded
        this.expandedGroups.clear()
        
        console.log(`Loaded ${allStats.length} stats entries`)
      } catch (error) {
        console.error('Error loading analytics data:', error)
        console.error('Error details:', error.response?.data || error.message)
        this.allStats = []
      } finally {
        this.loading = false
      }
    },
    goToPage(page) {
      if (page < 1 || page > this.totalPages) return
      this.currentPage = page
      // Don't reload data - pagination is done client-side on already loaded data
    },
    onPageSizeChange() {
      // Reset to first page when changing page size
      this.currentPage = 1
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
      // Reset to first page when filters change
      this.currentPage = 1
      this.$forceUpdate()
    },
    toggleGroup(group) {
      const key = `${group.domain}-${group.client_ip}`
      if (this.expandedGroups.has(key)) {
        this.expandedGroups.delete(key)
      } else {
        this.expandedGroups.add(key)
      }
      this.$forceUpdate()
    },
    formatDate(dateString) {
      if (!dateString) return ''
      const date = new Date(dateString)
      return date.toLocaleString()
    }
  },
  computed: {
    filteredStats() {
      let filtered = this.allStats
      
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
    groupedStats() {
      // Group flows by domain and client_ip
      const groups = new Map()
      
      this.filteredStats.forEach(flow => {
        const key = `${flow.domain}-${flow.client_ip}`
        
        if (!groups.has(key)) {
          groups.set(key, {
            domain: flow.domain,
            client_ip: flow.client_ip,
            total_bytes: 0,
            bytes_sent: 0,
            bytes_received: 0,
            total_packets: 0,
            flow_count: 0,
            flows: []
          })
        }
        
        const group = groups.get(key)
        group.total_bytes += flow.total_bytes || 0
        group.bytes_sent += flow.bytes_sent || 0
        group.bytes_received += flow.bytes_received || 0
        group.total_packets += flow.total_packets || 0
        group.flow_count += flow.flow_count || 1
        group.flows.push({
          server_ip: flow.server_ip,
          server_port: flow.server_port,
          protocol: flow.protocol,
          total_bytes: flow.total_bytes || 0,
          bytes_sent: flow.bytes_sent || 0,
          bytes_received: flow.bytes_received || 0,
          total_packets: flow.total_packets || 0,
          last_seen: flow.last_seen
        })
      })
      
      // Convert map to array and sort by total_bytes descending
      return Array.from(groups.values()).sort((a, b) => b.total_bytes - a.total_bytes)
    },
    paginatedStats() {
      // Apply pagination to grouped results
      const start = (this.currentPage - 1) * this.itemsPerPage
      const end = start + this.itemsPerPage
      return this.groupedStats.slice(start, end)
    },
    totalCount() {
      // Total count of grouped results
      return this.groupedStats.length
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

.group-row {
  cursor: pointer;
  transition: background-color 0.2s;
}

.group-row:hover {
  background-color: #f8f9fa;
}

.group-row.expanded {
  background-color: #e9ecef;
}

.expand-icon {
  text-align: center;
  font-size: 0.8rem;
  color: #666;
  user-select: none;
}

.detail-row {
  background-color: #f8f9fa;
}

.detail-cell {
  padding: 1rem !important;
  background-color: #f8f9fa;
}

.flows-table {
  width: 100%;
  border-collapse: collapse;
  background-color: white;
  border-radius: 4px;
  overflow: hidden;
}

.flows-table th {
  background-color: #e9ecef;
  padding: 0.5rem;
  font-size: 0.9rem;
  font-weight: 600;
  text-align: left;
  border-bottom: 1px solid #dee2e6;
}

.flows-table td {
  padding: 0.5rem;
  font-size: 0.9rem;
  border-bottom: 1px solid #f0f0f0;
}

.flows-table tr:last-child td {
  border-bottom: none;
}
</style>

