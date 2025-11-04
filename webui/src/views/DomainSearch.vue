<template>
  <div class="domain-search">
    <h1>Domain Search</h1>
    
    <div class="search-box">
      <input
        v-model="searchQuery"
        @keyup.enter="search"
        type="text"
        placeholder="Enter domain name..."
        class="search-input"
      />
      <button @click="search" class="search-button">Search</button>
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

    <div v-if="domainInfo" class="domain-info">
      <h2>{{ domainInfo.domain }}</h2>
      <div class="info-grid">
        <div class="info-item">
          <label>Query Type:</label>
          <span>{{ domainInfo.query_type }}</span>
        </div>
        <div class="info-item">
          <label>Resolved IPs:</label>
          <ul>
            <li v-for="ip in filteredResolvedIPs" :key="ip">{{ ip }}</li>
          </ul>
        </div>
        <div class="info-item">
          <label>First Seen:</label>
          <span>{{ formatDate(domainInfo.first_seen || domainInfo.query_timestamp) }}</span>
        </div>
        <div class="info-item">
          <label>Last Seen:</label>
          <span>{{ formatDate(domainInfo.last_seen) }}</span>
        </div>
      </div>

      <div class="whois-section" v-if="domainInfo">
        <h3>WHOIS Information</h3>
        <div class="whois-controls">
          <button @click="loadWhoisData(false)" class="refresh-whois-btn" :disabled="whoisLoading">
            {{ whoisData ? 'Refresh' : 'Load WHOIS Data' }}
          </button>
          <button @click="loadWhoisData(true)" class="force-refresh-btn" :disabled="whoisLoading">
            Force Refresh
          </button>
        </div>
        <div v-if="whoisLoading" class="loading">Loading WHOIS data...</div>
        <div v-else-if="whoisError" class="error">{{ whoisError }}</div>
        <div v-else-if="whoisData" class="whois-data">
          <div class="whois-meta">
            <span><strong>Last Updated:</strong> {{ formatDate(whoisData.whois_updated_at) }}</span>
            <span><strong>First Retrieved:</strong> {{ formatDate(whoisData.created_at) }}</span>
          </div>
          <div class="whois-fields">
            <div v-for="(value, key) in whoisData.whois_data" :key="key" class="whois-field">
              <label>{{ formatWhoisField(key) }}:</label>
              <span v-if="Array.isArray(value)" class="whois-value-array">
                <span v-for="(item, idx) in value" :key="idx">{{ item }}<span v-if="idx < value.length - 1">, </span></span>
              </span>
              <span v-else class="whois-value">{{ value }}</span>
            </div>
          </div>
        </div>
        <div v-else class="no-whois">
          No WHOIS data available. Click "Load WHOIS Data" to fetch it.
        </div>
      </div>

      <div class="traffic-section">
        <h3>Traffic for this Domain</h3>
        <div class="time-range-controls">
          <label>
            Time Range:
            <select v-model="timeRangeHours" @change="updateTimeRange">
              <option :value="1">Last Hour</option>
              <option :value="6">Last 6 Hours</option>
              <option :value="24">Last 24 Hours</option>
              <option :value="168">Last 7 Days</option>
              <option :value="720">Last 30 Days</option>
              <option value="">All Time</option>
            </select>
          </label>
          <div v-if="timeRangeHours" class="time-range-info">
            Showing data from {{ formatDate(timeRangeStart) }} to {{ formatDate(timeRangeEnd) }}
          </div>
        </div>
        <TrafficChart 
          :domain="domainInfo.domain" 
          :startTime="timeRangeStart"
          :endTime="timeRangeEnd"
        />
        <TrafficTable 
          :domain="domainInfo.domain"
          :startTime="timeRangeStart"
          :endTime="timeRangeEnd"
        />
      </div>
    </div>

    <div v-if="searchResults && searchResults.length > 0 && !domainInfo" class="search-results">
      <h2>Search Results</h2>
      <table class="results-table">
        <thead>
          <tr>
            <th>Domain</th>
            <th>Query Type</th>
            <th>IPs</th>
            <th>Last Seen</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="result in searchResults"
            :key="result.id"
            @click="selectDomain(result.domain)"
            class="clickable-row"
          >
            <td>{{ result.domain }}</td>
            <td>{{ result.query_type }}</td>
            <td>{{ filterIPsList(result.resolved_ips).join(', ') || 'N/A' }}</td>
            <td>{{ formatDate(result.last_seen) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script>
import api from '../api.js'
import { formatDateInTimezone, getTimezone } from '../utils/timezone.js'
import TrafficChart from '../components/TrafficChart.vue'
import TrafficTable from '../components/TrafficTable.vue'

export default {
  name: 'DomainSearch',
  components: {
    TrafficChart,
    TrafficTable
  },
  data() {
    return {
      searchQuery: '',
      searchResults: [],
      domainInfo: null,
      loading: false,
      whoisData: null,
      whoisLoading: false,
      whoisError: null,
      timeRangeHours: 24,
      timeRangeStart: null,
      timeRangeEnd: null,
      currentTimezone: getTimezone(),
      filterRfc1918: false,
      filterMulticast: false
    }
  },
  mounted() {
    this.updateTimeRange()
    window.addEventListener('timezone-changed', this.handleTimezoneChange)
    
    // Check if domain is provided in query params
    const domainParam = this.$route.query.domain
    if (domainParam) {
      this.searchQuery = domainParam
      this.search()
    }
  },
  beforeUnmount() {
    window.removeEventListener('timezone-changed', this.handleTimezoneChange)
  },
  watch: {
    domainInfo(newDomain) {
      if (newDomain) {
        // Auto-load WHOIS data when domain changes
        this.loadWhoisData(false)
        this.updateTimeRange()
      } else {
        this.whoisData = null
        this.whoisError = null
      }
    }
  },
  methods: {
    handleTimezoneChange(event) {
      this.currentTimezone = event.detail?.timezone || getTimezone()
      this.$forceUpdate()
    },
    async search() {
      if (!this.searchQuery.trim()) return
      
      this.loading = true
      this.domainInfo = null
      
      try {
        // First try to get exact domain info
        try {
          this.domainInfo = await api.getDomainInfo(this.searchQuery)
        } catch {
          // If not found, search
          this.searchResults = await api.searchDomains(this.searchQuery)
        }
      } catch (error) {
        console.error('Error searching domains:', error)
      } finally {
        this.loading = false
      }
    },
    async selectDomain(domain) {
      this.searchQuery = domain
      this.domainInfo = null
      this.search()
    },
    formatDate(dateString, formatString = 'MMM dd, yyyy HH:mm') {
      return formatDateInTimezone(dateString, formatString, this.currentTimezone)
    },
    async loadWhoisData(forceRefresh = false) {
      if (!this.domainInfo) return
      
      this.whoisLoading = true
      this.whoisError = null
      
      try {
        this.whoisData = await api.getDomainWhois(this.domainInfo.domain, forceRefresh)
      } catch (error) {
        if (error.response && error.response.status === 404) {
          this.whoisError = 'WHOIS data not available for this domain'
        } else {
          this.whoisError = `Error loading WHOIS data: ${error.message}`
        }
        this.whoisData = null
      } finally {
        this.whoisLoading = false
      }
    },
    formatWhoisField(fieldName) {
      // Convert snake_case to Title Case
      return fieldName
        .split('_')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ')
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
    filterIPsList(ips) {
      if (!ips || !Array.isArray(ips)) return []
      let filtered = [...ips]
      if (this.filterRfc1918) {
        filtered = filtered.filter(ip => !this.isRfc1918(ip))
      }
      if (this.filterMulticast) {
        filtered = filtered.filter(ip => !this.isMulticast(ip))
      }
      return filtered
    },
    applyFilter() {
      this.$forceUpdate()
    },
    updateTimeRange() {
      if (this.timeRangeHours && this.timeRangeHours !== '') {
        const hours = Number(this.timeRangeHours)
        this.timeRangeEnd = new Date()
        this.timeRangeStart = new Date(Date.now() - hours * 60 * 60 * 1000)
      } else {
        this.timeRangeStart = null
        this.timeRangeEnd = null
        this.timeRangeHours = null
      }
    }
  },
  computed: {
    filteredResolvedIPs() {
      if (!this.domainInfo || !this.domainInfo.resolved_ips) return []
      return this.filterIPsList(this.domainInfo.resolved_ips)
    }
  }
}
</script>

<style scoped>
.domain-search {
  padding: 2rem 0;
}

.search-box {
  display: flex;
  gap: 1rem;
  align-items: center;
  margin-bottom: 2rem;
  flex-wrap: wrap;
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

.search-input {
  flex: 1;
  padding: 0.75rem;
  font-size: 1rem;
  border: 1px solid #ddd;
  border-radius: 4px;
}

.search-button {
  padding: 0.75rem 2rem;
  background-color: #2c3e50;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 1rem;
}

.search-button:hover {
  background-color: #34495e;
}

.domain-info {
  background: white;
  padding: 2rem;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
  margin-bottom: 2rem;
}

.info-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 1.5rem;
  margin: 1.5rem 0;
}

.info-item {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.info-item label {
  font-weight: 600;
  color: #666;
  font-size: 0.9rem;
}

.info-item ul {
  list-style: none;
  padding: 0;
  margin: 0;
}

.whois-section {
  margin-top: 2rem;
  padding-top: 2rem;
  border-top: 1px solid #eee;
}

.whois-controls {
  display: flex;
  gap: 1rem;
  margin-bottom: 1rem;
}

.refresh-whois-btn,
.force-refresh-btn {
  padding: 0.5rem 1rem;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.9rem;
  transition: background-color 0.3s;
}

.refresh-whois-btn {
  background-color: #3498db;
  color: white;
}

.refresh-whois-btn:hover:not(:disabled) {
  background-color: #2980b9;
}

.force-refresh-btn {
  background-color: #e67e22;
  color: white;
}

.force-refresh-btn:hover:not(:disabled) {
  background-color: #d35400;
}

.refresh-whois-btn:disabled,
.force-refresh-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.whois-meta {
  display: flex;
  gap: 2rem;
  padding: 1rem;
  background-color: #f8f9fa;
  border-radius: 4px;
  margin-bottom: 1rem;
  font-size: 0.9rem;
}

.whois-data {
  margin-top: 1rem;
}

.whois-fields {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 1rem;
}

.whois-field {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  padding: 0.75rem;
  background-color: #f8f9fa;
  border-radius: 4px;
}

.whois-field label {
  font-weight: 600;
  color: #555;
  font-size: 0.85rem;
}

.whois-value {
  color: #333;
  word-break: break-word;
}

.whois-value-array {
  color: #333;
}

.no-whois,
.error {
  padding: 1rem;
  background-color: #fff3cd;
  border: 1px solid #ffc107;
  border-radius: 4px;
  color: #856404;
  margin-top: 1rem;
}

.error {
  background-color: #f8d7da;
  border-color: #f5c6cb;
  color: #721c24;
}

.traffic-section {
  margin-top: 2rem;
  padding-top: 2rem;
  border-top: 1px solid #eee;
}

.time-range-controls {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  margin-bottom: 1rem;
  padding: 1rem;
  background-color: #f8f9fa;
  border-radius: 4px;
}

.time-range-controls label {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-weight: 600;
}

.time-range-controls select {
  padding: 0.5rem;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 0.9rem;
}

.time-range-info {
  font-size: 0.85rem;
  color: #666;
  font-style: italic;
}

.search-results {
  background: white;
  padding: 2rem;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.results-table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 1rem;
}

.results-table th,
.results-table td {
  padding: 0.75rem;
  text-align: left;
  border-bottom: 1px solid #eee;
}

.results-table th {
  background-color: #f8f9fa;
  font-weight: 600;
}

.clickable-row {
  cursor: pointer;
}

.clickable-row:hover {
  background-color: #f8f9fa;
}

.loading {
  text-align: center;
  padding: 2rem;
  color: #666;
}
</style>

