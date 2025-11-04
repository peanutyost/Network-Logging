<template>
  <div class="ip-search">
    <h1>DNS Lookups by IP</h1>
    
    <div class="search-box">
      <input
        v-model="searchIp"
        @keyup.enter="search"
        type="text"
        placeholder="Enter IP address (e.g., 192.168.1.1 or 2001:db8::1)..."
        class="search-input"
      />
      <button @click="search" class="search-button" :disabled="loading">Search</button>
      <div class="filter-group">
        <label>
          Days to look back:
          <input
            type="number"
            v-model.number="days"
            min="1"
            max="365"
            @change="search"
            class="days-input"
          />
        </label>
      </div>
    </div>

    <div v-if="error" class="error">{{ error }}</div>
    <div v-if="loading" class="loading">Loading...</div>

    <div v-if="results.length > 0" class="results-section">
      <h2>DNS Lookups for {{ searchIp }}</h2>
      <p class="result-count">
        Showing {{ startIndex }} - {{ endIndex }} of {{ totalCount }} DNS lookup{{ totalCount !== 1 ? 's' : '' }}
      </p>
      
      <table class="results-table">
        <thead>
          <tr>
            <th>Domain</th>
            <th>Query Type</th>
            <th>All Resolved IPs</th>
            <th>First Seen</th>
            <th>Last Seen</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="result in results" :key="result.id">
            <td>
              <router-link :to="`/domains?domain=${encodeURIComponent(result.domain)}`" class="domain-link">
                {{ result.domain }}
              </router-link>
            </td>
            <td>{{ result.query_type }}</td>
            <td>
              <div class="ips-list">
                <span 
                  v-for="(ip, idx) in result.resolved_ips" 
                  :key="idx"
                  :class="{'highlight-ip': ip === searchIp}"
                  class="ip-tag"
                >
                  {{ ip }}
                </span>
              </div>
            </td>
            <td>{{ formatDate(result.first_seen || result.query_timestamp) }}</td>
            <td>{{ formatDate(result.last_seen) }}</td>
            <td>
              <router-link 
                :to="`/domains?domain=${encodeURIComponent(result.domain)}`" 
                class="view-link"
              >
                View Details
              </router-link>
            </td>
          </tr>
        </tbody>
      </table>
      
      <!-- Pagination Controls -->
      <div v-if="totalPages > 1" class="pagination">
        <button 
          @click="goToPage(1)" 
          :disabled="currentPage === 1"
          class="page-button"
        >
          First
        </button>
        <button 
          @click="goToPage(currentPage - 1)" 
          :disabled="currentPage === 1"
          class="page-button"
        >
          Previous
        </button>
        <span class="page-info">
          Page {{ currentPage }} of {{ totalPages }}
        </span>
        <button 
          @click="goToPage(currentPage + 1)" 
          :disabled="currentPage === totalPages"
          class="page-button"
        >
          Next
        </button>
        <button 
          @click="goToPage(totalPages)" 
          :disabled="currentPage === totalPages"
          class="page-button"
        >
          Last
        </button>
      </div>
    </div>

    <div v-else-if="!loading && searchIp && hasSearched" class="no-results">
      No DNS lookups found for IP address {{ searchIp }} in the last {{ days }} days.
    </div>
  </div>
</template>

<script>
import api from '../api.js'
import { formatDateInTimezone, getTimezone } from '../utils/timezone.js'

export default {
  name: 'IpSearch',
  data() {
    return {
      searchIp: '',
      results: [],
      loading: false,
      error: null,
      days: 30,
      limit: 1000, // Fixed at 1000 per page
      currentPage: 1,
      totalCount: 0,
      hasSearched: false,
      currentTimezone: getTimezone()
    }
  },
  computed: {
    totalPages() {
      return Math.ceil(this.totalCount / this.limit)
    },
    startIndex() {
      return this.totalCount > 0 ? (this.currentPage - 1) * this.limit + 1 : 0
    },
    endIndex() {
      const end = this.currentPage * this.limit
      return end > this.totalCount ? this.totalCount : end
    }
  },
  mounted() {
    // Check if IP is provided in query params
    const ipParam = this.$route.query.ip
    if (ipParam) {
      this.searchIp = ipParam
      this.search()
    }
    
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
    async search() {
      if (!this.searchIp || !this.searchIp.trim()) {
        this.error = 'Please enter an IP address'
        return
      }
      
      const ip = this.searchIp.trim()
      
      // Basic IP validation
      if (!this.isValidIp(ip)) {
        this.error = 'Please enter a valid IP address (IPv4 or IPv6)'
        this.results = []
        this.hasSearched = false
        this.totalCount = 0
        this.currentPage = 1
        return
      }
      
      // Reset to first page when searching
      this.currentPage = 1
      await this.loadPage()
    },
    async loadPage() {
      if (!this.searchIp || !this.searchIp.trim()) {
        return
      }
      
      const ip = this.searchIp.trim()
      
      // Basic IP validation
      if (!this.isValidIp(ip)) {
        return
      }
      
      this.error = null
      this.loading = true
      this.hasSearched = true
      
      try {
        const offset = (this.currentPage - 1) * this.limit
        const response = await api.getDnsLookupsByIp(ip, this.limit, offset, this.days)
        this.results = response.results || []
        this.totalCount = response.total || 0
      } catch (e) {
        console.error('Error searching DNS lookups by IP', e)
        this.error = e.response?.data?.detail || 'Error searching DNS lookups'
        this.results = []
        this.totalCount = 0
      } finally {
        this.loading = false
      }
    },
    goToPage(page) {
      if (page >= 1 && page <= this.totalPages) {
        this.currentPage = page
        this.loadPage()
      }
    },
    isValidIp(ip) {
      // Basic IPv4 and IPv6 validation
      const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/
      const ipv6Regex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/
      
      if (ipv4Regex.test(ip)) {
        // Validate IPv4 octets
        const parts = ip.split('.')
        return parts.every(part => {
          const num = parseInt(part, 10)
          return num >= 0 && num <= 255
        })
      }
      
      if (ipv6Regex.test(ip)) {
        return true
      }
      
      return false
    },
    formatDate(dateString, formatString = 'MMM dd, yyyy HH:mm:ss') {
      return formatDateInTimezone(dateString, formatString, this.currentTimezone)
    }
  }
}
</script>

<style scoped>
.ip-search {
  padding: 2rem 0;
}

.search-box {
  margin-bottom: 2rem;
  padding: 1.5rem;
  background: white;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.search-input {
  width: 100%;
  padding: 0.75rem;
  font-size: 1rem;
  border: 1px solid #ddd;
  border-radius: 4px;
  margin-bottom: 1rem;
}

.search-button {
  padding: 0.75rem 1.5rem;
  background-color: #007bff;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 1rem;
  margin-bottom: 1rem;
}

.search-button:hover:not(:disabled) {
  background-color: #0056b3;
}

.search-button:disabled {
  background-color: #6c757d;
  cursor: not-allowed;
}

.filter-group {
  display: flex;
  gap: 2rem;
  align-items: center;
}

.filter-group label {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.days-input,
.limit-input {
  width: 80px;
  padding: 0.5rem;
  border: 1px solid #ddd;
  border-radius: 4px;
}

.results-section {
  margin-top: 2rem;
}

.result-count {
  margin: 1rem 0;
  color: #666;
  font-size: 0.9rem;
}

.results-table {
  width: 100%;
  border-collapse: collapse;
  background: white;
  border-radius: 8px;
  overflow: hidden;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.results-table th,
.results-table td {
  padding: 1rem;
  text-align: left;
  border-bottom: 1px solid #eee;
}

.results-table th {
  background-color: #f8f9fa;
  font-weight: 600;
}

.results-table tbody tr:hover {
  background-color: #f8f9fa;
}

.domain-link {
  color: #007bff;
  text-decoration: none;
  font-weight: 500;
}

.domain-link:hover {
  text-decoration: underline;
}

.ips-list {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.ip-tag {
  padding: 0.25rem 0.5rem;
  background-color: #e9ecef;
  border-radius: 4px;
  font-family: monospace;
  font-size: 0.9rem;
}

.highlight-ip {
  background-color: #fff3cd;
  font-weight: 600;
}

.view-link {
  color: #007bff;
  text-decoration: none;
  font-size: 0.9rem;
}

.view-link:hover {
  text-decoration: underline;
}

.error {
  padding: 1rem;
  background-color: #f8d7da;
  color: #721c24;
  border-radius: 4px;
  margin-bottom: 1rem;
}

.loading {
  padding: 2rem;
  text-align: center;
  color: #666;
}

.no-results {
  padding: 2rem;
  text-align: center;
  color: #666;
  background: white;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.pagination {
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 1rem;
  margin-top: 2rem;
  padding: 1rem;
}

.page-button {
  padding: 0.5rem 1rem;
  background-color: #007bff;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.9rem;
}

.page-button:hover:not(:disabled) {
  background-color: #0056b3;
}

.page-button:disabled {
  background-color: #6c757d;
  cursor: not-allowed;
  opacity: 0.6;
}

.page-info {
  font-weight: 500;
  color: #333;
}
</style>

