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
            <li v-for="ip in domainInfo.resolved_ips" :key="ip">{{ ip }}</li>
          </ul>
        </div>
        <div class="info-item">
          <label>First Seen:</label>
          <span>{{ formatDate(domainInfo.query_timestamp) }}</span>
        </div>
        <div class="info-item">
          <label>Last Seen:</label>
          <span>{{ formatDate(domainInfo.last_seen) }}</span>
        </div>
      </div>

      <div class="traffic-section">
        <h3>Traffic for this Domain</h3>
        <TrafficChart :domain="domainInfo.domain" />
        <TrafficTable :domain="domainInfo.domain" />
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
            <td>{{ result.resolved_ips.join(', ') || 'N/A' }}</td>
            <td>{{ formatDate(result.last_seen) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script>
import api from '../api.js'
import { format, parseISO } from 'date-fns'
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
      loading: false
    }
  },
  methods: {
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
    formatDate(dateString) {
      if (!dateString) return 'N/A'
      try {
        return format(parseISO(dateString), 'MMM dd, yyyy HH:mm')
      } catch {
        return dateString
      }
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
  margin-bottom: 2rem;
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
  gap: 1.5rem fine;
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

.traffic-section {
  margin-top: 2rem;
  padding-top: 2rem;
  border-top: 1px solid #eee;
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

