<template>
  <div class="domain-detail">
    <div v-if="loading" class="loading">Loading domain information...</div>
    
    <div v-else-if="error" class="error">{{ error }}</div>
    
    <div v-else-if="domainInfo" class="domain-info">
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
  </div>
</template>

<script>
import api from '../api.js'
import { formatDateInTimezone, getTimezone } from '../utils/timezone.js'
import TrafficChart from './TrafficChart.vue'
import TrafficTable from './TrafficTable.vue'

export default {
  name: 'DomainDetail',
  components: {
    TrafficChart,
    TrafficTable
  },
  props: {
    domain: {
      type: String,
      required: true
    }
  },
  data() {
    return {
      domainInfo: null,
      loading: false,
      error: null,
      whoisData: null,
      whoisLoading: false,
      whoisError: null,
      timeRangeHours: 24,
      timeRangeStart: null,
      timeRangeEnd: null,
      currentTimezone: getTimezone()
    }
  },
  mounted() {
    if (this.domain) {
      this.loadDomainInfo()
    }
    this.updateTimeRange()
    window.addEventListener('timezone-changed', this.handleTimezoneChange)
  },
  beforeUnmount() {
    window.removeEventListener('timezone-changed', this.handleTimezoneChange)
  },
  watch: {
    domain() {
      this.loadDomainInfo()
      this.updateTimeRange()
    },
    domainInfo(newDomain) {
      if (newDomain) {
        // Auto-load WHOIS data when domain changes
        this.loadWhoisData(false)
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
    async loadDomainInfo() {
      if (!this.domain) return
      
      this.loading = true
      this.error = null
      
      try {
        this.domainInfo = await api.getDomainInfo(this.domain)
      } catch (error) {
        if (error.response && error.response.status === 404) {
          this.error = `Domain "${this.domain}" not found in database`
        } else {
          this.error = `Error loading domain information: ${error.message}`
        }
        this.domainInfo = null
      } finally {
        this.loading = false
      }
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
    formatDate(dateString, formatString = 'MMM dd, yyyy HH:mm') {
      return formatDateInTimezone(dateString, formatString, this.currentTimezone)
    },
    formatWhoisField(fieldName) {
      // Convert snake_case to Title Case
      return fieldName
        .split('_')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ')
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
  }
}
</script>

<style scoped>
.domain-detail {
  padding: 2rem 0;
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

.loading {
  text-align: center;
  padding: 2rem;
  color: #666;
}
</style>

