<template>
  <div class="threat-feeds">
    <h1>Threat Intelligence Feeds</h1>
    
    <!-- Configuration Section -->
    <div class="config-section">
      <h2>Threat Detection Settings</h2>
      <div class="config-card">
        <div class="config-row">
          <label for="lookback-days">Historical Scan Lookback (days):</label>
          <input 
            id="lookback-days"
            type="number" 
            v-model.number="lookbackDays" 
            min="1" 
            max="365"
            :disabled="savingConfig"
            class="config-input"
          />
          <button 
            @click="saveConfig" 
            :disabled="savingConfig"
            class="btn btn-primary"
          >
            {{ savingConfig ? 'Saving...' : 'Save' }}
          </button>
        </div>
        <p class="config-help">
          The system will automatically scan the past {{ lookbackDays }} days of DNS history daily 
          to detect any visits to threat feed domains or IPs.
        </p>
        <div class="scan-controls">
          <button 
            @click="triggerScan" 
            :disabled="scanning"
            class="btn btn-secondary"
          >
            {{ scanning ? 'Scanning...' : 'Run Historical Scan Now' }}
          </button>
          <span v-if="lastScanResult" class="scan-result">
            Last scan: {{ lastScanResult.alerts_created }} alerts from {{ lastScanResult.events_scanned }} events
          </span>
        </div>
      </div>
    </div>
    
    <div class="feeds-container">
      <div v-if="loading" class="loading">Loading feeds...</div>
      
      <div v-else-if="feeds.length === 0" class="empty-state">
        <p>No threat feeds configured.</p>
      </div>
      
      <div v-else class="feeds-list">
        <div v-for="feed in feeds" :key="feed.id" class="feed-card">
          <div class="feed-header">
            <h3>{{ feed.feed_name }}</h3>
            <div class="feed-controls">
              <label class="toggle-switch">
                <input 
                  type="checkbox" 
                  :checked="feed.enabled" 
                  @change="toggleFeed(feed.feed_name, $event.target.checked)"
                  :disabled="toggling === feed.feed_name"
                />
                <span class="toggle-slider"></span>
              </label>
              <span :class="['status-badge', feed.enabled ? 'enabled' : 'disabled']">
                {{ feed.enabled ? 'Enabled' : 'Disabled' }}
              </span>
            </div>
          </div>
          
          <div class="feed-info">
            <div class="info-row">
              <span class="label">Source URL:</span>
              <a :href="feed.source_url" target="_blank" rel="noopener noreferrer">
                {{ feed.source_url }}
              </a>
            </div>
            
            <div class="info-row">
              <span class="label">Indicators:</span>
              <span class="value">{{ feed.indicator_count.toLocaleString() }}</span>
            </div>
            
            <div class="info-row" v-if="feed.last_update">
              <span class="label">Last Update:</span>
              <span class="value">{{ formatDate(feed.last_update) }}</span>
            </div>
            
            <div class="info-row" v-if="feed.last_error">
              <span class="label error">Last Error:</span>
              <span class="value error">{{ feed.last_error }}</span>
            </div>
          </div>
          
          <div class="feed-actions">
            <button 
              @click="updateFeed(feed.feed_name)" 
              :disabled="updating === feed.feed_name || !feed.enabled"
              class="btn btn-primary"
            >
              {{ updating === feed.feed_name ? 'Updating...' : 'Update Now' }}
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import api from '../api.js'
import { formatDateInTimezone, getTimezone } from '../utils/timezone.js'

export default {
  name: 'ThreatFeeds',
  data() {
    return {
      feeds: [],
      loading: false,
      updating: null,
      toggling: null,
      currentTimezone: getTimezone(),
      lookbackDays: 30,
      savingConfig: false,
      scanning: false,
      lastScanResult: null
    }
  },
  mounted() {
    this.loadFeeds()
    this.loadConfig()
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
    async loadFeeds() {
      this.loading = true
      try {
        this.feeds = await api.getThreatFeeds()
      } catch (error) {
        console.error('Error loading threat feeds:', error)
        alert('Error loading threat feeds. Please try again.')
      } finally {
        this.loading = false
      }
    },
    async toggleFeed(feedName, enabled) {
      this.toggling = feedName
      try {
        await api.toggleThreatFeed(feedName, enabled)
        // Update local state
        const feed = this.feeds.find(f => f.feed_name === feedName)
        if (feed) {
          feed.enabled = enabled
        }
      } catch (error) {
        console.error('Error toggling feed:', error)
        alert('Error toggling feed. Please try again.')
        // Reload feeds to get correct state
        this.loadFeeds()
      } finally {
        this.toggling = null
      }
    },
    async updateFeed(feedName, force = false) {
      this.updating = feedName
      try {
        const result = await api.updateThreatFeed(feedName, force)
        if (result.success) {
          alert(`Feed updated successfully!\n\nDomains: ${result.domains || 0}\nIPs: ${result.ips || 0}\nTotal Indicators: ${result.indicator_count || 0}`)
          this.loadFeeds() // Refresh feeds
        } else {
          alert(`Failed to update feed: ${result.error || 'Unknown error'}`)
        }
      } catch (error) {
        console.error('Error updating feed:', error)
        if (error.response && error.response.status === 429) {
          // Throttled - ask user if they want to force update
          const forceUpdate = confirm(
            `${error.response.data?.detail || 'Feed was updated recently. Minimum 3 hours required between updates.'}\n\n` +
            'Do you want to force update anyway?'
          )
          if (forceUpdate) {
            // Retry with force flag
            this.updateFeed(feedName, true)
            return
          }
        } else {
          alert('Error updating feed. Please try again.')
        }
      } finally {
        this.updating = null
      }
    },
    formatDate(dateString) {
      return formatDateInTimezone(dateString, 'MMM dd, yyyy HH:mm:ss', this.currentTimezone)
    },
    async loadConfig() {
      try {
        const config = await api.getThreatConfig()
        this.lookbackDays = config.lookback_days || 30
      } catch (error) {
        console.error('Error loading threat config:', error)
      }
    },
    async saveConfig() {
      if (this.lookbackDays < 1 || this.lookbackDays > 365) {
        alert('Lookback days must be between 1 and 365')
        return
      }
      this.savingConfig = true
      try {
        await api.updateThreatConfig(this.lookbackDays)
        alert('Configuration saved successfully!')
      } catch (error) {
        console.error('Error saving config:', error)
        alert('Error saving configuration. Please try again.')
      } finally {
        this.savingConfig = false
      }
    },
    async triggerScan() {
      if (this.scanning) return
      
      // Warn user that scan may take a while
      const proceed = confirm(
        `Start historical threat scan?\n\n` +
        `This will scan the past ${this.lookbackDays} days of DNS history.\n` +
        `This may take several minutes depending on the amount of data.\n\n` +
        `Continue?`
      )
      if (!proceed) return
      
      this.scanning = true
      this.lastScanResult = null
      const startTime = Date.now()
      
      try {
        const result = await api.scanHistoricalThreats(this.lookbackDays)
        const duration = ((Date.now() - startTime) / 1000).toFixed(1)
        this.lastScanResult = result
        if (result.success) {
          alert(
            `Historical scan complete! (took ${duration}s)\n\n` +
            `Events scanned: ${result.events_scanned.toLocaleString()}\n` +
            `Domains checked: ${result.domains_checked.toLocaleString()}\n` +
            `IPs checked: ${result.ips_checked.toLocaleString()}\n` +
            `New alerts created: ${result.alerts_created.toLocaleString()}`
          )
        } else {
          alert('Scan completed but may have encountered errors. Check logs for details.')
        }
      } catch (error) {
        console.error('Error triggering scan:', error)
        if (error.code === 'ECONNABORTED' || error.message?.includes('timeout')) {
          alert(
            `Scan timed out after 5 minutes.\n\n` +
            `The scan may still be running on the server. Please check the server logs.\n` +
            `For large datasets, consider reducing the lookback period.`
          )
        } else {
          const errorMsg = error.response?.data?.detail || error.message || 'Unknown error occurred'
          alert(`Historical scan failed: ${errorMsg}\n\nPlease check the server logs for more details.`)
        }
      } finally {
        this.scanning = false
      }
    }
  }
}
</script>

<style scoped>
.threat-feeds {
  padding: 2rem 0;
}

.feeds-container {
  margin-top: 2rem;
}

.loading {
  text-align: center;
  padding: 3rem;
  color: #666;
}

.empty-state {
  text-align: center;
  padding: 3rem;
  color: #666;
}

.config-section {
  margin-bottom: 2rem;
}

.config-section h2 {
  font-size: 1.5rem;
  margin-bottom: 1rem;
  color: #333;
}

.config-card {
  background: white;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 1.5rem;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.config-row {
  display: flex;
  align-items: center;
  gap: 1rem;
  margin-bottom: 1rem;
}

.config-row label {
  font-weight: 500;
  color: #333;
  white-space: nowrap;
}

.config-input {
  padding: 0.5rem;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 1rem;
  width: 100px;
}

.config-input:disabled {
  background-color: #f5f5f5;
  cursor: not-allowed;
}

.config-help {
  color: #666;
  font-size: 0.9rem;
  margin-bottom: 1rem;
}

.scan-controls {
  display: flex;
  align-items: center;
  gap: 1rem;
  margin-top: 1rem;
}

.scan-result {
  color: #666;
  font-size: 0.9rem;
}

.btn {
  padding: 0.5rem 1rem;
  border: none;
  border-radius: 4px;
  font-size: 0.9rem;
  cursor: pointer;
  transition: background-color 0.2s;
}

.btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-primary {
  background-color: #007bff;
  color: white;
}

.btn-primary:hover:not(:disabled) {
  background-color: #0056b3;
}

.btn-secondary {
  background-color: #6c757d;
  color: white;
}

.btn-secondary:hover:not(:disabled) {
  background-color: #545b62;
}

.feeds-list {
  display: grid;
  gap: 1.5rem;
}

.feed-card {
  background: white;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 1.5rem;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.feed-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1rem;
}

.feed-header h3 {
  margin: 0;
  font-size: 1.25rem;
  color: #333;
}

.feed-controls {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.toggle-switch {
  position: relative;
  display: inline-block;
  width: 50px;
  height: 24px;
}

.toggle-switch input {
  opacity: 0;
  width: 0;
  height: 0;
}

.toggle-slider {
  position: absolute;
  cursor: pointer;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: #ccc;
  transition: .4s;
  border-radius: 24px;
}

.toggle-slider:before {
  position: absolute;
  content: "";
  height: 18px;
  width: 18px;
  left: 3px;
  bottom: 3px;
  background-color: white;
  transition: .4s;
  border-radius: 50%;
}

.toggle-switch input:checked + .toggle-slider {
  background-color: #28a745;
}

.toggle-switch input:checked + .toggle-slider:before {
  transform: translateX(26px);
}

.toggle-switch input:disabled + .toggle-slider {
  opacity: 0.6;
  cursor: not-allowed;
}

.status-badge {
  padding: 0.25rem 0.75rem;
  border-radius: 12px;
  font-size: 0.875rem;
  font-weight: 500;
}

.status-badge.enabled {
  background: #d4edda;
  color: #155724;
}

.status-badge.disabled {
  background: #f8d7da;
  color: #721c24;
}

.feed-info {
  margin-bottom: 1rem;
}

.info-row {
  display: flex;
  margin-bottom: 0.5rem;
  gap: 0.5rem;
}

.info-row .label {
  font-weight: 500;
  color: #666;
  min-width: 120px;
}

.info-row .label.error {
  color: #dc3545;
}

.info-row .value {
  color: #333;
}

.info-row .value.error {
  color: #dc3545;
}

.info-row a {
  color: #007bff;
  text-decoration: none;
}

.info-row a:hover {
  text-decoration: underline;
}

.feed-actions {
  margin-top: 1rem;
  padding-top: 1rem;
  border-top: 1px solid #e0e0e0;
}

.btn {
  padding: 0.5rem 1rem;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.875rem;
  font-weight: 500;
  transition: background 0.2s;
}

.btn-primary {
  background: #007bff;
  color: white;
}

.btn-primary:hover:not(:disabled) {
  background: #0056b3;
}

.btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}
</style>
