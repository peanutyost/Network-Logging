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
    
    <!-- Custom Feed Management Section -->
    <div class="custom-feed-section">
      <h2>Custom Threat Feed</h2>
      <div class="custom-feed-card">
        <div class="add-indicator-form">
          <h3>Add Indicator</h3>
          <div class="form-row">
            <label>
              Type:
              <select v-model="newIndicatorType" class="form-select">
                <option value="domain">Domain</option>
                <option value="ip">IP Address</option>
              </select>
            </label>
            <label v-if="newIndicatorType === 'domain'">
              Domain:
              <input 
                type="text" 
                v-model="newDomain" 
                placeholder="example.com"
                class="form-input"
                @keyup.enter="addCustomIndicator"
              />
            </label>
            <label v-if="newIndicatorType === 'ip'">
              IP Address:
              <input 
                type="text" 
                v-model="newIp" 
                placeholder="192.168.1.1"
                class="form-input"
                @keyup.enter="addCustomIndicator"
              />
            </label>
            <button 
              @click="addCustomIndicator" 
              :disabled="addingIndicator || !canAddIndicator"
              class="btn btn-primary"
            >
              {{ addingIndicator ? 'Adding...' : 'Add' }}
            </button>
          </div>
        </div>
        
        <div class="custom-indicators-list" v-if="customFeedIndicators.length > 0">
          <h3>Current Indicators ({{ customFeedIndicators.length }})</h3>
          <div class="indicators-table">
            <table>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Domain/IP</th>
                  <th>Added</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="indicator in customFeedIndicators" :key="indicator.id">
                  <td>{{ indicator.indicator_type }}</td>
                  <td>{{ indicator.domain || indicator.ip }}</td>
                  <td>{{ formatDate(indicator.first_seen) }}</td>
                  <td>
                    <button 
                      @click="removeCustomIndicator(indicator)" 
                      :disabled="removingIndicator === indicator.id"
                      class="btn btn-danger btn-sm"
                    >
                      {{ removingIndicator === indicator.id ? 'Removing...' : 'Remove' }}
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
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
            <div class="info-row" v-if="feed.homepage">
              <span class="label">Homepage:</span>
              <a :href="feed.homepage" target="_blank" rel="noopener noreferrer" class="homepage-link">
                {{ feed.homepage }}
              </a>
            </div>
            
            <div class="info-row">
              <span class="label">Source URL:</span>
              <a :href="feed.source_url" target="_blank" rel="noopener noreferrer">
                {{ feed.source_url }}
              </a>
            </div>
            
            <div class="info-row" v-if="feed.feed_name && feed.feed_name.startsWith('IPsum-L')">
              <span class="label">Threat Level:</span>
              <div class="level-controls">
                <select 
                  :value="feed.config && feed.config.level ? feed.config.level : 1" 
                  @change="updateIpsumLevel(feed.feed_name, parseInt($event.target.value))"
                  :disabled="toggling === feed.feed_name"
                  class="level-select"
                >
                  <option v-for="level in 8" :key="level" :value="level">
                    Level {{ level }}
                  </option>
                </select>
                <span class="level-help">(Higher = more blacklists)</span>
              </div>
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
      lastScanResult: null,
      // Custom feed management
      customFeedName: 'Custom',
      newIndicatorType: 'domain',
      newDomain: '',
      newIp: '',
      addingIndicator: false,
      removingIndicator: null,
      customFeedIndicators: []
    }
  },
  async mounted() {
    window.addEventListener('timezone-changed', this.handleTimezoneChange)
    await this.loadFeeds()
    await this.loadConfig()
    // Load custom feed indicators (non-blocking, fails silently if feed doesn't exist)
    this.loadCustomFeedIndicators().catch(() => {
      // Silently fail if custom feed doesn't exist yet
    })
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
    async updateIpsumLevel(feedName, newLevel) {
      if (newLevel < 1 || newLevel > 8) {
        alert('Level must be between 1 and 8')
        return
      }
      
      // Confirm before changing level (this will delete old IPsum feeds)
      const confirmChange = confirm(
        `Changing IPsum to level ${newLevel} will:\n\n` +
        `- Remove all existing IPsum feeds (including duplicates)\n` +
        `- Create a new feed at level ${newLevel}\n` +
        `- Clear all existing indicators (you'll need to update the feed)\n\n` +
        `Continue?`
      )
      if (!confirmChange) {
        this.loadFeeds() // Reload to reset UI
        return
      }
      
      this.toggling = feedName
      try {
        const result = await api.updateFeedConfig(feedName, { level: newLevel })
        alert(result.message || `IPsum level updated to ${newLevel}. Please update the feed to download new indicators.`)
        this.loadFeeds() // Refresh to show updated feed name
      } catch (error) {
        console.error('Error updating ipsum level:', error)
        alert('Error updating level. Please try again.')
        this.loadFeeds() // Reload to reset UI
      } finally {
        this.toggling = null
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
    },
    async addCustomIndicator() {
      if (!this.canAddIndicator) return
      
      this.addingIndicator = true
      try {
        await api.addCustomIndicator(
          this.customFeedName,
          this.newIndicatorType,
          this.newIndicatorType === 'domain' ? this.newDomain : null,
          this.newIndicatorType === 'ip' ? this.newIp : null
        )
        
        // Clear form
        this.newDomain = ''
        this.newIp = ''
        
        // Reload indicators and feeds
        await this.loadCustomFeedIndicators()
        await this.loadFeeds()
        
        alert('Indicator added successfully!')
      } catch (error) {
        console.error('Error adding custom indicator:', error)
        const errorMsg = error.response?.data?.detail || error.message || 'Unknown error'
        alert(`Error adding indicator: ${errorMsg}`)
      } finally {
        this.addingIndicator = false
      }
    },
    async removeCustomIndicator(indicator) {
      if (!confirm(`Remove ${indicator.indicator_type} '${indicator.domain || indicator.ip}' from custom feed?`)) {
        return
      }
      
      this.removingIndicator = indicator.id
      try {
        await api.removeCustomIndicator(
          this.customFeedName,
          indicator.indicator_type,
          indicator.domain,
          indicator.ip
        )
        
        // Reload indicators and feeds
        await this.loadCustomFeedIndicators()
        await this.loadFeeds()
        
        alert('Indicator removed successfully!')
      } catch (error) {
        console.error('Error removing custom indicator:', error)
        const errorMsg = error.response?.data?.detail || error.message || 'Unknown error'
        alert(`Error removing indicator: ${errorMsg}`)
      } finally {
        this.removingIndicator = null
      }
    },
    async loadCustomFeedIndicators() {
      try {
        const response = await api.getCustomFeedIndicators(this.customFeedName, 1000, 0)
        this.customFeedIndicators = response.indicators || []
      } catch (error) {
        // Feed might not exist yet, that's okay - just set empty array
        // Silently handle errors - feed might not exist yet
        console.debug('Could not load custom feed indicators (feed may not exist yet):', error)
        this.customFeedIndicators = []
      }
    }
  },
  computed: {
    canAddIndicator() {
      if (this.newIndicatorType === 'domain') {
        return this.newDomain.trim().length > 0
      } else {
        return this.newIp.trim().length > 0
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

.homepage-link {
  color: #007bff;
  text-decoration: none;
}

.homepage-link:hover {
  text-decoration: underline;
}

.level-controls {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.level-select {
  padding: 0.25rem 0.5rem;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 0.9rem;
}

.level-select:disabled {
  background-color: #f5f5f5;
  cursor: not-allowed;
}

.level-help {
  color: #666;
  font-size: 0.85rem;
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

.custom-feed-section {
  margin-bottom: 2rem;
}

.custom-feed-section h2 {
  font-size: 1.5rem;
  margin-bottom: 1rem;
  color: #333;
}

.custom-feed-card {
  background: white;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 1.5rem;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.add-indicator-form {
  margin-bottom: 2rem;
}

.add-indicator-form h3 {
  margin: 0 0 1rem 0;
  font-size: 1.1rem;
  color: #333;
}

.form-row {
  display: flex;
  gap: 1rem;
  align-items: flex-end;
  flex-wrap: wrap;
}

.form-row label {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  font-weight: 500;
  color: #333;
}

.form-input,
.form-select {
  padding: 0.5rem;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 0.9rem;
  min-width: 200px;
}

.form-input:focus,
.form-select:focus {
  outline: none;
  border-color: #007bff;
}

.custom-indicators-list {
  margin-top: 2rem;
  padding-top: 2rem;
  border-top: 1px solid #e0e0e0;
}

.custom-indicators-list h3 {
  margin: 0 0 1rem 0;
  font-size: 1.1rem;
  color: #333;
}

.indicators-table {
  overflow-x: auto;
}

.indicators-table table {
  width: 100%;
  border-collapse: collapse;
}

.indicators-table th,
.indicators-table td {
  padding: 0.75rem;
  text-align: left;
  border-bottom: 1px solid #eee;
}

.indicators-table th {
  background-color: #f8f9fa;
  font-weight: 600;
  color: #333;
}

.btn-sm {
  padding: 0.25rem 0.75rem;
  font-size: 0.85rem;
}

.btn-danger {
  background-color: #dc3545;
  color: white;
}

.btn-danger:hover:not(:disabled) {
  background-color: #c82333;
}
</style>
