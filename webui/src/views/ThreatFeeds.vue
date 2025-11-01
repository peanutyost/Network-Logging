<template>
  <div class="threat-feeds">
    <h1>Threat Intelligence Feeds</h1>
    
    <div class="feeds-container">
      <div v-if="loading" class="loading">Loading feeds...</div>
      
      <div v-else-if="feeds.length === 0" class="empty-state">
        <p>No threat feeds configured.</p>
      </div>
      
      <div v-else class="feeds-list">
        <div v-for="feed in feeds" :key="feed.id" class="feed-card">
          <div class="feed-header">
            <h3>{{ feed.feed_name }}</h3>
            <span :class="['status-badge', feed.enabled ? 'enabled' : 'disabled']">
              {{ feed.enabled ? 'Enabled' : 'Disabled' }}
            </span>
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
              :disabled="updating === feed.feed_name"
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
      currentTimezone: getTimezone()
    }
  },
  mounted() {
    this.loadFeeds()
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
    async updateFeed(feedName) {
      this.updating = feedName
      try {
        const result = await api.updateThreatFeed(feedName)
        if (result.success) {
          alert(`Feed updated successfully!\n\nDomains: ${result.domains || 0}\nIPs: ${result.ips || 0}\nTotal Indicators: ${result.indicator_count || 0}`)
          this.loadFeeds() // Refresh feeds
        } else {
          alert(`Failed to update feed: ${result.error || 'Unknown error'}`)
        }
      } catch (error) {
        console.error('Error updating feed:', error)
        alert('Error updating feed. Please try again.')
      } finally {
        this.updating = null
      }
    },
    formatDate(dateString) {
      return formatDateInTimezone(dateString, 'MMM dd, yyyy HH:mm:ss', this.currentTimezone)
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

