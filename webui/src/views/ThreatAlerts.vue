<template>
  <div class="threat-alerts">
    <div class="header">
      <h1>Threat Alerts</h1>
      <div class="controls">
        <label>
          <input type="checkbox" v-model="showResolved" @change="loadAlerts" />
          Show Resolved
        </label>
        <button @click="loadAlerts" class="btn btn-secondary">Refresh</button>
      </div>
    </div>
    
    <div class="stats" v-if="!loading">
      <div class="stat-card">
        <div class="stat-value">{{ totalAlerts }}</div>
        <div class="stat-label">Total Alerts</div>
      </div>
      <div class="stat-card">
        <div class="stat-value unresolved">{{ unresolvedCount }}</div>
        <div class="stat-label">Unresolved</div>
      </div>
    </div>
    
    <div class="alerts-container">
      <div v-if="loading" class="loading">Loading alerts...</div>
      
      <div v-else-if="alerts.length === 0" class="empty-state">
        <p>No threat alerts found.</p>
      </div>
      
      <div v-else class="alerts-list">
        <div 
          v-for="alert in alerts" 
          :key="alert.id" 
          :class="['alert-card', alert.resolved ? 'resolved' : 'unresolved']"
        >
          <div class="alert-header">
            <div class="alert-title">
              <span class="indicator-type">{{ alert.indicator_type.toUpperCase() }}</span>
              <span class="feed-name">{{ alert.feed_name }}</span>
            </div>
            <div class="alert-status">
              <span v-if="alert.resolved" class="status-badge resolved">Resolved</span>
              <span v-else class="status-badge unresolved">Active</span>
            </div>
          </div>
          
          <div class="alert-details">
            <div class="detail-row">
              <span class="label">Domain:</span>
              <span class="value">{{ alert.domain || 'N/A' }}</span>
            </div>
            <div class="detail-row" v-if="alert.ip">
              <span class="label">IP Address:</span>
              <span class="value">{{ alert.ip }}</span>
            </div>
            <div class="detail-row">
              <span class="label">Query Type:</span>
              <span class="value">{{ alert.query_type }}</span>
            </div>
            <div class="detail-row">
              <span class="label">Source IP:</span>
              <span class="value">{{ alert.source_ip }}</span>
            </div>
            <div class="detail-row">
              <span class="label">Detected:</span>
              <span class="value">{{ formatDate(alert.created_at) }}</span>
            </div>
            <div class="detail-row" v-if="alert.resolved_at">
              <span class="label">Resolved:</span>
              <span class="value">{{ formatDate(alert.resolved_at) }}</span>
            </div>
          </div>
          
          <div class="alert-actions" v-if="!alert.resolved">
            <button 
              @click="resolveAlert(alert.id)" 
              class="btn btn-primary"
              :disabled="resolving === alert.id"
            >
              {{ resolving === alert.id ? 'Resolving...' : 'Mark as Resolved' }}
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
  name: 'ThreatAlerts',
  data() {
    return {
      alerts: [],
      loading: false,
      resolving: null,
      showResolved: false,
      currentTimezone: getTimezone()
    }
  },
  computed: {
    totalAlerts() {
      return this.alerts.length
    },
    unresolvedCount() {
      return this.alerts.filter(a => !a.resolved).length
    }
  },
  mounted() {
    this.loadAlerts()
    window.addEventListener('timezone-changed', this.handleTimezoneChange)
    // Auto-refresh every 30 seconds
    this.refreshInterval = setInterval(this.loadAlerts, 30000)
  },
  beforeUnmount() {
    window.removeEventListener('timezone-changed', this.handleTimezoneChange)
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval)
    }
  },
  methods: {
    handleTimezoneChange(event) {
      this.currentTimezone = event.detail?.timezone || getTimezone()
      this.$forceUpdate()
    },
    async loadAlerts() {
      this.loading = true
      try {
        const resolved = this.showResolved ? null : false
        this.alerts = await api.getThreatAlerts(200, null, resolved)
      } catch (error) {
        console.error('Error loading threat alerts:', error)
        alert('Error loading threat alerts. Please try again.')
      } finally {
        this.loading = false
      }
    },
    async resolveAlert(alertId) {
      this.resolving = alertId
      try {
        await api.resolveThreatAlert(alertId)
        // Remove from list or mark as resolved
        const alert = this.alerts.find(a => a.id === alertId)
        if (alert) {
          alert.resolved = true
          alert.resolved_at = new Date().toISOString()
        }
        if (!this.showResolved) {
          // Remove from list if not showing resolved
          this.alerts = this.alerts.filter(a => a.id !== alertId)
        }
      } catch (error) {
        console.error('Error resolving alert:', error)
        alert('Error resolving alert. Please try again.')
      } finally {
        this.resolving = null
      }
    },
    formatDate(dateString) {
      return formatDateInTimezone(dateString, 'MMM dd, yyyy HH:mm:ss', this.currentTimezone)
    }
  }
}
</script>

<style scoped>
.threat-alerts {
  padding: 2rem 0;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 2rem;
}

.header h1 {
  margin: 0;
}

.controls {
  display: flex;
  gap: 1rem;
  align-items: center;
}

.controls label {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  cursor: pointer;
}

.stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
  margin-bottom: 2rem;
}

.stat-card {
  background: white;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 1.5rem;
  text-align: center;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.stat-value {
  font-size: 2rem;
  font-weight: bold;
  color: #333;
  margin-bottom: 0.5rem;
}

.stat-value.unresolved {
  color: #dc3545;
}

.stat-label {
  font-size: 0.875rem;
  color: #666;
}

.alerts-container {
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

.alerts-list {
  display: grid;
  gap: 1rem;
}

.alert-card {
  background: white;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 1.5rem;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.alert-card.unresolved {
  border-left: 4px solid #dc3545;
}

.alert-card.resolved {
  border-left: 4px solid #28a745;
  opacity: 0.7;
}

.alert-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1rem;
}

.alert-title {
  display: flex;
  gap: 0.5rem;
  align-items: center;
}

.indicator-type {
  background: #007bff;
  color: white;
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: bold;
}

.feed-name {
  font-weight: 500;
  color: #666;
}

.status-badge {
  padding: 0.25rem 0.75rem;
  border-radius: 12px;
  font-size: 0.875rem;
  font-weight: 500;
}

.status-badge.resolved {
  background: #d4edda;
  color: #155724;
}

.status-badge.unresolved {
  background: #f8d7da;
  color: #721c24;
}

.alert-details {
  margin-bottom: 1rem;
}

.detail-row {
  display: flex;
  margin-bottom: 0.5rem;
  gap: 0.5rem;
}

.detail-row .label {
  font-weight: 500;
  color: #666;
  min-width: 100px;
}

.detail-row .value {
  color: #333;
}

.alert-actions {
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

.btn-secondary {
  background: #6c757d;
  color: white;
}

.btn-secondary:hover {
  background: #545b62;
}

.btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}
</style>

