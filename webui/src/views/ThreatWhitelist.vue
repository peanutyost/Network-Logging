<template>
  <div class="threat-whitelist">
    <h1>Threat Whitelist</h1>
    <p class="description">Domains and IPs in the whitelist will not trigger threat alerts, even if they appear in threat intelligence feeds.</p>
    
    <div class="actions-bar">
      <button @click="showAddModal = true" class="btn btn-primary">Add to Whitelist</button>
      <div class="filters">
        <label>
          Filter:
          <select v-model="filterType" @change="loadWhitelist">
            <option value="">All</option>
            <option value="domain">Domains</option>
            <option value="ip">IPs</option>
          </select>
        </label>
      </div>
    </div>
    
    <div class="whitelist-container">
      <div v-if="loading" class="loading">Loading whitelist...</div>
      
      <div v-else-if="whitelist.length === 0" class="empty-state">
        <p>No whitelist entries found.</p>
      </div>
      
      <div v-else class="whitelist-table">
        <table>
          <thead>
            <tr>
              <th>Type</th>
              <th>Domain/IP</th>
              <th>Reason</th>
              <th>Added</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="entry in whitelist" :key="entry.id">
              <td>
                <span class="badge" :class="entry.indicator_type">
                  {{ entry.indicator_type.toUpperCase() }}
                </span>
              </td>
              <td>
                <code>{{ entry.domain || entry.ip }}</code>
              </td>
              <td>{{ entry.reason || '—' }}</td>
              <td>{{ formatDate(entry.created_at) }}</td>
              <td>
                <button 
                  @click="removeEntry(entry.id)" 
                  class="btn btn-danger btn-sm"
                  :disabled="removing === entry.id"
                >
                  {{ removing === entry.id ? 'Removing...' : 'Remove' }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
    
    <!-- Add Modal -->
    <div v-if="showAddModal" class="modal-overlay" @click="showAddModal = false">
      <div class="modal-content" @click.stop>
        <div class="modal-header">
          <h2>Add to Whitelist</h2>
          <button @click="showAddModal = false" class="modal-close">&times;</button>
        </div>
        <div class="modal-body">
          <div class="form-group">
            <label>Type:</label>
            <select v-model="newEntry.indicator_type" @change="clearNewEntry">
              <option value="domain">Domain</option>
              <option value="ip">IP Address</option>
            </select>
          </div>
          
          <div class="form-group" v-if="newEntry.indicator_type === 'domain'">
            <label>Domain:</label>
            <input 
              type="text" 
              v-model="newEntry.domain" 
              placeholder="example.com"
              @input="clearNewEntryIp"
            />
          </div>
          
          <div class="form-group" v-if="newEntry.indicator_type === 'ip'">
            <label>IP Address:</label>
            <input 
              type="text" 
              v-model="newEntry.ip" 
              placeholder="192.168.1.1"
              @input="clearNewEntryDomain"
            />
          </div>
          
          <div class="form-group">
            <label>Reason (optional):</label>
            <textarea 
              v-model="newEntry.reason" 
              placeholder="Why is this being whitelisted?"
              rows="3"
            ></textarea>
          </div>
        </div>
        <div class="modal-footer">
          <button @click="showAddModal = false" class="btn btn-secondary">Cancel</button>
          <button 
            @click="addEntry" 
            class="btn btn-primary"
            :disabled="adding || !isValidEntry"
          >
            {{ adding ? 'Adding...' : 'Add' }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import api from '../api.js'
import { formatDateInTimezone, getTimezone } from '../utils/timezone.js'

export default {
  name: 'ThreatWhitelist',
  data() {
    return {
      whitelist: [],
      loading: false,
      removing: null,
      adding: false,
      showAddModal: false,
      filterType: '',
      newEntry: {
        indicator_type: 'domain',
        domain: '',
        ip: '',
        reason: ''
      },
      currentTimezone: getTimezone()
    }
  },
  computed: {
    isValidEntry() {
      if (this.newEntry.indicator_type === 'domain') {
        return this.newEntry.domain && this.newEntry.domain.trim().length > 0
      } else {
        return this.newEntry.ip && this.newEntry.ip.trim().length > 0
      }
    }
  },
  mounted() {
    this.loadWhitelist()
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
    async loadWhitelist() {
      this.loading = true
      try {
        this.whitelist = await api.getThreatWhitelist(200, this.filterType || null)
      } catch (error) {
        console.error('Error loading whitelist:', error)
        alert('Error loading whitelist. Please try again.')
      } finally {
        this.loading = false
      }
    },
    clearNewEntry() {
      this.newEntry.domain = ''
      this.newEntry.ip = ''
      this.newEntry.reason = ''
    },
    clearNewEntryIp() {
      this.newEntry.ip = ''
    },
    clearNewEntryDomain() {
      this.newEntry.domain = ''
    },
    async addEntry() {
      if (!this.isValidEntry) {
        return
      }
      
      this.adding = true
      try {
        await api.addThreatWhitelist({
          indicator_type: this.newEntry.indicator_type,
          domain: this.newEntry.domain || null,
          ip: this.newEntry.ip || null,
          reason: this.newEntry.reason || null
        })
        this.showAddModal = false
        this.clearNewEntry()
        this.loadWhitelist()
        alert('Successfully added to whitelist! All related alerts have been resolved.')
      } catch (error) {
        console.error('Error adding whitelist entry:', error)
        alert(error.response?.data?.detail || 'Error adding whitelist entry. Please try again.')
      } finally {
        this.adding = false
      }
    },
    async removeEntry(whitelistId) {
      if (!confirm('Are you sure you want to remove this entry from the whitelist?')) {
        return
      }
      
      this.removing = whitelistId
      try {
        await api.removeThreatWhitelist(whitelistId)
        this.loadWhitelist()
      } catch (error) {
        console.error('Error removing whitelist entry:', error)
        alert('Error removing whitelist entry. Please try again.')
      } finally {
        this.removing = null
      }
    },
    formatDate(dateString) {
      return formatDateInTimezone(dateString, 'MMM dd, yyyy HH:mm:ss', this.currentTimezone)
    }
  }
}
</script>

<style scoped>
.threat-whitelist {
  padding: 2rem 0;
}

.description {
  color: #666;
  margin-bottom: 2rem;
}

.actions-bar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1.5rem;
}

.filters {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.filters label {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.filters select {
  padding: 0.5rem;
  border: 1px solid #ddd;
  border-radius: 4px;
}

.whitelist-container {
  background: white;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  overflow: hidden;
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

.whitelist-table {
  overflow-x: auto;
}

table {
  width: 100%;
  border-collapse: collapse;
}

thead {
  background: #f5f5f5;
}

th, td {
  padding: 1rem;
  text-align: left;
  border-bottom: 1px solid #e0e0e0;
}

th {
  font-weight: 600;
  color: #333;
}

tbody tr:hover {
  background: #f9f9f9;
}

.badge {
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: bold;
}

.badge.domain {
  background: #e3f2fd;
  color: #1976d2;
}

.badge.ip {
  background: #fff3e0;
  color: #f57c00;
}

code {
  background: #f5f5f5;
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  font-family: 'Courier New', monospace;
  font-size: 0.875rem;
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

.btn-danger {
  background: #dc3545;
  color: white;
}

.btn-danger:hover:not(:disabled) {
  background: #c82333;
}

.btn-secondary {
  background: #6c757d;
  color: white;
}

.btn-secondary:hover {
  background: #545b62;
}

.btn-sm {
  padding: 0.25rem 0.75rem;
  font-size: 0.75rem;
}

.btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: 1000;
}

.modal-content {
  background: white;
  border-radius: 8px;
  width: 90%;
  max-width: 500px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1.5rem;
  border-bottom: 1px solid #e0e0e0;
}

.modal-header h2 {
  margin: 0;
}

.modal-close {
  background: none;
  border: none;
  font-size: 1.5rem;
  cursor: pointer;
  color: #666;
  padding: 0;
  width: 30px;
  height: 30px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-close:hover {
  color: #333;
}

.modal-body {
  padding: 1.5rem;
}

.form-group {
  margin-bottom: 1.5rem;
}

.form-group label {
  display: block;
  margin-bottom: 0.5rem;
  font-weight: 500;
  color: #333;
}

.form-group input,
.form-group select,
.form-group textarea {
  width: 100%;
  padding: 0.5rem;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 0.875rem;
}

.form-group textarea {
  resize: vertical;
  font-family: inherit;
}

.modal-footer {
  display: flex;
  justify-content: flex-end;
  gap: 1rem;
  padding: 1.5rem;
  border-top: 1px solid #e0e0e0;
}
</style>

