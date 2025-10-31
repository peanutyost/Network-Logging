<template>
  <div class="settings-page">
    <h1>User Settings</h1>
    
    <div class="settings-sections">
      <!-- Profile Section -->
      <section class="settings-section">
        <h2>Profile Information</h2>
        <div class="profile-info">
          <div class="info-item">
            <label>Username:</label>
            <span>{{ currentUser?.username || 'N/A' }}</span>
          </div>
          <div class="info-item">
            <label>Email:</label>
            <span>{{ currentUser?.email || 'N/A' }}</span>
          </div>
          <div class="info-item">
            <label>Role:</label>
            <span class="role-badge" :class="currentUser?.is_admin ? 'admin' : 'user'">
              {{ currentUser?.is_admin ? 'Administrator' : 'User' }}
            </span>
          </div>
        </div>
      </section>

      <!-- Password Change Section -->
      <section class="settings-section">
        <h2>Change Password</h2>
        <form @submit.prevent="changePassword" class="password-form">
          <div class="form-group">
            <label for="current-password">Current Password</label>
            <input
              id="current-password"
              v-model="passwordForm.currentPassword"
              type="password"
              required
              placeholder="Enter current password"
            />
          </div>
          <div class="form-group">
            <label for="new-password">New Password</label>
            <input
              id="new-password"
              v-model="passwordForm.newPassword"
              type="password"
              required
              minlength="6"
              placeholder="Enter new password (min 6 characters)"
            />
          </div>
          <div class="form-group">
            <label for="confirm-password">Confirm New Password</label>
            <input
              id="confirm-password"
              v-model="passwordForm.confirmPassword"
              type="password"
              required
              minlength="6"
              placeholder="Confirm new password"
            />
          </div>
          <div v-if="passwordError" class="error-message">{{ passwordError }}</div>
          <div v-if="passwordSuccess" class="success-message">{{ passwordSuccess }}</div>
          <button type="submit" :disabled="changingPassword" class="save-button">
            {{ changingPassword ? 'Changing Password...' : 'Change Password' }}
          </button>
        </form>
      </section>

      <!-- Timezone Section -->
      <section class="settings-section">
        <h2>Timezone Settings</h2>
        <div class="timezone-section">
          <div class="form-group">
            <label for="timezone">Select Timezone</label>
            <select
              id="timezone"
              v-model="selectedTimezone"
              @change="updateTimezone"
              class="timezone-select"
            >
              <optgroup label="Common Timezones">
                <option 
                  v-for="tz in commonTimezones" 
                  :key="tz.value" 
                  :value="tz.value"
                >
                  {{ tz.label }}
                </option>
              </optgroup>
              <optgroup v-if="showAllTimezones" label="All Timezones">
                <option 
                  v-for="tz in allTimezones.filter(tz => !commonTimezones.find(ct => ct.value === tz.value))" 
                  :key="tz.value" 
                  :value="tz.value"
                >
                  {{ tz.label }}
                </option>
              </optgroup>
            </select>
          </div>
          <div class="timezone-info">
            <p><strong>Current timezone:</strong> {{ selectedTimezone }}</p>
            <p><strong>Current time:</strong> {{ currentTime }}</p>
          </div>
          <button @click="showAllTimezones = !showAllTimezones" class="toggle-button">
            {{ showAllTimezones ? 'Hide All Timezones' : 'Show All Timezones' }}
          </button>
        </div>
      </section>
    </div>
  </div>
</template>

<script>
import { ref, onMounted, onUnmounted } from 'vue'
import { getTimezone, setTimezone, getCommonTimezones, getAllTimezones, formatDateInTimezone } from '../utils/timezone.js'
import api from '../api.js'

export default {
  name: 'Settings',
  data() {
    return {
      currentUser: null,
      passwordForm: {
        currentPassword: '',
        newPassword: '',
        confirmPassword: ''
      },
      passwordError: '',
      passwordSuccess: '',
      changingPassword: false,
      selectedTimezone: getTimezone(),
      currentTime: '',
      showAllTimezones: false,
      commonTimezones: getCommonTimezones(),
      allTimezones: getAllTimezones(),
      timeInterval: null
    }
  },
  async mounted() {
    await this.loadCurrentUser()
    this.updateCurrentTime()
    this.timeInterval = setInterval(this.updateCurrentTime, 1000)
    
    // Listen for timezone changes
    window.addEventListener('timezone-changed', this.updateCurrentTime)
  },
  beforeUnmount() {
    if (this.timeInterval) {
      clearInterval(this.timeInterval)
    }
    window.removeEventListener('timezone-changed', this.updateCurrentTime)
  },
  methods: {
    async loadCurrentUser() {
      try {
        this.currentUser = await api.getCurrentUser()
      } catch (err) {
        console.error('Failed to load user:', err)
      }
    },
    async changePassword() {
      this.passwordError = ''
      this.passwordSuccess = ''
      
      // Validate passwords match
      if (this.passwordForm.newPassword !== this.passwordForm.confirmPassword) {
        this.passwordError = 'New passwords do not match'
        return
      }
      
      // Validate minimum length
      if (this.passwordForm.newPassword.length < 6) {
        this.passwordError = 'New password must be at least 6 characters long'
        return
      }
      
      this.changingPassword = true
      try {
        await api.changePassword({
          current_password: this.passwordForm.currentPassword,
          new_password: this.passwordForm.newPassword
        })
        
        this.passwordSuccess = 'Password changed successfully!'
        this.passwordForm = {
          currentPassword: '',
          newPassword: '',
          confirmPassword: ''
        }
        
        // Clear success message after 5 seconds
        setTimeout(() => {
          this.passwordSuccess = ''
        }, 5000)
      } catch (err) {
        this.passwordError = err.response?.data?.detail || 'Failed to change password. Please check your current password.'
      } finally {
        this.changingPassword = false
      }
    },
    updateTimezone() {
      setTimezone(this.selectedTimezone)
      this.updateCurrentTime()
      // Emit event to notify other components
      window.dispatchEvent(new CustomEvent('timezone-changed', { 
        detail: { timezone: this.selectedTimezone } 
      }))
    },
    updateCurrentTime() {
      const now = new Date().toISOString()
      this.currentTime = formatDateInTimezone(now, 'MMM dd, yyyy HH:mm:ss', this.selectedTimezone)
    }
  }
}
</script>

<style scoped>
.settings-page {
  max-width: 800px;
  margin: 0 auto;
  padding: 2rem;
}

h1 {
  color: #2c3e50;
  margin-bottom: 2rem;
  font-size: 2rem;
}

.settings-sections {
  display: flex;
  flex-direction: column;
  gap: 2rem;
}

.settings-section {
  background: white;
  padding: 2rem;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.settings-section h2 {
  color: #2c3e50;
  margin-bottom: 1.5rem;
  font-size: 1.5rem;
  border-bottom: 2px solid #667eea;
  padding-bottom: 0.5rem;
}

.profile-info {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.info-item {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0.75rem;
  background: #f8f9fa;
  border-radius: 4px;
}

.info-item label {
  font-weight: 600;
  color: #555;
  min-width: 100px;
}

.info-item span {
  color: #333;
}

.role-badge {
  padding: 0.25rem 0.75rem;
  border-radius: 4px;
  font-size: 0.85rem;
  font-weight: 500;
}

.role-badge.admin {
  background: #667eea;
  color: white;
}

.role-badge.user {
  background: #95a5a6;
  color: white;
}

.password-form {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.form-group label {
  font-weight: 500;
  color: #333;
}

.form-group input,
.form-group select {
  padding: 0.75rem;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 1rem;
}

.form-group input:focus,
.form-group select:focus {
  outline: none;
  border-color: #667eea;
  box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
}

.timezone-section {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.timezone-select {
  max-width: 400px;
}

.timezone-info {
  padding: 1rem;
  background: #f8f9fa;
  border-radius: 4px;
}

.timezone-info p {
  margin: 0.5rem 0;
  color: #555;
}

.toggle-button {
  align-self: flex-start;
  padding: 0.5rem 1rem;
  background: #f8f9fa;
  border: 1px solid #ddd;
  border-radius: 4px;
  cursor: pointer;
  color: #667eea;
  font-size: 0.9rem;
}

.toggle-button:hover {
  background: #e9ecef;
}

.save-button {
  align-self: flex-start;
  padding: 0.75rem 2rem;
  background: #667eea;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 1rem;
  font-weight: 500;
  transition: background 0.3s;
}

.save-button:hover:not(:disabled) {
  background: #5568d3;
}

.save-button:disabled {
  background: #ccc;
  cursor: not-allowed;
}

.error-message {
  padding: 0.75rem;
  background: #fee;
  color: #e74c3c;
  border-radius: 4px;
  border: 1px solid #fcc;
}

.success-message {
  padding: 0.75rem;
  background: #efe;
  color: #27ae60;
  border-radius: 4px;
  border: 1px solid #cfc;
}
</style>

