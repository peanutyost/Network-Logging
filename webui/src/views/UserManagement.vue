<template>
  <div class="user-management">
    <div class="header">
      <h1>User Management</h1>
      <button @click="showCreateModal = true" class="create-button">Create New User</button>
    </div>

    <div v-if="loading" class="loading">Loading users...</div>
    <div v-else-if="error" class="error">{{ error }}</div>
    <div v-else>
      <table class="users-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Username</th>
            <th>Email</th>
            <th>Admin</th>
            <th>Active</th>
            <th>Created</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="user in users" :key="user.id">
            <td>{{ user.id }}</td>
            <td>{{ user.username }}</td>
            <td>{{ user.email }}</td>
            <td>
              <span :class="['badge', user.is_admin ? 'badge-admin' : 'badge-user']">
                {{ user.is_admin ? 'Admin' : 'User' }}
              </span>
            </td>
            <td>
              <span :class="['badge', user.is_active ? 'badge-active' : 'badge-inactive']">
                {{ user.is_active ? 'Active' : 'Inactive' }}
              </span>
            </td>
            <td>{{ formatDate(user.created_at) }}</td>
            <td class="actions">
              <button @click="editUser(user)" class="btn-edit">Edit</button>
              <button
                @click="deleteUser(user.id)"
                :disabled="currentUser?.id === user.id"
                class="btn-delete"
                :title="currentUser?.id === user.id ? 'Cannot delete your own account' : 'Delete user'"
              >
                Delete
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Create/Edit Modal -->
    <div v-if="showCreateModal || showEditModal" class="modal-overlay" @click="closeModal">
      <div class="modal" @click.stop>
        <h2>{{ showEditModal ? 'Edit User' : 'Create New User' }}</h2>
        <form @submit.prevent="saveUser">
          <div class="form-group">
            <label>Username</label>
            <input
              v-model="formData.username"
              type="text"
              required
              minlength="3"
              maxlength="50"
              :disabled="showEditModal"
            />
          </div>
          <div class="form-group">
            <label>Email</label>
            <input v-model="formData.email" type="email" required />
          </div>
          <div class="form-group">
            <label>Password {{ showEditModal ? '(leave blank to keep current)' : '' }}</label>
            <input
              v-model="formData.password"
              type="password"
              :required="!showEditModal"
              minlength="6"
            />
          </div>
          <div class="form-group checkbox-group">
            <label>
              <input v-model="formData.is_admin" type="checkbox" />
              Admin User
            </label>
          </div>
          <div class="form-group checkbox-group">
            <label>
              <input v-model="formData.is_active" type="checkbox" />
              Active
            </label>
          </div>
          <div v-if="saveError" class="error">{{ saveError }}</div>
          <div class="modal-actions">
            <button type="button" @click="closeModal" class="btn-cancel">Cancel</button>
            <button type="submit" :disabled="saving" class="btn-save">
              {{ saving ? 'Saving...' : 'Save' }}
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
</template>

<script>
import api from '../api.js'
import { formatDateInTimezone, getTimezone } from '../utils/timezone.js'

export default {
  name: 'UserManagement',
  data() {
    return {
      users: [],
      loading: false,
      error: '',
      showCreateModal: false,
      showEditModal: false,
      formData: {
        username: '',
        email: '',
        password: '',
        is_admin: false,
        is_active: true
      },
      editingUserId: null,
      saving: false,
      saveError: '',
      currentUser: null,
      currentTimezone: getTimezone()
    }
  },
  mounted() {
    this.loadUsers()
    this.loadCurrentUser()
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
    async loadUsers() {
      this.loading = true
      this.error = ''
      try {
        this.users = await api.getUsers()
      } catch (err) {
        this.error = err.response?.data?.detail || 'Failed to load users'
        if (err.response?.status === 403) {
          this.error = 'You do not have permission to view users'
        }
      } finally {
        this.loading = false
      }
    },
    async loadCurrentUser() {
      try {
        this.currentUser = await api.getCurrentUser()
      } catch (err) {
        // Ignore errors
      }
    },
    formatDate(dateString) {
      return formatDateInTimezone(dateString, 'yyyy-MM-dd HH:mm', this.currentTimezone)
    },
    editUser(user) {
      this.formData = {
        username: user.username,
        email: user.email,
        password: '',
        is_admin: user.is_admin,
        is_active: user.is_active
      }
      this.editingUserId = user.id
      this.showEditModal = true
      this.saveError = ''
    },
    async saveUser() {
      this.saving = true
      this.saveError = ''
      try {
        const userData = {
          username: this.formData.username,
          email: this.formData.email,
          is_admin: this.formData.is_admin,
          is_active: this.formData.is_active
        }
        if (this.formData.password) {
          userData.password = this.formData.password
        }
        if (this.showEditModal) {
          await api.updateUser(this.editingUserId, userData)
        } else {
          await api.createUser(userData)
        }
        await this.loadUsers()
        this.closeModal()
      } catch (err) {
        this.saveError = err.response?.data?.detail || 'Failed to save user'
      } finally {
        this.saving = false
      }
    },
    async deleteUser(userId) {
      if (!confirm('Are you sure you want to delete this user?')) {
        return
      }
      try {
        await api.deleteUser(userId)
        await this.loadUsers()
      } catch (err) {
        alert(err.response?.data?.detail || 'Failed to delete user')
      }
    },
    closeModal() {
      this.showCreateModal = false
      this.showEditModal = false
      this.formData = {
        username: '',
        email: '',
        password: '',
        is_admin: false,
        is_active: true
      }
      this.editingUserId = null
      this.saveError = ''
    }
  }
}
</script>

<style scoped>
.user-management {
  padding: 2rem;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 2rem;
}

h1 {
  color: #2c3e50;
  margin: 0;
}

.create-button {
  padding: 0.75rem 1.5rem;
  background: #667eea;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 1rem;
}

.create-button:hover {
  background: #5568d3;
}

.loading,
.error {
  text-align: center;
  padding: 2rem;
  color: #555;
}

.error {
  color: #e74c3c;
}

.users-table {
  width: 100%;
  border-collapse: collapse;
  background: white;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  border-radius: 4px;
  overflow: hidden;
}

.users-table thead {
  background: #f8f9fa;
}

.users-table th,
.users-table td {
  padding: 1rem;
  text-align: left;
  border-bottom: 1px solid #eee;
}

.users-table th {
  font-weight: 600;
  color: #2c3e50;
}

.users-table tbody tr:hover {
  background: #f8f9fa;
}

.badge {
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  font-size: 0.85rem;
  font-weight: 500;
}

.badge-admin {
  background: #667eea;
  color: white;
}

.badge-user {
  background: #95a5a6;
  color: white;
}

.badge-active {
  background: #27ae60;
  color: white;
}

.badge-inactive {
  background: #e74c3c;
  color: white;
}

.actions {
  display: flex;
  gap: 0.5rem;
}

.btn-edit,
.btn-delete {
  padding: 0.5rem 1rem;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.9rem;
}

.btn-edit {
  background: #3498db;
  color: white;
}

.btn-edit:hover {
  background: #2980b9;
}

.btn-delete {
  background: #e74c3c;
  color: white;
}

.btn-delete:hover:not(:disabled) {
  background: #c0392b;
}

.btn-delete:disabled {
  background: #ccc;
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

.modal {
  background: white;
  border-radius: 8px;
  padding: 2rem;
  width: 90%;
  max-width: 500px;
  max-height: 90vh;
  overflow-y: auto;
}

.modal h2 {
  margin-top: 0;
  color: #2c3e50;
}

.form-group {
  margin-bottom: 1.5rem;
}

.form-group label {
  display: block;
  margin-bottom: 0.5rem;
  color: #333;
  font-weight: 500;
}

.form-group input[type='text'],
.form-group input[type='email'],
.form-group input[type='password'] {
  width: 100%;
  padding: 0.75rem;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 1rem;
  box-sizing: border-box;
}

.form-group input:focus {
  outline: none;
  border-color: #667eea;
}

.checkbox-group label {
  display: flex;
  align-items: center;
  font-weight: normal;
}

.checkbox-group input[type='checkbox'] {
  margin-right: 0.5rem;
  width: auto;
}

.modal-actions {
  display: flex;
  gap: 1rem;
  justify-content: flex-end;
  margin-top: 2rem;
}

.btn-cancel,
.btn-save {
  padding: 0.75rem 1.5rem;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  font-size: 1rem;
}

.btn-cancel {
  background: #95a5a6;
  color: white;
}

.btn-cancel:hover {
  background: #7f8c8d;
}

.btn-save {
  background: #667eea;
  color: white;
}

.btn-save:hover:not(:disabled) {
  background: #5568d3;
}

.btn-save:disabled {
  background: #ccc;
  cursor: not-allowed;
}
</style>

