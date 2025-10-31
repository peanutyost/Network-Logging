<template>
  <div class="login-container">
    <div class="login-card">
      <h1>Network Traffic DNS Logger</h1>
      <h2>Sign In</h2>
      <form @submit.prevent="handleLogin" class="login-form">
        <div class="form-group">
          <label for="username">Username</label>
          <input
            id="username"
            v-model="username"
            type="text"
            required
            autocomplete="username"
            placeholder="Enter your username"
          />
        </div>
        <div class="form-group">
          <label for="password">Password</label>
          <input
            id="password"
            v-model="password"
            type="password"
            required
            autocomplete="current-password"
            placeholder="Enter your password"
          />
        </div>
        <div v-if="error" class="error-message">{{ error }}</div>
        <button type="submit" :disabled="loading" class="login-button">
          {{ loading ? 'Signing in...' : 'Sign In' }}
        </button>
      </form>
      <div v-if="showRegister" class="register-section">
        <hr />
        <h3>Register New User</h3>
        <form @submit.prevent="handleRegister" class="register-form">
          <div class="form-group">
            <label for="reg-username">Username</label>
            <input
              id="reg-username"
              v-model="registerData.username"
              type="text"
              required
              minlength="3"
              maxlength="50"
              placeholder="Choose a username"
            />
          </div>
          <div class="form-group">
            <label for="reg-email">Email</label>
            <input
              id="reg-email"
              v-model="registerData.email"
              type="email"
              required
              placeholder="Enter your email"
            />
          </div>
          <div class="form-group">
            <label for="reg-password">Password</label>
            <input
              id="reg-password"
              v-model="registerData.password"
              type="password"
              required
              minlength="6"
              placeholder="Choose a password (min 6 chars)"
            />
          </div>
          <div v-if="registerError" class="error-message">{{ registerError }}</div>
          <button type="submit" :disabled="registerLoading" class="register-button">
            {{ registerLoading ? 'Registering...' : 'Register' }}
          </button>
        </form>
      </div>
      <div class="toggle-register">
        <button @click="showRegister = !showRegister" class="toggle-button">
          {{ showRegister ? 'Hide Registration' : 'Show Registration' }}
        </button>
      </div>
    </div>
  </div>
</template>

<script>
import api from '../api.js'

export default {
  name: 'Login',
  data() {
    return {
      username: '',
      password: '',
      error: '',
      loading: false,
      showRegister: false,
      registerData: {
        username: '',
        email: '',
        password: ''
      },
      registerError: '',
      registerLoading: false
    }
  },
  mounted() {
    // Redirect if already logged in
    if (localStorage.getItem('auth_token')) {
      this.$router.push('/')
    }
  },
  methods: {
    async handleLogin() {
      this.error = ''
      this.loading = true
      try {
        await api.login(this.username, this.password)
        const user = await api.getCurrentUser()
        this.$router.push('/')
      } catch (err) {
        this.error = err.response?.data?.detail || 'Login failed. Please check your credentials.'
      } finally {
        this.loading = false
      }
    },
    async handleRegister() {
      this.registerError = ''
      this.registerLoading = true
      try {
        await api.register(this.registerData)
        this.registerError = ''
        this.showRegister = false
        this.registerData = { username: '', email: '', password: '' }
        alert('Registration successful! Please sign in.')
      } catch (err) {
        this.registerError = err.response?.data?.detail || 'Registration failed. Please try again.'
      } finally {
        this.registerLoading = false
      }
    }
  }
}
</script>

<style scoped>
.login-container {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 100vh;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  padding: 2rem;
}

.login-card {
  background: white;
  border-radius: 8px;
  padding: 3rem;
  box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
  width: 100%;
  max-width: 450px;
}

h1 {
  text-align: center;
  color: #2c3e50;
  margin-bottom: 0.5rem;
  font-size: 1.8rem;
}

h2 {
  text-align: center;
  color: #555;
  margin-bottom: 2rem;
  font-size: 1.3rem;
  font-weight: 400;
}

h3 {
  text-align: center;
  color: #555;
  margin: 1.5rem 0 1rem;
  font-size: 1.1rem;
}

.form-group {
  margin-bottom: 1.5rem;
}

label {
  display: block;
  margin-bottom: 0.5rem;
  color: #333;
  font-weight: 500;
}

input {
  width: 100%;
  padding: 0.75rem;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 1rem;
  box-sizing: border-box;
}

input:focus {
  outline: none;
  border-color: #667eea;
  box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
}

.login-button,
.register-button {
  width: 100%;
  padding: 0.75rem;
  background: #667eea;
  color: white;
  border: none;
  border-radius: 4px;
  font-size: 1rem;
  font-weight: 500;
  cursor: pointer;
  transition: background 0.3s;
}

.login-button:hover:not(:disabled),
.register-button:hover:not(:disabled) {
  background: #5568d3;
}

.login-button:disabled,
.register-button:disabled {
  background: #ccc;
  cursor: not-allowed;
}

.error-message {
  color: #e74c3c;
  margin-bottom: 1rem;
  padding: 0.5rem;
  background: #fee;
  border-radius: 4px;
  font-size: 0.9rem;
}

hr {
  margin: 2rem 0;
  border: none;
  border-top: 1px solid #eee;
}

.toggle-register {
  margin-top: 1.5rem;
  text-align: center;
}

.toggle-button {
  background: none;
  border: none;
  color: #667eea;
  cursor: pointer;
  text-decoration: underline;
  font-size: 0.9rem;
}

.toggle-button:hover {
  color: #5568d3;
}
</style>

