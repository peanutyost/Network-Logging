import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 10000
})

// Add token to requests if available
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('auth_token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Handle 401 errors - redirect to login
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      localStorage.removeItem('auth_token')
      localStorage.removeItem('user')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

export default {
  // Dashboard
  async getDashboardStats(hours = 24) {
    const response = await api.get(`/dashboard/stats?hours=${hours}`)
    return response.data
  },

  // DNS
  async searchDomains(query, limit = 100) {
    const response = await api.get(`/dns/search?query=${encodeURIComponent(query)}&limit=${limit}`)
    return response.data
  },

  async getDomainInfo(domain) {
    const response = await api.get(`/dns/domain/${encodeURIComponent(domain)}`)
    return response.data
  },

  async getDomainWhois(domain, forceRefresh = false) {
    const response = await api.get(`/dns/domain/${encodeURIComponent(domain)}/whois?force_refresh=${forceRefresh}`)
    return response.data
  },

  async getRecentDns(limit = 200, since = null) {
    let url = `/dns/recent?limit=${limit}`
    if (since) {
      url += `&since=${encodeURIComponent(since.toISOString())}`
    }
    const response = await api.get(url)
    return response.data
  },

  async getDnsEvents({ limit = 500, since = null, source_ip = null, domain = null, event_type = null } = {}) {
    const params = new URLSearchParams()
    params.append('limit', String(limit))
    if (since) params.append('since', since.toISOString())
    if (source_ip) params.append('source_ip', source_ip)
    if (domain) params.append('domain', domain)
    if (event_type) params.append('event_type', event_type)
    const response = await api.get(`/dns/events?${params.toString()}`)
    return response.data
  },

  // Traffic
  async getTrafficByDomain(domain, startTime = null, endTime = null) {
    let url = `/traffic/domain/${encodeURIComponent(domain)}`
    const params = new URLSearchParams()
    if (startTime) params.append('start_time', startTime.toISOString())
    if (endTime) params.append('end_time', endTime.toISOString())
    if (params.toString()) url += `?${params.toString()}`
    
    const response = await api.get(url)
    return response.data
  },

  async getTrafficVolume(domain, startTime = null, endTime = null) {
    let url = `/traffic/domain/${encodeURIComponent(domain)}/volume`
    const params = new URLSearchParams()
    if (startTime) params.append('start_time', startTime.toISOString())
    if (endTime) params.append('end_time', endTime.toISOString())
    if (params.toString()) url += `?${params.toString()}`
    
    const response = await api.get(url)
    return response.data
  },

  async getTopDomains(limit = 10, startTime = null, endTime = null) {
    let url = `/traffic/top-domains?limit=${limit}`
    const params = new URLSearchParams()
    if (startTime) params.append('start_time', startTime.toISOString())
    if (endTime) params.append('end_time', endTime.toISOString())
    if (params.toString()) url += `&${params.toString()}`
    
    const response = await api.get(url)
    return response.data
  },

  // Threat Hunting
  async getOrphanedIPs(days = 7, startTime = null, endTime = null) {
    let url = `/threat/orphaned-ips?days=${days}`
    const params = new URLSearchParams()
    if (startTime) params.append('start_time', startTime.toISOString())
    if (endTime) params.append('end_time', endTime.toISOString())
    if (params.toString()) url += `&${params.toString()}`
    
    const response = await api.get(url)
    return response.data
  },

  // Authentication
  async login(username, password) {
    const formData = new URLSearchParams()
    formData.append('username', username)
    formData.append('password', password)
    const response = await api.post('/auth/login', formData, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    })
    if (response.data.access_token) {
      localStorage.setItem('auth_token', response.data.access_token)
    }
    return response.data
  },

  async register(userData) {
    const response = await api.post('/auth/register', userData)
    return response.data
  },

  async getCurrentUser() {
    const response = await api.get('/auth/me')
    localStorage.setItem('user', JSON.stringify(response.data))
    return response.data
  },

  logout() {
    localStorage.removeItem('auth_token')
    localStorage.removeItem('user')
  },

  // User Management (Admin only)
  async getUsers(skip = 0, limit = 100) {
    const response = await api.get(`/users?skip=${skip}&limit=${limit}`)
    return response.data
  },

  async getUser(userId) {
    const response = await api.get(`/users/${userId}`)
    return response.data
  },

  async createUser(userData) {
    const response = await api.post('/users', userData)
    return response.data
  },

  async updateUser(userId, userData) {
    const response = await api.put(`/users/${userId}`, userData)
    return response.data
  },

  async deleteUser(userId) {
    await api.delete(`/users/${userId}`)
  },

  // User Settings
  async changePassword(passwordData) {
    const response = await api.post('/auth/change-password', passwordData)
    return response.data
  },

  // Threat Intelligence
  async getThreatFeeds() {
    const response = await api.get('/threat/feeds')
    return response.data
  },

  async updateThreatFeed(feedName) {
    const response = await api.post(`/threat/feeds/${feedName}/update`)
    return response.data
  },

  async getThreatAlerts(limit = 100, since = null, resolved = null) {
    const params = { limit }
    if (since) params.since = since
    if (resolved !== null) params.resolved = resolved
    const response = await api.get('/threat/alerts', { params })
    return response.data
  },

  async resolveThreatAlert(alertId) {
    const response = await api.post(`/threat/alerts/${alertId}/resolve`)
    return response.data
  },

  async toggleThreatFeed(feedName, enabled) {
    const response = await api.put(`/threat/feeds/${feedName}/toggle?enabled=${enabled}`)
    return response.data
  },

  // Threat Whitelist
  async getThreatWhitelist(limit = 100, indicatorType = null) {
    const params = { limit }
    if (indicatorType) params.indicator_type = indicatorType
    const response = await api.get('/threat/whitelist', { params })
    return response.data
  },

  async addThreatWhitelist(entry) {
    const response = await api.post('/threat/whitelist', entry)
    return response.data
  },

  async removeThreatWhitelist(whitelistId) {
    const response = await api.delete(`/threat/whitelist/${whitelistId}`)
    return response.data
  },

  // Threat configuration
  async getThreatConfig() {
    const response = await api.get('/threat/config')
    return response.data
  },

  async updateThreatConfig(lookbackDays) {
    const response = await api.put('/threat/config', { lookback_days: lookbackDays })
    return response.data
  },

  // Historical threat scan
  async scanHistoricalThreats(days = 30) {
    const response = await api.post(`/threat/scan-historical?days=${days}`)
    return response.data
  }
}

