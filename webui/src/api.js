import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 10000
})

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
  }
}

