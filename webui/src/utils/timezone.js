// Timezone utility for handling UTC dates and timezone conversions
// Using native JavaScript Intl API instead of date-fns-tz to avoid dependency issues
import { format, parseISO } from 'date-fns'

const TIMEZONE_STORAGE_KEY = 'network_logger_timezone'
const DEFAULT_TIMEZONE = Intl.DateTimeFormat().resolvedOptions().timeZone

/**
 * Get the user's selected timezone or default
 */
export function getTimezone() {
  if (typeof window === 'undefined') {
    return DEFAULT_TIMEZONE
  }
  return localStorage.getItem(TIMEZONE_STORAGE_KEY) || DEFAULT_TIMEZONE
}

/**
 * Set the user's timezone preference
 */
export function setTimezone(timezone) {
  if (typeof window !== 'undefined') {
    localStorage.setItem(TIMEZONE_STORAGE_KEY, timezone)
  }
}

/**
 * Get default timezone (browser's timezone)
 */
export function getDefaultTimezone() {
  return DEFAULT_TIMEZONE
}

/**
 * Format a UTC date string to the user's selected timezone
 * @param {string|Date} dateString - UTC date string or Date object
 * @param {string} formatString - date-fns format string (default: 'MMM dd, yyyy HH:mm:ss')
 * @param {string} timezone - Optional timezone override
 */
export function formatDateInTimezone(dateString, formatString = 'MMM dd, yyyy HH:mm:ss', timezone = null) {
  if (!dateString) return 'N/A'
  
  try {
    const tz = timezone || getTimezone()
    let date
    
    // Handle different input types - ensure UTC dates are parsed correctly
    if (typeof dateString === 'string') {
      // Normalize the date string to ensure UTC
      let normalizedDateStr = dateString.trim()
      
      // If it ends with Z or has timezone offset, it's already timezone-aware
      if (normalizedDateStr.endsWith('Z') || /[+-]\d{2}:?\d{2}$/.test(normalizedDateStr)) {
        date = new Date(normalizedDateStr)
      } else if (normalizedDateStr.includes('T')) {
        // ISO string without timezone - assume UTC and add Z
        // Remove any trailing spaces or timezone info
        normalizedDateStr = normalizedDateStr.replace(/\s+$/, '')
        if (!normalizedDateStr.endsWith('Z') && !/[+-]\d{2}:?\d{2}$/.test(normalizedDateStr)) {
          normalizedDateStr += 'Z'
        }
        date = new Date(normalizedDateStr)
      } else {
        // Not an ISO string - try parsing as-is
        date = new Date(normalizedDateStr)
      }
      
      // Ensure we have a valid date
      if (isNaN(date.getTime())) {
        console.warn('Invalid date string:', dateString)
        return String(dateString)
      }
    } else if (dateString instanceof Date) {
      if (isNaN(dateString.getTime())) {
        return 'Invalid Date'
      }
      date = dateString
    } else {
      return String(dateString)
    }
    
    // Determine format requirements
    const use12Hour = formatString.includes('hh') || formatString.includes('h')
    const needMonthName = formatString.includes('MMM')
    const needMonth2Digit = formatString.includes('MM') && !needMonthName
    const needDay2Digit = formatString.includes('dd')
    const needHour2Digit = formatString.includes('HH') || formatString.includes('hh')
    const needMinute2Digit = formatString.includes('mm')
    const needSecond2Digit = formatString.includes('ss')
    
    // Get all parts we need in the target timezone
    const intlOptions = {
      timeZone: tz,
      year: 'numeric',
      month: needMonthName ? 'short' : (needMonth2Digit ? '2-digit' : 'numeric'),
      day: needDay2Digit ? '2-digit' : 'numeric',
      hour: needHour2Digit ? '2-digit' : 'numeric',
      minute: needMinute2Digit ? '2-digit' : 'numeric',
      second: needSecond2Digit ? '2-digit' : 'numeric',
      hour12: use12Hour
    }
    
    const formatter = new Intl.DateTimeFormat('en-US', intlOptions)
    const parts = formatter.formatToParts(date)
    
    // Extract values from parts
    const values = {}
    parts.forEach(part => {
      if (!values[part.type] || part.type === 'dayPeriod') {
        values[part.type] = part.value
      }
    })
    
    // Build formatted string by replacing tokens
    let result = formatString
    
    // Year
    if (values.year) {
      result = result.replace(/yyyy/g, values.year)
    }
    
    // Month
    if (values.month) {
      if (needMonthName) {
        result = result.replace(/MMM/g, values.month)
      } else if (needMonth2Digit) {
        // Convert to 2-digit number
        const monthNum = parseInt(values.month) || 
          ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'].indexOf(values.month) + 1 || 1
        result = result.replace(/MM/g, monthNum.toString().padStart(2, '0'))
      } else if (formatString.includes('M')) {
        const monthNum = parseInt(values.month) || 
          ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'].indexOf(values.month) + 1 || 1
        result = result.replace(/M/g, monthNum.toString())
      }
    }
    
    // Day
    if (values.day) {
      if (needDay2Digit) {
        result = result.replace(/dd/g, values.day.padStart(2, '0'))
      } else if (formatString.includes('d')) {
        result = result.replace(/d/g, values.day)
      }
    }
    
    // Hour - handle 24-hour vs 12-hour conversion
    // Replace longest tokens first to avoid partial matches
    if (values.hour !== undefined) {
      const hourStr = values.hour
      const hourNum = parseInt(hourStr) || 0
      
      // 24-hour format (HH or H)
      if (formatString.includes('HH')) {
        // Replace HH first (2-digit, 24-hour)
        result = result.replace(/HH/g, hourNum.toString().padStart(2, '0'))
      } else if (formatString.includes('H')) {
        // Single H (1-digit, 24-hour) - only if HH wasn't found
        result = result.replace(/\bH\b/g, hourNum.toString())
      }
      
      // 12-hour format (hh or h) - only if not already replaced
      if (!formatString.includes('HH') && !formatString.includes('H')) {
        if (formatString.includes('hh')) {
          // Replace hh first (2-digit, 12-hour)
          result = result.replace(/hh/g, hourStr.padStart(2, '0'))
        } else if (formatString.includes('h')) {
          // Single h (1-digit, 12-hour)
          result = result.replace(/\bh\b/g, hourStr)
        }
      }
    }
    
    // Minute
    if (values.minute) {
      if (needMinute2Digit) {
        result = result.replace(/mm/g, values.minute.padStart(2, '0'))
      } else if (formatString.includes('m')) {
        result = result.replace(/m/g, values.minute)
      }
    }
    
    // Second
    if (values.second) {
      if (needSecond2Digit) {
        result = result.replace(/ss/g, values.second.padStart(2, '0'))
      } else if (formatString.includes('s')) {
        result = result.replace(/s/g, values.second)
      }
    }
    
    // AM/PM
    if (use12Hour && values.dayPeriod) {
      result = result.replace(/a/g, values.dayPeriod.toLowerCase())
      result = result.replace(/A/g, values.dayPeriod.toUpperCase())
    }
    
    return result
  } catch (error) {
    console.error('Error formatting date:', error, dateString, 'timezone:', timezone || getTimezone())
    // Fallback to simple formatting
    try {
      const date = typeof dateString === 'string' ? new Date(dateString) : dateString
      if (isNaN(date.getTime())) {
        return String(dateString)
      }
      // Use Intl directly as fallback
      return new Intl.DateTimeFormat('en-US', {
        timeZone: timezone || getTimezone(),
        year: 'numeric',
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
      }).format(date)
    } catch (e) {
      return String(dateString)
    }
  }
}

/**
 * Get list of common timezones
 */
export function getCommonTimezones() {
  return [
    { value: 'UTC', label: 'UTC (Coordinated Universal Time)' },
    { value: 'America/New_York', label: 'Eastern Time (US & Canada)' },
    { value: 'America/Chicago', label: 'Central Time (US & Canada)' },
    { value: 'America/Denver', label: 'Mountain Time (US & Canada)' },
    { value: 'America/Los_Angeles', label: 'Pacific Time (US & Canada)' },
    { value: 'America/Phoenix', label: 'Arizona' },
    { value: 'America/Anchorage', label: 'Alaska' },
    { value: 'America/Honolulu', label: 'Hawaii' },
    { value: 'Europe/London', label: 'London' },
    { value: 'Europe/Paris', label: 'Paris' },
    { value: 'Europe/Berlin', label: 'Berlin' },
    { value: 'Europe/Rome', label: 'Rome' },
    { value: 'Europe/Madrid', label: 'Madrid' },
    { value: 'Europe/Moscow', label: 'Moscow' },
    { value: 'Asia/Tokyo', label: 'Tokyo' },
    { value: 'Asia/Shanghai', label: 'Shanghai' },
    { value: 'Asia/Hong_Kong', label: 'Hong Kong' },
    { value: 'Asia/Dubai', label: 'Dubai' },
    { value: 'Asia/Singapore', label: 'Singapore' },
    { value: 'Asia/Kolkata', label: 'Mumbai, Kolkata' },
    { value: 'Australia/Sydney', label: 'Sydney' },
    { value: 'Australia/Melbourne', label: 'Melbourne' },
    { value: 'Pacific/Auckland', label: 'Auckland' }
  ]
}

/**
 * Get all available timezones (Intl.supportedValuesOf if available, otherwise common list)
 */
export function getAllTimezones() {
  if (typeof Intl !== 'undefined' && Intl.supportedValuesOf) {
    try {
      const timezones = Intl.supportedValuesOf('timeZone')
      return timezones.map(tz => ({
        value: tz,
        label: tz.replace(/_/g, ' ')
      }))
    } catch (e) {
      // Fallback to common timezones if not supported
      return getCommonTimezones()
    }
  }
  return getCommonTimezones()
}
