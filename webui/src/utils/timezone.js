// Timezone utility for handling UTC dates and timezone conversions
import { format, parseISO } from 'date-fns'
import { utcToZonedTime, zonedTimeToUtc } from 'date-fns-tz'

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
    
    // Handle different input types
    if (typeof dateString === 'string') {
      // Parse ISO string - assume it's in UTC
      date = parseISO(dateString)
    } else if (dateString instanceof Date) {
      // Already a Date object - assume it's in UTC
      date = dateString
    } else {
      return String(dateString)
    }
    
    // Convert UTC date to the selected timezone
    const zonedDate = utcToZonedTime(date, tz)
    return format(zonedDate, formatString)
  } catch (error) {
    console.error('Error formatting date:', error, dateString)
    return String(dateString)
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

