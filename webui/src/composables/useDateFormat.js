import { ref, onMounted, onUnmounted } from 'vue'
import { formatDateInTimezone, getTimezone } from '../utils/timezone.js'

/**
 * Composable for date formatting with timezone support
 */
export function useDateFormat() {
  const timezone = ref(getTimezone())
  
  const formatDate = (dateString, formatString = 'MMM dd, yyyy HH:mm:ss') => {
    return formatDateInTimezone(dateString, formatString, timezone.value)
  }
  
  // Listen for timezone changes
  const handleTimezoneChange = (event) => {
    timezone.value = event.detail.timezone
  }
  
  onMounted(() => {
    window.addEventListener('timezone-changed', handleTimezoneChange)
  })
  
  onUnmounted(() => {
    window.removeEventListener('timezone-changed', handleTimezoneChange)
  })
  
  return {
    formatDate,
    timezone
  }
}

