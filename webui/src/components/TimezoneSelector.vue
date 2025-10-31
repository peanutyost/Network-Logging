<template>
  <div class="timezone-selector">
    <label>
      Timezone:
      <select v-model="selectedTimezone" @change="updateTimezone" class="timezone-select">
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
    </label>
    <div class="timezone-info">
      Current time: {{ currentTime }}
    </div>
  </div>
</template>

<script>
import { ref, onMounted, onUnmounted } from 'vue'
import { getTimezone, setTimezone, getCommonTimezones, getAllTimezones, formatDateInTimezone } from '../utils/timezone.js'

export default {
  name: 'TimezoneSelector',
  setup() {
    const selectedTimezone = ref(getTimezone())
    const currentTime = ref('')
    const showAllTimezones = ref(false)
    let interval = null
    
    const commonTimezones = getCommonTimezones()
    const allTimezones = getAllTimezones()
    
    const updateCurrentTime = () => {
      const now = new Date().toISOString()
      currentTime.value = formatDateInTimezone(now, 'MMM dd, yyyy HH:mm:ss', selectedTimezone.value)
    }
    
    const updateTimezone = () => {
      setTimezone(selectedTimezone.value)
      updateCurrentTime()
      // Emit event to notify parent components
      window.dispatchEvent(new CustomEvent('timezone-changed', { 
        detail: { timezone: selectedTimezone.value } 
      }))
    }
    
    onMounted(() => {
      updateCurrentTime()
      interval = setInterval(updateCurrentTime, 1000)
      
      // Listen for timezone changes
      window.addEventListener('timezone-changed', updateCurrentTime)
    })
    
    onUnmounted(() => {
      if (interval) {
        clearInterval(interval)
      }
      window.removeEventListener('timezone-changed', updateCurrentTime)
    })
    
    return {
      selectedTimezone,
      currentTime,
      commonTimezones,
      allTimezones,
      showAllTimezones,
      updateTimezone
    }
  }
}
</script>

<style scoped>
.timezone-selector {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0.5rem 1rem;
  background-color: rgba(255, 255, 255, 0.1);
  border-radius: 4px;
}

.timezone-selector label {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  color: white;
  font-size: 0.9rem;
}

.timezone-select {
  padding: 0.4rem 0.6rem;
  border: 1px solid rgba(255, 255, 255, 0.3);
  border-radius: 4px;
  background-color: rgba(255, 255, 255, 0.9);
  color: #333;
  font-size: 0.85rem;
  cursor: pointer;
}

.timezone-select:hover {
  background-color: white;
}

.timezone-info {
  font-size: 0.85rem;
  color: rgba(255, 255, 255, 0.9);
  font-style: italic;
}
</style>

