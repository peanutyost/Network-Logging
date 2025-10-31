<template>
  <div class="traffic-chart">
    <Line
      v-if="chartData"
      :data="chartData"
      :options="chartOptions"
    />
    <div v-else class="loading">Loading chart data...</div>
  </div>
</template>

<script>
import { Line } from 'vue-chartjs'
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend
} from 'chart.js'
import api from '../api.js'
import { format, parseISO } from 'date-fns'

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend
)

export default {
  name: 'TrafficChart',
  components: {
    Line
  },
  props: {
    domain: {
      type: String,
      required: true
    },
    startTime: {
      type: Date,
      default: null
    },
    endTime: {
      type: Date,
      default: null
    }
  },
  data() {
    return {
      chartData: null,
      chartOptions: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'top'
          },
          title: {
            display: true,
            text: 'Traffic Volume Over Time'
          }
        },
        scales: {
          y: {
            beginAtZero: true,
            ticks: {
              callback: function(value) {
                return value + ' B'
              }
            }
          }
        }
      }
    }
  },
  mounted() {
    this.loadData()
  },
  watch: {
    domain() {
      this.loadData()
    },
    startTime() {
      this.loadData()
    },
    endTime() {
      this.loadData()
    }
  },
  methods: {
    async loadData() {
      try {
        const data = await api.getTrafficVolume(this.domain, this.startTime, this.endTime)
        
        if (data && data.length > 0) {
          const labels = data.map(d => format(parseISO(d.timestamp), 'MMM dd HH:mm'))
          this.chartData = {
            labels,
            datasets: [
              {
                label: 'Bytes Sent',
                data: data.map(d => d.bytes_sent),
                borderColor: 'rgb(75, 192, 192)',
                backgroundColor: 'rgba(75, 192, 192, 0.2)'
              },
              {
                label: 'Bytes Received',
                data: data.map(d => d.bytes_received),
                borderColor: 'rgb(255, 99, 132)',
                backgroundColor: 'rgba(255, 99, 132, 0.2)'
              }
            ]
          }
        }
      } catch (error) {
        console.error('Error loading traffic chart data:', error)
      }
    }
  }
}
</script>

<style scoped>
.traffic-chart {
  height: 400px;
  margin: 1rem 0;
}
</style>

