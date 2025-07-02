import { Chart } from "@/components/ui/chart"
// Dashboard JavaScript
class IDSDashboard {
  constructor() {
    this.data = null
    this.charts = {}
    this.refreshInterval = null
    this.init()
  }

  async init() {
    await this.loadData()
    this.setupEventListeners()
    this.renderDashboard()
    this.startAutoRefresh()
  }

  async loadData() {
    try {
      // Try to load from dashboard_data.json
      const response = await fetch("dashboard_data.json")
      if (response.ok) {
        this.data = await response.json()
      } else {
        // Use sample data if file doesn't exist
        this.data = this.generateSampleData()
      }
    } catch (error) {
      console.warn("Could not load dashboard data, using sample data:", error)
      this.data = this.generateSampleData()
    }
  }

  generateSampleData() {
    const now = new Date()
    const alerts = []
    const severities = ["Critical", "High", "Medium", "Low"]
    const attackTypes = ["SQL Injection", "XSS Attack", "Brute Force", "Port Scan", "Malware"]
    const ips = ["192.168.1.100", "10.0.0.5", "172.16.0.10", "8.8.8.8"]

    // Generate sample alerts
    for (let i = 0; i < 50; i++) {
      const alertTime = new Date(now.getTime() - Math.random() * 24 * 60 * 60 * 1000)
      alerts.push({
        alert_id: `ALERT-${String(i + 1).padStart(6, "0")}`,
        signature_name: attackTypes[Math.floor(Math.random() * attackTypes.length)],
        severity: severities[Math.floor(Math.random() * severities.length)],
        src_ip: ips[Math.floor(Math.random() * ips.length)],
        dst_ip: "192.168.1.1",
        src_port: Math.floor(Math.random() * 65535),
        dst_port: [80, 443, 22, 21][Math.floor(Math.random() * 4)],
        protocol: "TCP",
        timestamp: alertTime.toISOString(),
      })
    }

    return {
      system_status: {
        signatures_loaded: 5,
        packets_processed: 1000,
        alerts_generated: alerts.length,
        processing_rate: 125.5,
      },
      alerts: alerts,
      metrics: {
        accuracy: 0.92,
        precision: 0.88,
        recall: 0.85,
        f1_score: 0.865,
        false_positive_rate: 0.12,
        true_positives: 42,
        true_negatives: 920,
        false_positives: 38,
        false_negatives: 8,
      },
      signatures: [
        { signature_id: "SQLI-001", name: "SQL Injection", severity: "High", protocol: "TCP" },
        { signature_id: "XSS-001", name: "XSS Attack", severity: "Medium", protocol: "TCP" },
        { signature_id: "BRUTE-001", name: "Brute Force", severity: "High", protocol: "TCP" },
        { signature_id: "SCAN-001", name: "Port Scan", severity: "Medium", protocol: "TCP" },
        { signature_id: "MALWARE-001", name: "Malware", severity: "Critical", protocol: "TCP" },
      ],
      timestamp: now.toISOString(),
    }
  }

  setupEventListeners() {
    // Refresh button
    document.getElementById("refreshBtn").addEventListener("click", () => {
      this.refreshData()
    })

    // Severity filter
    document.getElementById("severityFilter").addEventListener("change", (e) => {
      this.filterAlerts(e.target.value)
    })

    // Add signature button
    document.getElementById("addSignatureBtn").addEventListener("click", () => {
      this.openModal("signatureModal")
    })

    // Modal close buttons
    document.querySelectorAll(".close").forEach((closeBtn) => {
      closeBtn.addEventListener("click", (e) => {
        const modal = e.target.closest(".modal")
        this.closeModal(modal.id)
      })
    })

    // Modal background click
    document.querySelectorAll(".modal").forEach((modal) => {
      modal.addEventListener("click", (e) => {
        if (e.target === modal) {
          this.closeModal(modal.id)
        }
      })
    })

    // Signature form submission
    document.getElementById("signatureForm").addEventListener("submit", (e) => {
      e.preventDefault()
      this.addSignature()
    })

    // Alert row clicks
    document.addEventListener("click", (e) => {
      if (e.target.closest(".alert-row")) {
        const alertId = e.target.closest(".alert-row").dataset.alertId
        this.showAlertDetails(alertId)
      }
    })
  }

  async refreshData() {
    const refreshBtn = document.getElementById("refreshBtn")
    const originalText = refreshBtn.innerHTML
    refreshBtn.innerHTML = '<i class="fas fa-sync-alt fa-spin"></i> Refreshing...'
    refreshBtn.disabled = true

    await this.loadData()
    this.renderDashboard()

    setTimeout(() => {
      refreshBtn.innerHTML = originalText
      refreshBtn.disabled = false
    }, 1000)
  }

  renderDashboard() {
    this.updateStats()
    this.renderCharts()
    this.renderTables()
  }

  updateStats() {
    const stats = this.data.system_status
    document.getElementById("totalAlerts").textContent = stats.alerts_generated.toLocaleString()
    document.getElementById("packetsProcessed").textContent = stats.packets_processed.toLocaleString()
    document.getElementById("processingRate").textContent = stats.processing_rate.toFixed(1)
    document.getElementById("signaturesLoaded").textContent = stats.signatures_loaded
  }

  renderCharts() {
    this.renderSeverityChart()
    this.renderPerformanceChart()
    this.renderTimelineChart()
  }

  renderSeverityChart() {
    const ctx = document.getElementById("severityChart").getContext("2d")

    // Count alerts by severity
    const severityCounts = {}
    this.data.alerts.forEach((alert) => {
      severityCounts[alert.severity] = (severityCounts[alert.severity] || 0) + 1
    })

    if (this.charts.severity) {
      this.charts.severity.destroy()
    }

    this.charts.severity = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: Object.keys(severityCounts),
        datasets: [
          {
            data: Object.values(severityCounts),
            backgroundColor: [
              "#ef4444", // Critical - Red
              "#f59e0b", // High - Orange
              "#3b82f6", // Medium - Blue
              "#10b981", // Low - Green
            ],
            borderWidth: 0,
            hoverOffset: 10,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: {
              padding: 20,
              usePointStyle: true,
            },
          },
        },
      },
    })
  }

  renderPerformanceChart() {
    const ctx = document.getElementById("performanceChart").getContext("2d")
    const metrics = this.data.metrics

    if (this.charts.performance) {
      this.charts.performance.destroy()
    }

    this.charts.performance = new Chart(ctx, {
      type: "bar",
      data: {
        labels: ["Accuracy", "Precision", "Recall", "F1 Score"],
        datasets: [
          {
            label: "Performance Metrics",
            data: [metrics.accuracy * 100, metrics.precision * 100, metrics.recall * 100, metrics.f1_score * 100],
            backgroundColor: [
              "rgba(102, 126, 234, 0.8)",
              "rgba(16, 185, 129, 0.8)",
              "rgba(245, 158, 11, 0.8)",
              "rgba(239, 68, 68, 0.8)",
            ],
            borderColor: [
              "rgba(102, 126, 234, 1)",
              "rgba(16, 185, 129, 1)",
              "rgba(245, 158, 11, 1)",
              "rgba(239, 68, 68, 1)",
            ],
            borderWidth: 2,
            borderRadius: 8,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            beginAtZero: true,
            max: 100,
            ticks: {
              callback: (value) => value + "%",
            },
          },
        },
        plugins: {
          legend: {
            display: false,
          },
        },
      },
    })
  }

  renderTimelineChart() {
    const ctx = document.getElementById("timelineChart").getContext("2d")

    // Group alerts by hour
    const hourlyAlerts = {}
    const now = new Date()

    // Initialize last 24 hours
    for (let i = 23; i >= 0; i--) {
      const hour = new Date(now.getTime() - i * 60 * 60 * 1000)
      const hourKey = hour.getHours()
      hourlyAlerts[hourKey] = 0
    }

    // Count alerts by hour
    this.data.alerts.forEach((alert) => {
      const alertTime = new Date(alert.timestamp)
      const hour = alertTime.getHours()
      hourlyAlerts[hour] = (hourlyAlerts[hour] || 0) + 1
    })

    if (this.charts.timeline) {
      this.charts.timeline.destroy()
    }

    this.charts.timeline = new Chart(ctx, {
      type: "line",
      data: {
        labels: Object.keys(hourlyAlerts).map((h) => `${h}:00`),
        datasets: [
          {
            label: "Alerts per Hour",
            data: Object.values(hourlyAlerts),
            borderColor: "rgba(102, 126, 234, 1)",
            backgroundColor: "rgba(102, 126, 234, 0.1)",
            borderWidth: 3,
            fill: true,
            tension: 0.4,
            pointBackgroundColor: "rgba(102, 126, 234, 1)",
            pointBorderColor: "#fff",
            pointBorderWidth: 2,
            pointRadius: 6,
            pointHoverRadius: 8,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            beginAtZero: true,
            ticks: {
              stepSize: 1,
            },
          },
        },
        plugins: {
          legend: {
            display: false,
          },
        },
      },
    })
  }

  renderTables() {
    this.renderAlertsTable()
    this.renderSignaturesTable()
  }

  renderAlertsTable() {
    const tbody = document.getElementById("alertsTableBody")
    tbody.innerHTML = ""

    // Sort alerts by timestamp (newest first)
    const sortedAlerts = [...this.data.alerts].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))

    sortedAlerts.slice(0, 20).forEach((alert) => {
      const row = document.createElement("tr")
      row.className = "alert-row"
      row.dataset.alertId = alert.alert_id

      const time = new Date(alert.timestamp).toLocaleTimeString()
      const severityClass = `severity-${alert.severity.toLowerCase()}`

      row.innerHTML = `
                <td>${time}</td>
                <td><span class="severity-badge ${severityClass}">${alert.severity}</span></td>
                <td>${alert.signature_name}</td>
                <td>${alert.src_ip}</td>
                <td>${alert.dst_ip}:${alert.dst_port}</td>
                <td>${alert.protocol}</td>
            `

      tbody.appendChild(row)
    })
  }

  renderSignaturesTable() {
    const tbody = document.getElementById("signaturesTableBody")
    tbody.innerHTML = ""

    this.data.signatures.forEach((signature) => {
      const row = document.createElement("tr")
      const severityClass = `severity-${signature.severity.toLowerCase()}`

      row.innerHTML = `
                <td>${signature.signature_id}</td>
                <td>${signature.name}</td>
                <td><span class="severity-badge ${severityClass}">${signature.severity}</span></td>
                <td>${signature.protocol}</td>
                <td><span class="status-dot active"></span> Active</td>
            `

      tbody.appendChild(row)
    })
  }

  filterAlerts(severity) {
    const rows = document.querySelectorAll("#alertsTableBody tr")

    rows.forEach((row) => {
      if (!severity) {
        row.style.display = ""
      } else {
        const alertSeverity = row.querySelector(".severity-badge").textContent
        row.style.display = alertSeverity === severity ? "" : "none"
      }
    })
  }

  showAlertDetails(alertId) {
    const alert = this.data.alerts.find((a) => a.alert_id === alertId)
    if (!alert) return

    const modalBody = document.getElementById("alertModalBody")
    modalBody.innerHTML = `
            <div class="alert-details">
                <div class="detail-row">
                    <strong>Alert ID:</strong> ${alert.alert_id}
                </div>
                <div class="detail-row">
                    <strong>Attack Type:</strong> ${alert.signature_name}
                </div>
                <div class="detail-row">
                    <strong>Severity:</strong> 
                    <span class="severity-badge severity-${alert.severity.toLowerCase()}">${alert.severity}</span>
                </div>
                <div class="detail-row">
                    <strong>Source:</strong> ${alert.src_ip}:${alert.src_port}
                </div>
                <div class="detail-row">
                    <strong>Destination:</strong> ${alert.dst_ip}:${alert.dst_port}
                </div>
                <div class="detail-row">
                    <strong>Protocol:</strong> ${alert.protocol}
                </div>
                <div class="detail-row">
                    <strong>Timestamp:</strong> ${new Date(alert.timestamp).toLocaleString()}
                </div>
                ${
                  alert.payload_snippet
                    ? `
                <div class="detail-row">
                    <strong>Payload:</strong>
                    <pre style="background: #f5f5f5; padding: 1rem; border-radius: 8px; margin-top: 0.5rem; overflow-x: auto;">${alert.payload_snippet}</pre>
                </div>
                `
                    : ""
                }
            </div>
        `

    this.openModal("alertModal")
  }

  addSignature() {
    const form = document.getElementById("signatureForm")
    const formData = new FormData(form)

    const newSignature = {
      signature_id: formData.get("signature_id"),
      name: formData.get("name"),
      protocol: formData.get("protocol"),
      severity: formData.get("severity"),
      description: formData.get("description"),
    }

    // Add to data (in real app, this would be sent to backend)
    this.data.signatures.push(newSignature)
    this.data.system_status.signatures_loaded++

    // Update display
    this.renderSignaturesTable()
    this.updateStats()

    // Close modal and reset form
    this.closeModal("signatureModal")
    form.reset()

    // Show success message
    this.showNotification("Signature added successfully!", "success")
  }

  openModal(modalId) {
    document.getElementById(modalId).style.display = "block"
    document.body.style.overflow = "hidden"
  }

  closeModal(modalId) {
    document.getElementById(modalId).style.display = "none"
    document.body.style.overflow = "auto"
  }

  showNotification(message, type = "info") {
    // Create notification element
    const notification = document.createElement("div")
    notification.className = `notification notification-${type}`
    notification.innerHTML = `
            <i class="fas fa-${type === "success" ? "check-circle" : "info-circle"}"></i>
            <span>${message}</span>
        `

    // Add styles
    notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: ${type === "success" ? "#10b981" : "#3b82f6"};
            color: white;
            padding: 1rem 1.5rem;
            border-radius: 8px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
            z-index: 10000;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            animation: slideInRight 0.3s ease;
        `

    document.body.appendChild(notification)

    // Remove after 3 seconds
    setTimeout(() => {
      notification.style.animation = "slideOutRight 0.3s ease"
      setTimeout(() => {
        document.body.removeChild(notification)
      }, 300)
    }, 3000)
  }

  startAutoRefresh() {
    // Refresh every 30 seconds
    this.refreshInterval = setInterval(() => {
      this.refreshData()
    }, 30000)
  }

  stopAutoRefresh() {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval)
    }
  }
}

// Initialize dashboard when DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
  new IDSDashboard()
})

// Add CSS animations for notifications
const style = document.createElement("style")
style.textContent = `
    @keyframes slideInRight {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    
    @keyframes slideOutRight {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
    
    .detail-row {
        margin-bottom: 1rem;
        padding-bottom: 0.5rem;
        border-bottom: 1px solid rgba(0, 0, 0, 0.1);
    }
    
    .detail-row:last-child {
        border-bottom: none;
        margin-bottom: 0;
    }
`
document.head.appendChild(style)
