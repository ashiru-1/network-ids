import { NextResponse } from "next/server"

// Store data in memory for demo (in production, use a database)
let dashboardData: any = null
let lastGenerated = 0

// Sample data generator with more realistic data
function generateSampleData() {
  const now = new Date()
  const alerts = []
  const severities = ["Critical", "High", "Medium", "Low"]
  const attackTypes = [
    "SQL Injection Attempt",
    "Cross-Site Scripting",
    "SSH Brute Force",
    "Port Scan Detection",
    "Malware Communication",
    "DDoS Attack",
    "Buffer Overflow",
    "Privilege Escalation",
  ]
  const ips = ["192.168.1.100", "10.0.0.5", "172.16.0.10", "203.0.113.1", "198.51.100.42"]

  // Generate alerts with realistic distribution
  const numAlerts = 45 + Math.floor(Math.random() * 30) // 45-75 alerts

  for (let i = 0; i < numAlerts; i++) {
    // More recent alerts are more likely
    const hoursBack = Math.pow(Math.random(), 2) * 24 // Weighted towards recent
    const alertTime = new Date(now.getTime() - hoursBack * 60 * 60 * 1000)

    // Severity distribution: more medium/low, fewer critical
    let severity
    const severityRand = Math.random()
    if (severityRand < 0.1) severity = "Critical"
    else if (severityRand < 0.3) severity = "High"
    else if (severityRand < 0.7) severity = "Medium"
    else severity = "Low"

    alerts.push({
      alert_id: `ALERT-${String(i + 1).padStart(6, "0")}`,
      signature_id: `SIG-${String(Math.floor(Math.random() * 100) + 1).padStart(3, "0")}`,
      signature_name: attackTypes[Math.floor(Math.random() * attackTypes.length)],
      severity: severity,
      src_ip: ips[Math.floor(Math.random() * ips.length)],
      dst_ip: "192.168.1.1",
      src_port: 1024 + Math.floor(Math.random() * 64511),
      dst_port: [80, 443, 22, 21, 25, 53, 3389, 8080][Math.floor(Math.random() * 8)],
      protocol: Math.random() > 0.1 ? "TCP" : "UDP",
      timestamp: alertTime.toISOString(),
      payload_snippet: `Sample payload for ${attackTypes[Math.floor(Math.random() * attackTypes.length)]}...`,
      description: `Detected suspicious activity from ${ips[Math.floor(Math.random() * ips.length)]}`,
    })
  }

  // Sort alerts by timestamp (newest first)
  alerts.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())

  const packetsProcessed = 5000 + Math.floor(Math.random() * 3000)
  const truePositives = Math.floor(numAlerts * 0.85) // 85% of alerts are true positives
  const falsePositives = numAlerts - truePositives
  const falseNegatives = Math.floor(truePositives * 0.15) // 15% missed
  const trueNegatives = packetsProcessed - numAlerts - falseNegatives

  const accuracy = (truePositives + trueNegatives) / packetsProcessed
  const precision = truePositives / (truePositives + falsePositives)
  const recall = truePositives / (truePositives + falseNegatives)
  const f1Score = (2 * (precision * recall)) / (precision + recall)

  return {
    system_status: {
      signatures_loaded: 8,
      packets_processed: packetsProcessed,
      alerts_generated: numAlerts,
      processing_rate: 125.5 + Math.random() * 75,
    },
    alerts: alerts,
    metrics: {
      accuracy: accuracy,
      precision: precision,
      recall: recall,
      f1_score: f1Score,
      false_positive_rate: falsePositives / (falsePositives + trueNegatives),
      true_positives: truePositives,
      true_negatives: trueNegatives,
      false_positives: falsePositives,
      false_negatives: falseNegatives,
      total_packets: packetsProcessed,
    },
    signatures: [
      {
        signature_id: "SQLI-001",
        name: "SQL Injection Attempt",
        severity: "High",
        protocol: "TCP",
        description: "Detects SQL injection attempts in HTTP traffic",
      },
      {
        signature_id: "XSS-001",
        name: "Cross-Site Scripting",
        severity: "Medium",
        protocol: "TCP",
        description: "Detects XSS attacks in web traffic",
      },
      {
        signature_id: "BRUTE-001",
        name: "SSH Brute Force",
        severity: "High",
        protocol: "TCP",
        description: "Detects SSH brute force login attempts",
      },
      {
        signature_id: "SCAN-001",
        name: "Port Scan Detection",
        severity: "Medium",
        protocol: "TCP",
        description: "Detects network port scanning activities",
      },
      {
        signature_id: "MALWARE-001",
        name: "Malware Communication",
        severity: "Critical",
        protocol: "TCP",
        description: "Detects malware command and control traffic",
      },
      {
        signature_id: "DDOS-001",
        name: "DDoS Attack",
        severity: "Critical",
        protocol: "UDP",
        description: "Detects distributed denial of service attacks",
      },
      {
        signature_id: "BUFFER-001",
        name: "Buffer Overflow",
        severity: "High",
        protocol: "TCP",
        description: "Detects buffer overflow attack attempts",
      },
      {
        signature_id: "PRIV-001",
        name: "Privilege Escalation",
        severity: "High",
        protocol: "TCP",
        description: "Detects privilege escalation attempts",
      },
    ],
    timestamp: now.toISOString(),
  }
}

export async function GET() {
  try {
    const now = Date.now()

    // Generate new data if it's been more than 5 minutes or no data exists
    if (!dashboardData || now - lastGenerated > 5 * 60 * 1000) {
      dashboardData = generateSampleData()
      lastGenerated = now
    }

    return NextResponse.json(dashboardData)
  } catch (error) {
    console.error("Error fetching dashboard data:", error)
    return NextResponse.json({ error: "Failed to fetch dashboard data" }, { status: 500 })
  }
}
