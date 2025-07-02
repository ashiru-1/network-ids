import { NextResponse } from "next/server"

export async function POST(request: Request) {
  try {
    console.log("=== ATTACK SIMULATION STARTED ===")

    const { attackType, emailNotification } = await request.json()

    // Simulate processing time for realistic attack
    await new Promise((resolve) => setTimeout(resolve, 3000))

    // Generate realistic attack scenarios
    const attackScenarios = {
      "sql-injection": {
        name: "SQL Injection Attack",
        severity: "Critical",
        payload: "' UNION SELECT username, password FROM users--",
        description: "Attempted database breach via SQL injection",
      },
      "brute-force": {
        name: "SSH Brute Force Attack",
        severity: "High",
        payload: "Multiple failed login attempts detected",
        description: "Coordinated brute force attack on SSH service",
      },
      ddos: {
        name: "DDoS Attack",
        severity: "Critical",
        payload: "High volume traffic from multiple sources",
        description: "Distributed denial of service attack detected",
      },
      malware: {
        name: "Malware Communication",
        severity: "Critical",
        payload: "powershell.exe -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0",
        description: "Malware attempting to establish C2 communication",
      },
    }

    const alerts = []
    const systemLogs = []

    // Generate multiple attack vectors
    const attackTypes = ["sql-injection", "brute-force", "ddos", "malware"]
    const sourceIPs = ["203.0.113.1", "198.51.100.42", "192.0.2.146", "203.0.113.195"]

    let criticalCount = 0

    for (let i = 0; i < 15; i++) {
      const attackKey = attackTypes[Math.floor(Math.random() * attackTypes.length)]
      const attack = attackScenarios[attackKey]
      const sourceIP = sourceIPs[Math.floor(Math.random() * sourceIPs.length)]

      if (attack.severity === "Critical") criticalCount++

      const alert = {
        alert_id: `ALERT-${String(i + 1).padStart(6, "0")}`,
        signature_id: `SIG-${attackKey.toUpperCase()}-001`,
        signature_name: attack.name,
        severity: attack.severity,
        src_ip: sourceIP,
        dst_ip: "192.168.1.1",
        src_port: 1024 + Math.floor(Math.random() * 64511),
        dst_port:
          attackKey === "sql-injection" ? 80 : attackKey === "brute-force" ? 22 : attackKey === "ddos" ? 80 : 443,
        protocol: "TCP",
        timestamp: new Date(Date.now() - Math.random() * 300000).toISOString(), // Last 5 minutes
        payload_snippet: attack.payload,
        description: attack.description,
      }

      alerts.push(alert)

      // Generate system logs
      systemLogs.push(`[${new Date(alert.timestamp).toISOString()}] CRITICAL: ${attack.name} detected from ${sourceIP}`)
      systemLogs.push(`[${new Date(alert.timestamp).toISOString()}] ALERT: Signature ${alert.signature_id} triggered`)

      if (attack.severity === "Critical") {
        systemLogs.push(
          `[${new Date(alert.timestamp).toISOString()}] ACTION: Automatic IP blocking initiated for ${sourceIP}`,
        )
      }
    }

    // Sort alerts by timestamp (newest first)
    alerts.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())

    // Add email notification log
    let emailSent = false
    if (emailNotification && criticalCount > 0) {
      emailSent = true
      systemLogs.push(`[${new Date().toISOString()}] EMAIL: Critical alert notification sent to security@company.com`)
      systemLogs.push(
        `[${new Date().toISOString()}] EMAIL: ${criticalCount} critical threats detected - immediate response required`,
      )
    }

    // Add more realistic system logs
    systemLogs.unshift(`[${new Date().toISOString()}] SYSTEM: Attack simulation initiated`)
    systemLogs.unshift(`[${new Date().toISOString()}] SYSTEM: Enhanced monitoring mode activated`)
    systemLogs.unshift(`[${new Date().toISOString()}] SYSTEM: Threat intelligence feeds updated`)

    const result = {
      system_status: {
        signatures_loaded: 8,
        packets_processed: 2500,
        alerts_generated: alerts.length,
        processing_rate: 89.3,
      },
      alerts: alerts,
      criticalAlertsCount: criticalCount,
      systemLogs: systemLogs.reverse(), // Most recent first
      metrics: {
        accuracy: 0.94,
        precision: 0.91,
        recall: 0.89,
        f1_score: 0.9,
      },
      emailSent: emailSent,
      timestamp: new Date().toISOString(),
    }

    console.log("=== ATTACK SIMULATION COMPLETED ===", {
      alertsGenerated: alerts.length,
      criticalAlerts: criticalCount,
      emailSent: emailSent,
    })

    return NextResponse.json({
      success: true,
      message: `Attack simulation completed. ${criticalCount} critical threats detected!`,
      data: result,
      emailSent: emailSent,
    })
  } catch (error) {
    console.error("=== ATTACK SIMULATION ERROR ===", error)
    return NextResponse.json(
      {
        success: false,
        error: "Attack simulation failed",
        details: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 },
    )
  }
}
