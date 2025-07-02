import { NextResponse } from "next/server"

export async function POST(request: Request) {
  try {
    console.log("=== SIMULATION API CALLED ===")

    const { type } = await request.json()

    // Simulate processing time
    await new Promise((resolve) => setTimeout(resolve, 2000))

    const alerts = []
    const severities = ["Critical", "High", "Medium", "Low"]
    const attackTypes = [
      "SQL Injection Attempt",
      "Cross-Site Scripting Attack",
      "SSH Brute Force Attack",
      "Port Scan Detection",
      "Malware Communication",
      "DDoS Attack Pattern",
      "Buffer Overflow Attempt",
    ]
    const sourceIPs = ["192.168.1.100", "10.0.0.5", "172.16.0.10", "203.0.113.1"]

    // Generate 20 alerts
    for (let i = 0; i < 20; i++) {
      const severity = severities[Math.floor(Math.random() * severities.length)]
      const attackType = attackTypes[Math.floor(Math.random() * attackTypes.length)]
      const sourceIP = sourceIPs[Math.floor(Math.random() * sourceIPs.length)]

      alerts.push({
        alert_id: `ALERT-${String(i + 1).padStart(6, "0")}`,
        signature_name: attackType,
        severity: severity,
        src_ip: sourceIP,
        dst_ip: "192.168.1.1",
        src_port: 1024 + Math.floor(Math.random() * 64511),
        dst_port: [80, 443, 22, 21, 25, 53][Math.floor(Math.random() * 6)],
        protocol: "TCP",
        timestamp: new Date().toISOString(),
      })
    }

    const result = {
      system_status: {
        signatures_loaded: 8,
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
      },
      timestamp: new Date().toISOString(),
    }

    console.log("=== SIMULATION SUCCESS ===", {
      alertsGenerated: alerts.length,
      packetsProcessed: 1000,
    })

    return NextResponse.json({
      success: true,
      message: "Network simulation completed successfully",
      data: result,
    })
  } catch (error) {
    console.error("=== SIMULATION ERROR ===", error)
    return NextResponse.json(
      {
        success: false,
        error: "Simulation failed",
        details: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 },
    )
  }
}
