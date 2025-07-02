"use client"

import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from "recharts"

interface Alert {
  severity: string
}

interface SimpleAlertsChartProps {
  alerts: Alert[]
}

const COLORS = {
  Critical: "#dc2626",
  High: "#ea580c",
  Medium: "#2563eb",
  Low: "#059669",
}

export function SimpleAlertsChart({ alerts }: SimpleAlertsChartProps) {
  console.log("SimpleAlertsChart - alerts received:", alerts?.length || 0)

  if (!alerts || alerts.length === 0) {
    return (
      <div className="h-64 flex items-center justify-center text-gray-500">
        <div className="text-center">
          <div className="text-lg font-medium">No Alert Data</div>
          <div className="text-sm">Run simulation to generate alerts</div>
        </div>
      </div>
    )
  }

  // Count alerts by severity
  const severityCounts = alerts.reduce(
    (acc, alert) => {
      const severity = alert.severity || "Unknown"
      acc[severity] = (acc[severity] || 0) + 1
      return acc
    },
    {} as Record<string, number>,
  )

  const data = Object.entries(severityCounts).map(([severity, count]) => ({
    name: severity,
    value: count,
    color: COLORS[severity as keyof typeof COLORS] || "#6b7280",
  }))

  console.log("Chart data prepared:", data)

  return (
    <div className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie data={data} cx="50%" cy="50%" innerRadius={50} outerRadius={100} paddingAngle={2} dataKey="value">
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip
            formatter={(value, name) => [value, `${name} Alerts`]}
            contentStyle={{
              backgroundColor: "white",
              border: "1px solid #e5e7eb",
              borderRadius: "6px",
              boxShadow: "0 4px 6px -1px rgba(0, 0, 0, 0.1)",
            }}
          />
          <Legend verticalAlign="bottom" height={36} iconType="circle" />
        </PieChart>
      </ResponsiveContainer>
    </div>
  )
}
