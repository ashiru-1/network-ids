"use client"

import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from "recharts"

interface Alert {
  severity: string
}

interface AlertsChartProps {
  alerts: Alert[]
}

const COLORS = {
  Critical: "#ef4444",
  High: "#f59e0b",
  Medium: "#3b82f6",
  Low: "#10b981",
}

export function AlertsChart({ alerts }: AlertsChartProps) {
  console.log("AlertsChart received alerts:", alerts)

  // Ensure alerts is an array
  if (!Array.isArray(alerts) || alerts.length === 0) {
    return (
      <div className="flex items-center justify-center h-[300px] text-gray-500">
        <div className="text-center">
          <div className="text-lg font-medium">No alert data available</div>
          <div className="text-sm">Run a simulation to generate alerts</div>
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

  console.log("Chart data:", data)

  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-[300px] text-gray-500">
        <div className="text-center">
          <div className="text-lg font-medium">No alerts to display</div>
          <div className="text-sm">Click "Run Simulation" to generate sample data</div>
        </div>
      </div>
    )
  }

  return (
    <div className="w-full h-[300px]">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie data={data} cx="50%" cy="50%" innerRadius={60} outerRadius={120} paddingAngle={5} dataKey="value">
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip
            formatter={(value, name) => [value, `${name} Alerts`]}
            contentStyle={{
              backgroundColor: "white",
              border: "1px solid #ccc",
              borderRadius: "8px",
            }}
          />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
    </div>
  )
}
