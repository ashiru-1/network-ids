"use client"

import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts"

interface Alert {
  timestamp: string
}

interface TimelineChartProps {
  alerts: Alert[]
}

export function TimelineChart({ alerts }: TimelineChartProps) {
  console.log("TimelineChart received alerts:", alerts)

  // Validate alerts data
  if (!Array.isArray(alerts) || alerts.length === 0) {
    return (
      <div className="flex items-center justify-center h-[300px] text-gray-500">
        <div className="text-center">
          <div className="text-lg font-medium">No timeline data available</div>
          <div className="text-sm">Run a simulation to see alert patterns over time</div>
        </div>
      </div>
    )
  }

  // Group alerts by hour over the last 24 hours
  const now = new Date()
  const hourlyData = Array.from({ length: 24 }, (_, i) => {
    const hour = new Date(now.getTime() - (23 - i) * 60 * 60 * 1000)
    return {
      hour: hour.getHours().toString().padStart(2, "0") + ":00",
      alerts: 0,
      timestamp: hour.getTime(),
    }
  })

  // Count alerts for each hour
  alerts.forEach((alert) => {
    try {
      const alertTime = new Date(alert.timestamp)
      if (isNaN(alertTime.getTime())) {
        console.warn("Invalid timestamp:", alert.timestamp)
        return
      }

      const alertHour = alertTime.getHours()
      const dataPoint = hourlyData.find((h) => {
        const dataHour = new Date(h.timestamp).getHours()
        return dataHour === alertHour
      })
      if (dataPoint) {
        dataPoint.alerts++
      }
    } catch (error) {
      console.warn("Error processing alert timestamp:", alert.timestamp, error)
    }
  })

  console.log("Timeline chart data:", hourlyData)

  return (
    <div className="w-full h-[300px]">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={hourlyData} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
          <XAxis dataKey="hour" tick={{ fontSize: 12 }} axisLine={{ stroke: "#9ca3af" }} />
          <YAxis tick={{ fontSize: 12 }} axisLine={{ stroke: "#9ca3af" }} />
          <Tooltip
            formatter={(value) => [value, "Alerts"]}
            contentStyle={{
              backgroundColor: "white",
              border: "1px solid #ccc",
              borderRadius: "8px",
            }}
          />
          <Line
            type="monotone"
            dataKey="alerts"
            stroke="#3b82f6"
            strokeWidth={3}
            dot={{ fill: "#3b82f6", strokeWidth: 2, r: 4 }}
            activeDot={{ r: 6, fill: "#1d4ed8" }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}
