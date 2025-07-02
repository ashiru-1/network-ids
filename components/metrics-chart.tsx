"use client"

import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts"

interface Metrics {
  accuracy: number
  precision: number
  recall: number
  f1_score: number
}

interface MetricsChartProps {
  metrics: Metrics
}

export function MetricsChart({ metrics }: MetricsChartProps) {
  console.log("MetricsChart received metrics:", metrics)

  // Validate metrics data
  if (!metrics || typeof metrics !== "object") {
    return (
      <div className="flex items-center justify-center h-[300px] text-gray-500">
        <div className="text-center">
          <div className="text-lg font-medium">No metrics data available</div>
          <div className="text-sm">Run a simulation to generate performance metrics</div>
        </div>
      </div>
    )
  }

  const data = [
    {
      name: "Accuracy",
      value: Math.round((metrics.accuracy || 0) * 100),
      fill: "#3b82f6",
    },
    {
      name: "Precision",
      value: Math.round((metrics.precision || 0) * 100),
      fill: "#10b981",
    },
    {
      name: "Recall",
      value: Math.round((metrics.recall || 0) * 100),
      fill: "#f59e0b",
    },
    {
      name: "F1 Score",
      value: Math.round((metrics.f1_score || 0) * 100),
      fill: "#ef4444",
    },
  ]

  console.log("Metrics chart data:", data)

  return (
    <div className="w-full h-[300px]">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
          <XAxis dataKey="name" tick={{ fontSize: 12 }} axisLine={{ stroke: "#9ca3af" }} />
          <YAxis domain={[0, 100]} tick={{ fontSize: 12 }} axisLine={{ stroke: "#9ca3af" }} />
          <Tooltip
            formatter={(value) => [`${value}%`, "Performance"]}
            contentStyle={{
              backgroundColor: "white",
              border: "1px solid #ccc",
              borderRadius: "8px",
            }}
          />
          <Bar dataKey="value" radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
