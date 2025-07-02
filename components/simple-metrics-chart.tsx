"use client"

import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts"

interface Metrics {
  accuracy: number
  precision: number
  recall: number
  f1_score: number
}

interface SimpleMetricsChartProps {
  metrics: Metrics
}

export function SimpleMetricsChart({ metrics }: SimpleMetricsChartProps) {
  console.log("SimpleMetricsChart - metrics received:", metrics)

  if (!metrics) {
    return (
      <div className="h-64 flex items-center justify-center text-gray-500">
        <div className="text-center">
          <div className="text-lg font-medium">No Metrics Data</div>
          <div className="text-sm">Run simulation to generate performance data</div>
        </div>
      </div>
    )
  }

  const data = [
    {
      name: "Accuracy",
      value: Math.round((metrics.accuracy || 0) * 100),
      fill: "#2563eb",
    },
    {
      name: "Precision",
      value: Math.round((metrics.precision || 0) * 100),
      fill: "#059669",
    },
    {
      name: "Recall",
      value: Math.round((metrics.recall || 0) * 100),
      fill: "#ea580c",
    },
    {
      name: "F1 Score",
      value: Math.round((metrics.f1_score || 0) * 100),
      fill: "#dc2626",
    },
  ]

  console.log("Metrics chart data prepared:", data)

  return (
    <div className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6" />
          <XAxis dataKey="name" tick={{ fontSize: 12, fill: "#6b7280" }} axisLine={{ stroke: "#d1d5db" }} />
          <YAxis domain={[0, 100]} tick={{ fontSize: 12, fill: "#6b7280" }} axisLine={{ stroke: "#d1d5db" }} />
          <Tooltip
            formatter={(value) => [`${value}%`, "Performance"]}
            contentStyle={{
              backgroundColor: "white",
              border: "1px solid #e5e7eb",
              borderRadius: "6px",
              boxShadow: "0 4px 6px -1px rgba(0, 0, 0, 0.1)",
            }}
          />
          <Bar dataKey="value" radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
