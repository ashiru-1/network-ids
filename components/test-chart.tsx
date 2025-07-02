"use client"

import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer } from "recharts"

const testData = [
  { name: "Test 1", value: 10 },
  { name: "Test 2", value: 20 },
  { name: "Test 3", value: 15 },
]

export function TestChart() {
  return (
    <div className="w-full h-[200px] border border-gray-300 rounded p-4">
      <h3 className="text-lg font-semibold mb-2">Test Chart</h3>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={testData}>
          <XAxis dataKey="name" />
          <YAxis />
          <Bar dataKey="value" fill="#3b82f6" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
