"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import {
  Search,
  Filter,
  AlertTriangle,
  Clock,
  CheckCircle,
  XCircle,
  Eye,
  Download,
  Ban,
  Mail,
  RefreshCw,
} from "lucide-react"

export default function InvestigationsPage() {
  const [alerts, setAlerts] = useState<any[]>([])
  const [filteredAlerts, setFilteredAlerts] = useState<any[]>([])
  const [alertStatuses, setAlertStatuses] = useState<Record<string, string>>({})
  const [selectedAlert, setSelectedAlert] = useState<any>(null)
  const [filters, setFilters] = useState({
    status: "unchecked",
    severity: "",
    search: "",
  })
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadAlerts()
  }, [])

  useEffect(() => {
    applyFilters()
  }, [alerts, filters, alertStatuses])

  const loadAlerts = async () => {
    try {
      const response = await fetch("/api/dashboard-data")
      const data = await response.json()
      if (data?.alerts) {
        setAlerts(data.alerts)
        // Initialize statuses
        const statuses: Record<string, string> = {}
        data.alerts.forEach((alert: any) => {
          statuses[alert.alert_id] = "unchecked"
        })
        setAlertStatuses(statuses)
      }
    } catch (error) {
      console.error("Failed to load alerts:", error)
    } finally {
      setLoading(false)
    }
  }

  const applyFilters = () => {
    let filtered = [...alerts]

    // Filter by status
    if (filters.status) {
      filtered = filtered.filter((alert) => (alertStatuses[alert.alert_id] || "unchecked") === filters.status)
    }

    // Filter by severity
    if (filters.severity) {
      filtered = filtered.filter((alert) => alert.severity === filters.severity)
    }

    // Filter by search
    if (filters.search) {
      const searchLower = filters.search.toLowerCase()
      filtered = filtered.filter(
        (alert) =>
          alert.signature_name.toLowerCase().includes(searchLower) ||
          alert.src_ip.includes(searchLower) ||
          alert.dst_ip.includes(searchLower) ||
          alert.alert_id.toLowerCase().includes(searchLower),
      )
    }

    setFilteredAlerts(filtered)
  }

  const updateAlertStatus = (alertId: string, status: string) => {
    setAlertStatuses((prev) => ({
      ...prev,
      [alertId]: status,
    }))
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "Critical":
        return "bg-red-100 text-red-800 border-red-200"
      case "High":
        return "bg-orange-100 text-orange-800 border-orange-200"
      case "Medium":
        return "bg-blue-100 text-blue-800 border-blue-200"
      case "Low":
        return "bg-green-100 text-green-800 border-green-200"
      default:
        return "bg-gray-100 text-gray-800 border-gray-200"
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case "resolved":
        return "bg-green-100 text-green-800 border-green-200"
      case "in-progress":
        return "bg-yellow-100 text-yellow-800 border-yellow-200"
      case "unchecked":
        return "bg-gray-100 text-gray-800 border-gray-200"
      default:
        return "bg-gray-100 text-gray-800 border-gray-200"
    }
  }

  const getStatusCounts = () => {
    const counts = {
      unchecked: 0,
      "in-progress": 0,
      resolved: 0,
    }

    alerts.forEach((alert) => {
      const status = alertStatuses[alert.alert_id] || "unchecked"
      counts[status as keyof typeof counts]++
    })

    return counts
  }

  const statusCounts = getStatusCounts()

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <RefreshCw className="h-8 w-8 animate-spin mx-auto mb-4 text-blue-600" />
          <p className="text-gray-600">Loading investigations...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center space-x-3">
              <Search className="h-8 w-8 text-blue-600" />
              <div>
                <h1 className="text-2xl font-semibold text-gray-900">Security Investigations</h1>
                <p className="text-sm text-gray-500">Manage and track security alert investigations</p>
              </div>
            </div>

            <div className="flex items-center space-x-4">
              <Button onClick={loadAlerts} variant="outline" size="sm">
                <RefreshCw className="h-4 w-4 mr-2" />
                Refresh
              </Button>
              <Button onClick={() => (window.location.href = "/")} variant="outline">
                ← Back to Dashboard
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Status Overview Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-gray-600">Unchecked</CardTitle>
              <XCircle className="h-4 w-4 text-gray-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-gray-900">{statusCounts.unchecked}</div>
              <p className="text-xs text-gray-500 mt-1">Awaiting investigation</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-gray-600">In Progress</CardTitle>
              <Clock className="h-4 w-4 text-yellow-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-yellow-600">{statusCounts["in-progress"]}</div>
              <p className="text-xs text-gray-500 mt-1">Currently investigating</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-gray-600">Resolved</CardTitle>
              <CheckCircle className="h-4 w-4 text-green-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-600">{statusCounts.resolved}</div>
              <p className="text-xs text-gray-500 mt-1">Investigation complete</p>
            </CardContent>
          </Card>
        </div>

        {/* Filters */}
        <Card className="mb-6">
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Filter className="h-5 w-5" />
              <span>Filters</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="text-sm font-medium text-gray-700 mb-2 block">Search</label>
                <Input
                  placeholder="Search alerts, IPs, or IDs..."
                  value={filters.search}
                  onChange={(e) => setFilters((prev) => ({ ...prev, search: e.target.value }))}
                />
              </div>
              <div>
                <label className="text-sm font-medium text-gray-700 mb-2 block">Status</label>
                <Select
                  value={filters.status}
                  onValueChange={(value) => setFilters((prev) => ({ ...prev, status: value }))}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="All statuses" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All statuses</SelectItem>
                    <SelectItem value="unchecked">Unchecked</SelectItem>
                    <SelectItem value="in-progress">In Progress</SelectItem>
                    <SelectItem value="resolved">Resolved</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <label className="text-sm font-medium text-gray-700 mb-2 block">Severity</label>
                <Select
                  value={filters.severity}
                  onValueChange={(value) => setFilters((prev) => ({ ...prev, severity: value }))}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="All severities" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All severities</SelectItem>
                    <SelectItem value="Critical">Critical</SelectItem>
                    <SelectItem value="High">High</SelectItem>
                    <SelectItem value="Medium">Medium</SelectItem>
                    <SelectItem value="Low">Low</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Alerts List */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Alerts List */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <span>Security Alerts ({filteredAlerts.length})</span>
                <AlertTriangle className="h-5 w-5 text-red-500" />
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4 max-h-96 overflow-y-auto">
                {filteredAlerts.map((alert, index) => (
                  <div
                    key={index}
                    className={`border rounded-lg p-4 cursor-pointer transition-colors ${
                      selectedAlert?.alert_id === alert.alert_id ? "border-blue-500 bg-blue-50" : "hover:bg-gray-50"
                    }`}
                    onClick={() => setSelectedAlert(alert)}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center space-x-2">
                        <Badge className={getSeverityColor(alert.severity)}>{alert.severity}</Badge>
                        <Badge className={getStatusColor(alertStatuses[alert.alert_id] || "unchecked")}>
                          {(alertStatuses[alert.alert_id] || "unchecked").replace("-", " ").toUpperCase()}
                        </Badge>
                      </div>
                      <span className="text-xs text-gray-500">{alert.alert_id}</span>
                    </div>
                    <h3 className="font-medium text-gray-900 mb-1">{alert.signature_name}</h3>
                    <p className="text-sm text-gray-500">
                      {alert.src_ip} → {alert.dst_ip}:{alert.dst_port}
                    </p>
                    <p className="text-xs text-gray-400 mt-1">{new Date(alert.timestamp).toLocaleString()}</p>
                  </div>
                ))}
                {filteredAlerts.length === 0 && (
                  <div className="text-center py-8 text-gray-500">
                    <AlertTriangle className="h-8 w-8 mx-auto mb-2 text-gray-400" />
                    <p>No alerts match the current filters</p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Investigation Details */}
          <Card>
            <CardHeader>
              <CardTitle>Investigation Details</CardTitle>
            </CardHeader>
            <CardContent>
              {selectedAlert ? (
                <div className="space-y-6">
                  {/* Status Control */}
                  <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                    <span className="font-medium">Investigation Status:</span>
                    <Select
                      value={alertStatuses[selectedAlert.alert_id] || "unchecked"}
                      onValueChange={(value) => updateAlertStatus(selectedAlert.alert_id, value)}
                    >
                      <SelectTrigger className="w-40">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="unchecked">Unchecked</SelectItem>
                        <SelectItem value="in-progress">In Progress</SelectItem>
                        <SelectItem value="resolved">Resolved</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  {/* Alert Details */}
                  <div className="space-y-4">
                    <div>
                      <label className="text-sm font-medium text-gray-500">Alert ID</label>
                      <p className="font-mono text-sm">{selectedAlert.alert_id}</p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-gray-500">Attack Type</label>
                      <p>{selectedAlert.signature_name}</p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-gray-500">Source</label>
                      <p className="font-mono">
                        {selectedAlert.src_ip}:{selectedAlert.src_port}
                      </p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-gray-500">Destination</label>
                      <p className="font-mono">
                        {selectedAlert.dst_ip}:{selectedAlert.dst_port}
                      </p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-gray-500">Detection Time</label>
                      <p>{new Date(selectedAlert.timestamp).toLocaleString()}</p>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex flex-wrap gap-2">
                    <Button size="sm" className="bg-red-600 hover:bg-red-700">
                      <Ban className="h-4 w-4 mr-1" />
                      Block IP
                    </Button>
                    <Button size="sm" variant="outline">
                      <Download className="h-4 w-4 mr-1" />
                      Report
                    </Button>
                    <Button size="sm" variant="outline">
                      <Mail className="h-4 w-4 mr-1" />
                      Alert
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => updateAlertStatus(selectedAlert.alert_id, "resolved")}
                    >
                      <CheckCircle className="h-4 w-4 mr-1" />
                      Resolve
                    </Button>
                  </div>
                </div>
              ) : (
                <div className="text-center py-8 text-gray-500">
                  <Eye className="h-8 w-8 mx-auto mb-2 text-gray-400" />
                  <p>Select an alert to view investigation details</p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  )
}
