"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import {
  Shield,
  RefreshCw,
  Play,
  AlertTriangle,
  Network,
  Activity,
  CheckCircle,
  XCircle,
  Clock,
  Search,
  Mail,
  Bug,
  FileText,
  Zap,
  Download,
  Ban,
} from "lucide-react"

export default function Dashboard() {
  const [loading, setLoading] = useState(false)
  const [data, setData] = useState<any>(null)
  const [error, setError] = useState<string | null>(null)
  const [isRunning, setIsRunning] = useState(false)
  const [isAttackRunning, setIsAttackRunning] = useState(false)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null)
  const [selectedAlert, setSelectedAlert] = useState<any>(null)
  const [showBlockModal, setShowBlockModal] = useState(false)
  const [blockingIP, setBlockingIP] = useState("")
  const [isBlocking, setIsBlocking] = useState(false)
  const [isGeneratingReport, setIsGeneratingReport] = useState(false)
  const [currentView, setCurrentView] = useState<"dashboard" | "investigation">("dashboard")
  const [alertStatuses, setAlertStatuses] = useState<Record<string, string>>({})

  const handleRunSimulation = async () => {
    console.log("Starting normal simulation...")
    setIsRunning(true)
    setError(null)

    try {
      const response = await fetch("/api/run-simulation", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type: "normal" }),
      })

      const result = await response.json()
      if (result.success) {
        setData(result.data)
        setLastUpdate(new Date())
      } else {
        setError(result.error || "Simulation failed")
      }
    } catch (err) {
      setError("Network error: Unable to connect to simulation service")
    } finally {
      setIsRunning(false)
    }
  }

  const handleAttackSimulation = async () => {
    console.log("Starting attack simulation...")
    setIsAttackRunning(true)
    setError(null)

    try {
      const response = await fetch("/api/simulate-attack", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          attackType: "multi-vector",
          emailNotification: true,
        }),
      })

      const result = await response.json()
      if (result.success) {
        setData(result.data)
        setLastUpdate(new Date())
        if (result.emailSent) {
          alert("🚨 Critical alerts detected! Email notification sent to security team.")
        }
      } else {
        setError(result.error || "Attack simulation failed")
      }
    } catch (err) {
      setError("Network error: Unable to connect to attack simulation service")
    } finally {
      setIsAttackRunning(false)
    }
  }

  const handleRefresh = async () => {
    if (!data) return

    setIsRefreshing(true)
    setError(null)

    try {
      const response = await fetch("/api/dashboard-data")
      const result = await response.json()

      if (result) {
        setData(result)
        setLastUpdate(new Date())
      } else {
        setError("Failed to refresh data")
      }
    } catch (err) {
      setError("Network error: Unable to refresh data")
    } finally {
      setIsRefreshing(false)
    }
  }

  const handleInvestigateAlert = (alert: any) => {
    setSelectedAlert(alert)
    setCurrentView("investigation")
    // Set default status if not already set
    if (!alertStatuses[alert.alert_id]) {
      setAlertStatuses((prev) => ({
        ...prev,
        [alert.alert_id]: "unchecked",
      }))
    }
  }

  const handleBackToDashboard = () => {
    setCurrentView("dashboard")
    setSelectedAlert(null)
  }

  const handleBlockIP = async () => {
    if (!selectedAlert) return

    setBlockingIP(selectedAlert.src_ip)
    setIsBlocking(true)
    setShowBlockModal(true)

    // Simulate blocking process
    await new Promise((resolve) => setTimeout(resolve, 2000))
    setIsBlocking(false)

    // Auto-close modal after 3 seconds
    setTimeout(() => {
      setShowBlockModal(false)
      setBlockingIP("")
    }, 3000)
  }

  const handleGenerateReport = async () => {
    if (!selectedAlert) return

    setIsGeneratingReport(true)

    try {
      const response = await fetch("/api/generate-report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alert: selectedAlert }),
      })

      if (response.ok) {
        const blob = await response.blob()
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement("a")
        a.style.display = "none"
        a.href = url
        a.download = `security-report-${selectedAlert.alert_id}.pdf`
        document.body.appendChild(a)
        a.click()
        window.URL.revokeObjectURL(url)
        document.body.removeChild(a)

        alert("✅ Security report generated and downloaded successfully!")
      } else {
        throw new Error("Failed to generate report")
      }
    } catch (err) {
      alert("❌ Failed to generate report. Please try again.")
    } finally {
      setIsGeneratingReport(false)
    }
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

  const updateAlertStatus = (alertId: string, status: string) => {
    setAlertStatuses((prev) => ({
      ...prev,
      [alertId]: status,
    }))
  }

  if (currentView === "investigation") {
    return (
      <div className="min-h-screen bg-gray-50">
        {/* Block IP Modal */}
        {showBlockModal && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-lg p-8 max-w-md w-full mx-4 transform transition-all duration-300 scale-100">
              <div className="text-center">
                {isBlocking ? (
                  <>
                    <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-red-600 mx-auto mb-4"></div>
                    <h3 className="text-lg font-semibold text-gray-900 mb-2">Blocking IP Address</h3>
                    <p className="text-gray-600">Processing security action for {blockingIP}...</p>
                  </>
                ) : (
                  <>
                    <div className="relative mx-auto mb-4 w-16 h-16">
                      <div className="absolute inset-0 bg-green-100 rounded-full animate-ping"></div>
                      <div className="relative bg-green-500 rounded-full w-16 h-16 flex items-center justify-center">
                        <CheckCircle className="h-8 w-8 text-white animate-bounce" />
                      </div>
                    </div>
                    <h3 className="text-lg font-semibold text-green-800 mb-2">IP Address Blocked Successfully!</h3>
                    <p className="text-gray-600 mb-4">
                      Source IP <span className="font-mono font-semibold">{blockingIP}</span> has been blocked from
                      accessing the network.
                    </p>
                    <div className="bg-green-50 border border-green-200 rounded-lg p-3">
                      <p className="text-sm text-green-700">
                        ✅ Firewall rules updated
                        <br />✅ Traffic from {blockingIP} blocked
                        <br />✅ Security team notified
                      </p>
                    </div>
                  </>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Investigation Header */}
        <header className="bg-white border-b border-gray-200 shadow-sm">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between items-center py-4">
              <div className="flex items-center space-x-4">
                <Button onClick={handleBackToDashboard} variant="outline" size="sm">
                  ← Back to Dashboard
                </Button>
                <div className="flex items-center space-x-3">
                  <Search className="h-8 w-8 text-blue-600" />
                  <div>
                    <h1 className="text-2xl font-semibold text-gray-900">Alert Investigation</h1>
                    <p className="text-sm text-gray-500">Detailed analysis and response management</p>
                  </div>
                </div>
              </div>

              <div className="flex items-center space-x-4">
                <div className="flex items-center space-x-2">
                  <span className="text-sm text-gray-500">Status:</span>
                  <select
                    value={alertStatuses[selectedAlert?.alert_id] || "unchecked"}
                    onChange={(e) => updateAlertStatus(selectedAlert?.alert_id, e.target.value)}
                    className="px-3 py-1 border border-gray-300 rounded-md text-sm"
                  >
                    <option value="unchecked">Unchecked</option>
                    <option value="in-progress">In Progress</option>
                    <option value="resolved">Resolved</option>
                  </select>
                </div>
              </div>
            </div>
          </div>
        </header>

        {/* Investigation Content */}
        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {selectedAlert && (
            <div className="space-y-6">
              {/* Alert Status Banner */}
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-4">
                    <Badge className={getSeverityColor(selectedAlert.severity)}>{selectedAlert.severity}</Badge>
                    <Badge className={getStatusColor(alertStatuses[selectedAlert.alert_id] || "unchecked")}>
                      {(alertStatuses[selectedAlert.alert_id] || "unchecked").replace("-", " ").toUpperCase()}
                    </Badge>
                    <h2 className="text-xl font-semibold text-gray-900">{selectedAlert.signature_name}</h2>
                  </div>
                  <div className="text-sm text-gray-500">Alert ID: {selectedAlert.alert_id}</div>
                </div>
              </div>

              {/* Alert Overview */}
              <Card>
                <CardHeader>
                  <CardTitle>Alert Overview</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 gap-6">
                    <div>
                      <label className="text-sm font-medium text-gray-500">Alert ID</label>
                      <p className="font-mono text-sm mt-1">{selectedAlert.alert_id}</p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-gray-500">Severity</label>
                      <div className="mt-1">
                        <Badge className={getSeverityColor(selectedAlert.severity)}>{selectedAlert.severity}</Badge>
                      </div>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-gray-500">Attack Type</label>
                      <p className="mt-1">{selectedAlert.signature_name}</p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-gray-500">Detection Time</label>
                      <p className="mt-1">{new Date(selectedAlert.timestamp).toLocaleString()}</p>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Network Details */}
              <Card>
                <CardHeader>
                  <CardTitle>Network Details</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 gap-6">
                    <div>
                      <label className="text-sm font-medium text-gray-500">Source IP</label>
                      <p className="font-mono mt-1">
                        {selectedAlert.src_ip}:{selectedAlert.src_port}
                      </p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-gray-500">Destination IP</label>
                      <p className="font-mono mt-1">
                        {selectedAlert.dst_ip}:{selectedAlert.dst_port}
                      </p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-gray-500">Protocol</label>
                      <p className="mt-1">{selectedAlert.protocol}</p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-gray-500">Signature ID</label>
                      <p className="font-mono mt-1">{selectedAlert.signature_id}</p>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Payload Analysis */}
              {selectedAlert.payload_snippet && (
                <Card>
                  <CardHeader>
                    <CardTitle>Payload Analysis</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <pre className="bg-gray-50 p-4 rounded-lg text-sm font-mono overflow-x-auto border">
                      {selectedAlert.payload_snippet}
                    </pre>
                  </CardContent>
                </Card>
              )}

              {/* Threat Intelligence */}
              <Card>
                <CardHeader>
                  <CardTitle>Threat Intelligence</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div>
                      <label className="text-sm font-medium text-gray-500">Risk Level</label>
                      <p className="mt-1">{selectedAlert.severity}</p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-gray-500">Attack Vector</label>
                      <p className="mt-1">{selectedAlert.signature_name}</p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-gray-500">Recommended Action</label>
                      <p className="mt-1">
                        {selectedAlert.severity === "Critical"
                          ? "Immediate isolation and investigation required"
                          : selectedAlert.severity === "High"
                            ? "Block source IP and monitor"
                            : selectedAlert.severity === "Medium"
                              ? "Monitor and log for patterns"
                              : "Continue monitoring"}
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Response Actions */}
              <Card>
                <CardHeader>
                  <CardTitle>Response Actions</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex flex-wrap gap-4">
                    <Button onClick={handleBlockIP} className="bg-red-600 hover:bg-red-700">
                      <Ban className="h-4 w-4 mr-2" />
                      Block Source IP
                    </Button>
                    <Button variant="outline">
                      <Mail className="h-4 w-4 mr-2" />
                      Send Alert
                    </Button>
                    <Button onClick={handleGenerateReport} variant="outline" disabled={isGeneratingReport}>
                      {isGeneratingReport ? (
                        <>
                          <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                          Generating...
                        </>
                      ) : (
                        <>
                          <Download className="h-4 w-4 mr-2" />
                          Generate Report
                        </>
                      )}
                    </Button>
                    <Button variant="outline" onClick={() => updateAlertStatus(selectedAlert.alert_id, "resolved")}>
                      <CheckCircle className="h-4 w-4 mr-2" />
                      Mark as Resolved
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </div>
          )}
        </main>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col gap-4 sm:flex-row sm:justify-between sm:items-center py-4 text-center sm:text-left">
            <div className="flex flex-col sm:flex-row items-center sm:space-x-4 gap-2 sm:gap-0 w-full sm:w-auto justify-center sm:justify-start">
              <div className="flex items-center space-x-3 justify-center">
                <Shield className="h-8 w-8 text-blue-600" />
                <div>
                  <h1 className="text-2xl font-semibold text-gray-900">Network IDS</h1>
                  <p className="text-sm text-gray-500">Advanced Intrusion Detection & Response</p>
                </div>
              </div>
            </div>

            <div className="flex flex-wrap justify-center sm:justify-end items-center gap-2 sm:space-x-4 w-full sm:w-auto">
              {lastUpdate && (
                <div className="flex items-center space-x-2 text-sm text-gray-500">
                  <Clock className="h-4 w-4" />
                  <span>Last updated: {lastUpdate.toLocaleTimeString()}</span>
                </div>
              )}

              <Button onClick={handleRefresh} disabled={isRefreshing || !data} variant="outline" size="sm">
                {isRefreshing ? (
                  <>
                    <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                    Refreshing...
                  </>
                ) : (
                  <>
                    <RefreshCw className="h-4 w-4 mr-2" />
                    Refresh
                  </>
                )}
              </Button>

              <Button onClick={handleRunSimulation} disabled={isRunning} variant="outline">
                {isRunning ? (
                  <>
                    <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                    Running...
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4 mr-2" />
                    Normal Simulation
                  </>
                )}
              </Button>

              {/* Group Simulate Attack and Manage Investigations buttons for mobile */}
              <div className="flex flex-row gap-2 w-full sm:w-auto justify-center sm:inline-flex">
                <Button
                  onClick={handleAttackSimulation}
                  disabled={isAttackRunning}
                  className="bg-red-600 hover:bg-red-700"
                  size="sm"
                >
                  {isAttackRunning ? (
                    <>
                      <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                      Simulating Attack...
                    </>
                  ) : (
                    <>
                      <Bug className="h-4 w-4 mr-2" />
                      Simulate Attack
                    </>
                  )}
                </Button>

                <Button
                  onClick={() => (window.location.href = "/investigations")}
                  className="bg-blue-600 hover:bg-blue-700"
                  size="sm"
                >
                  <Search className="h-4 w-4 mr-2" />
                  Manage Investigations
                </Button>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Error Alert */}
        {error && (
          <Alert className="mb-6 border-red-200 bg-red-50">
            <XCircle className="h-4 w-4 text-red-600" />
            <AlertDescription className="text-red-800">{error}</AlertDescription>
          </Alert>
        )}

        {/* Success Alert */}
        {data && !error && (
          <Alert className="mb-6 border-green-200 bg-green-50">
            <CheckCircle className="h-4 w-4 text-green-600" />
            <AlertDescription className="text-green-800">
              Analysis completed. {data.system_status?.alerts_generated || 0} alerts generated from{" "}
              {data.system_status?.packets_processed || 0} packets.
              {data.criticalAlertsCount > 0 && ` ${data.criticalAlertsCount} critical threats detected!`}
            </AlertDescription>
          </Alert>
        )}

        {/* Critical Alerts Banner */}
        {data?.alerts && data.alerts.filter((alert: any) => alert.severity === "Critical").length > 0 && (
          <Alert className="mb-6 border-red-200 bg-red-50">
            <AlertTriangle className="h-4 w-4 text-red-600" />
            <AlertDescription className="text-red-800 flex items-center justify-between">
              <span>
                🚨 {data.alerts.filter((alert: any) => alert.severity === "Critical").length} critical security threats
                detected! Immediate investigation required.
              </span>
              <Button
                onClick={() => (window.location.href = "/investigations")}
                className="bg-red-600 hover:bg-red-700 ml-4"
                size="sm"
              >
                <Search className="h-4 w-4 mr-2" />
                Investigate Now
              </Button>
            </AlertDescription>
          </Alert>
        )}

        {/* System Status Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-gray-600">Total Alerts</CardTitle>
              <AlertTriangle className="h-4 w-4 text-red-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-gray-900">{data?.system_status?.alerts_generated || 0}</div>
              <p className="text-xs text-gray-500 mt-1">Security incidents detected</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-gray-600">Critical Threats</CardTitle>
              <Zap className="h-4 w-4 text-red-600" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-red-600">{data?.criticalAlertsCount || 0}</div>
              <p className="text-xs text-gray-500 mt-1">Immediate attention required</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-gray-600">Packets Processed</CardTitle>
              <Network className="h-4 w-4 text-blue-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-gray-900">
                {data?.system_status?.packets_processed?.toLocaleString() || 0}
              </div>
              <p className="text-xs text-gray-500 mt-1">Network packets analyzed</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-gray-600">Detection Rate</CardTitle>
              <Activity className="h-4 w-4 text-green-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-gray-900">
                {data?.metrics?.accuracy ? `${Math.round(data.metrics.accuracy * 100)}%` : "0%"}
              </div>
              <p className="text-xs text-gray-500 mt-1">Threat detection accuracy</p>
            </CardContent>
          </Card>
        </div>

        {/* Main Content Tabs */}
        <Tabs defaultValue="alerts" className="space-y-6">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="alerts">Security Alerts</TabsTrigger>
            <TabsTrigger value="logs">System Logs</TabsTrigger>
          </TabsList>

          {/* Security Alerts Tab */}
          <TabsContent value="alerts">
            {data?.alerts && data.alerts.length > 0 ? (
              <div className="space-y-6">
                {/* Call to Action Card */}
                <Card className="border-blue-200 bg-blue-50">
                  <CardContent className="pt-6">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-4">
                        <div className="bg-blue-100 p-3 rounded-full">
                          <Search className="h-6 w-6 text-blue-600" />
                        </div>
                        <div>
                          <h3 className="text-lg font-semibold text-blue-900">Advanced Investigation Management</h3>
                          <p className="text-blue-700">
                            Track alert statuses, filter by criteria, and manage investigations efficiently
                          </p>
                        </div>
                      </div>
                      <Button
                        onClick={() => (window.location.href = "/investigations")}
                        className="bg-blue-600 hover:bg-blue-700"
                      >
                        <Search className="h-4 w-4 mr-2" />
                        Open Investigations
                      </Button>
                    </div>
                  </CardContent>
                </Card>

                {/* Existing alerts card */}
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center space-x-2">
                      <AlertTriangle className="h-5 w-5 text-red-500" />
                      <span>Security Alerts</span>
                    </CardTitle>
                    <p className="text-sm text-gray-500">Click on any alert to open detailed investigation</p>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      {data.alerts.slice(0, 20).map((alert: any, index: number) => (
                        <div
                          key={index}
                          className="border rounded-lg p-4 hover:bg-gray-50 cursor-pointer transition-colors"
                          onClick={() => handleInvestigateAlert(alert)}
                        >
                          <div className="flex items-center justify-between">
                            <div className="flex items-center space-x-4">
                              <Badge className={getSeverityColor(alert.severity)}>{alert.severity}</Badge>
                              {alertStatuses[alert.alert_id] && (
                                <Badge className={getStatusColor(alertStatuses[alert.alert_id])}>
                                  {alertStatuses[alert.alert_id].replace("-", " ").toUpperCase()}
                                </Badge>
                              )}
                              <div>
                                <h3 className="font-medium text-gray-900">{alert.signature_name}</h3>
                                <p className="text-sm text-gray-500">
                                  {alert.src_ip} → {alert.dst_ip}:{alert.dst_port} ({alert.protocol})
                                </p>
                              </div>
                            </div>
                            <div className="flex items-center space-x-4">
                              <span className="text-sm text-gray-500">
                                {new Date(alert.timestamp).toLocaleString()}
                              </span>
                              <Search className="h-4 w-4 text-blue-500" />
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              </div>
            ) : (
              <Card className="text-center py-12">
                <CardContent>
                  <Shield className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                  <h3 className="text-lg font-medium text-gray-900 mb-2">No Alerts</h3>
                  <p className="text-gray-500 mb-6">
                    Run a simulation to generate network traffic and detect security threats.
                  </p>
                  <div className="space-x-4">
                    <Button onClick={handleRunSimulation} variant="outline">
                      <Play className="h-4 w-4 mr-2" />
                      Normal Traffic
                    </Button>
                    <Button onClick={handleAttackSimulation} className="bg-red-600 hover:bg-red-700">
                      <Bug className="h-4 w-4 mr-2" />
                      Simulate Attack
                    </Button>
                  </div>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* System Logs Tab */}
          <TabsContent value="logs">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <FileText className="h-5 w-5 text-gray-500" />
                  <span>System Logs</span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="bg-black text-green-400 p-4 rounded-lg font-mono text-sm h-96 overflow-y-auto">
                  {data?.systemLogs ? (
                    data.systemLogs.map((log: string, index: number) => (
                      <div key={index} className="mb-1">
                        {log}
                      </div>
                    ))
                  ) : (
                    <div className="text-gray-500">
                      [INFO] Network IDS System Ready
                      <br />
                      [INFO] Signature database loaded: 8 rules
                      <br />
                      [INFO] Monitoring interfaces: eth0, eth1
                      <br />
                      [INFO] Real-time analysis: ACTIVE
                      <br />
                      [INFO] Email notifications: ENABLED
                      <br />
                      [INFO] Waiting for network traffic...
                      <br />
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </main>
      {/* Floating Action Button for Investigations */}
      {data?.alerts && data.alerts.length > 0 && (
        <div className="fixed bottom-6 right-6 z-50">
          <Button
            onClick={() => (window.location.href = "/investigations")}
            className="bg-blue-600 hover:bg-blue-700 shadow-lg hover:shadow-xl transition-all duration-300 rounded-full h-14 w-14 p-0"
            title="Manage Investigations"
          >
            <div className="relative">
              <Search className="h-6 w-6" />
              {/* Badge showing unresolved alerts count */}
              {Object.values(alertStatuses).filter((status) => status !== "resolved").length > 0 && (
                <div className="absolute -top-2 -right-2 bg-red-500 text-white text-xs rounded-full h-5 w-5 flex items-center justify-center">
                  {Object.values(alertStatuses).filter((status) => status !== "resolved").length}
                </div>
              )}
            </div>
          </Button>
        </div>
      )}
    </div>
  )
}
