"use client"

import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"

interface Alert {
  alert_id: string
  signature_name: string
  severity: string
  src_ip: string
  dst_ip: string
  dst_port: number
  protocol: string
  timestamp: string
}

interface AlertsTableProps {
  alerts: Alert[]
}

export function AlertsTable({ alerts }: AlertsTableProps) {
  const getSeverityVariant = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return "destructive"
      case "high":
        return "destructive"
      case "medium":
        return "default"
      case "low":
        return "secondary"
      default:
        return "default"
    }
  }

  const sortedAlerts = [...alerts]
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, 20)

  return (
    <div className="rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Time</TableHead>
            <TableHead>Severity</TableHead>
            <TableHead>Attack Type</TableHead>
            <TableHead>Source IP</TableHead>
            <TableHead>Destination</TableHead>
            <TableHead>Protocol</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {sortedAlerts.map((alert) => (
            <TableRow key={alert.alert_id} className="hover:bg-muted/50">
              <TableCell className="font-mono text-sm">{new Date(alert.timestamp).toLocaleTimeString()}</TableCell>
              <TableCell>
                <Badge variant={getSeverityVariant(alert.severity)}>{alert.severity}</Badge>
              </TableCell>
              <TableCell className="font-medium">{alert.signature_name}</TableCell>
              <TableCell className="font-mono">{alert.src_ip}</TableCell>
              <TableCell className="font-mono">
                {alert.dst_ip}:{alert.dst_port}
              </TableCell>
              <TableCell>{alert.protocol}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}
