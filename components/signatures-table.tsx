"use client"

import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"

interface Signature {
  signature_id: string
  name: string
  severity: string
  protocol: string
  description: string
}

interface SignaturesTableProps {
  signatures: Signature[]
}

export function SignaturesTable({ signatures }: SignaturesTableProps) {
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

  return (
    <div className="rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>ID</TableHead>
            <TableHead>Name</TableHead>
            <TableHead>Severity</TableHead>
            <TableHead>Protocol</TableHead>
            <TableHead>Status</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {signatures.map((signature) => (
            <TableRow key={signature.signature_id} className="hover:bg-muted/50">
              <TableCell className="font-mono">{signature.signature_id}</TableCell>
              <TableCell className="font-medium">{signature.name}</TableCell>
              <TableCell>
                <Badge variant={getSeverityVariant(signature.severity)}>{signature.severity}</Badge>
              </TableCell>
              <TableCell>{signature.protocol}</TableCell>
              <TableCell>
                <div className="flex items-center space-x-2">
                  <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                  <span className="text-sm">Active</span>
                </div>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}
