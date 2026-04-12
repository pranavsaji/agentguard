"use client"

import { useEffect, useState, useCallback } from "react"
import { useAuth } from "@clerk/nextjs"
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table"
import { apiClient, ComplianceFramework, ComplianceReport, ControlStatus } from "@/lib/api-client"
import { CheckSquare } from "lucide-react"

const FRAMEWORKS: { key: ComplianceFramework; label: string }[] = [
  { key: "SOC2", label: "SOC 2" },
  { key: "NIST_800_53", label: "NIST 800-53" },
  { key: "PCI_DSS", label: "PCI DSS" },
  { key: "ISO_27001", label: "ISO 27001" },
]

const CONTROL_STATUS_COLORS: Record<ControlStatus, string> = {
  PASS: "bg-green-100 text-green-800",
  FAIL: "bg-red-100 text-red-800",
  WARNING: "bg-yellow-100 text-yellow-800",
  NOT_APPLICABLE: "bg-gray-100 text-gray-600",
}

function scoreColor(score: number): string {
  if (score >= 80) return "#22c55e"
  if (score >= 60) return "#eab308"
  return "#ef4444"
}

function ScoreCircle({ score }: { score: number }) {
  const color = scoreColor(score)
  const radius = 44
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (score / 100) * circumference

  return (
    <div className="relative inline-flex items-center justify-center w-32 h-32">
      <svg className="absolute" width="128" height="128" viewBox="0 0 128 128">
        <circle cx="64" cy="64" r={radius} fill="none" stroke="#e5e7eb" strokeWidth="10" />
        <circle
          cx="64" cy="64" r={radius} fill="none"
          stroke={color} strokeWidth="10"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform="rotate(-90 64 64)"
        />
      </svg>
      <div className="text-center z-10">
        <span className="text-2xl font-bold" style={{ color }}>{score}%</span>
        <p className="text-xs text-gray-500 mt-0.5">overall</p>
      </div>
    </div>
  )
}

function SkeletonRow() {
  return (
    <TableRow>
      {[...Array(5)].map((_, i) => (
        <TableCell key={i}><div className="h-4 bg-gray-100 rounded animate-pulse" /></TableCell>
      ))}
    </TableRow>
  )
}

export default function CompliancePage() {
  const { getToken } = useAuth()
  const [framework, setFramework] = useState<ComplianceFramework>("SOC2")
  const [report, setReport] = useState<ComplianceReport | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchReport = useCallback(async (fw: ComplianceFramework) => {
    setLoading(true)
    setError(null)
    try {
      const token = await getToken()
      if (!token) return
      const data = await apiClient.compliance.report(token, fw)
      setReport(data)
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load report")
    } finally {
      setLoading(false)
    }
  }, [getToken])

  useEffect(() => { fetchReport(framework) }, [fetchReport, framework])

  const handleFrameworkChange = (fw: ComplianceFramework) => {
    setFramework(fw)
  }

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
          <CheckSquare className="h-6 w-6 text-blue-500" />
          Compliance Posture
        </h1>
        {report && (
          <p className="text-sm text-gray-500 mt-1">
            Last generated: {new Date(report.generated_at).toLocaleString()}
          </p>
        )}
      </div>

      {/* Framework tabs */}
      <div className="flex gap-1 border-b">
        {FRAMEWORKS.map(f => (
          <button
            key={f.key}
            onClick={() => handleFrameworkChange(f.key)}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              framework === f.key
                ? "border-blue-600 text-blue-600"
                : "border-transparent text-gray-500 hover:text-gray-700"
            }`}
          >
            {f.label}
          </button>
        ))}
      </div>

      {error ? (
        <div className="text-center py-12 text-red-500">{error}</div>
      ) : loading ? (
        <div className="space-y-4">
          <div className="flex items-center gap-8 rounded-lg border bg-white p-6 shadow-sm">
            <div className="w-32 h-32 rounded-full bg-gray-100 animate-pulse" />
            <div className="grid grid-cols-3 gap-6 flex-1">
              {[...Array(3)].map((_, i) => (
                <div key={i} className="rounded-lg border p-4 space-y-2">
                  <div className="h-4 bg-gray-100 rounded animate-pulse w-16" />
                  <div className="h-8 bg-gray-100 rounded animate-pulse" />
                </div>
              ))}
            </div>
          </div>
          <div className="rounded-lg border bg-white shadow-sm overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="bg-gray-50">
                  {["Control", "Name", "Status", "Evidence", "Affected"].map(h => (
                    <TableHead key={h}>{h}</TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>{[...Array(5)].map((_, i) => <SkeletonRow key={i} />)}</TableBody>
            </Table>
          </div>
        </div>
      ) : report ? (
        <>
          {/* Summary */}
          <div className="flex items-center gap-8 rounded-lg border bg-white p-6 shadow-sm">
            <ScoreCircle score={report.overall_score} />
            <div className="grid grid-cols-3 gap-4 flex-1">
              <div className="rounded-lg border p-4 text-center">
                <p className="text-xs text-gray-500 mb-1">Passing</p>
                <p className="text-3xl font-bold text-green-600">{report.controls_passing}</p>
              </div>
              <div className="rounded-lg border p-4 text-center">
                <p className="text-xs text-gray-500 mb-1">Failing</p>
                <p className="text-3xl font-bold text-red-500">{report.controls_failing}</p>
              </div>
              <div className="rounded-lg border p-4 text-center">
                <p className="text-xs text-gray-500 mb-1">Warnings</p>
                <p className="text-3xl font-bold text-yellow-500">{report.controls_warning}</p>
              </div>
            </div>
          </div>

          {/* Controls table */}
          <div className="rounded-lg border bg-white shadow-sm overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="bg-gray-50">
                  <TableHead>Control ID</TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Evidence</TableHead>
                  <TableHead>Affected</TableHead>
                  <TableHead>Remediation</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {report.controls.length === 0 ? (
                  <TableRow><TableCell colSpan={6} className="text-center py-12 text-gray-400">No controls found</TableCell></TableRow>
                ) : report.controls.map(ctrl => (
                  <TableRow key={ctrl.control_id} className="hover:bg-gray-50">
                    <TableCell className="font-mono text-xs text-gray-600">{ctrl.control_id}</TableCell>
                    <TableCell className="font-medium text-sm">{ctrl.control_name}</TableCell>
                    <TableCell>
                      <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${CONTROL_STATUS_COLORS[ctrl.status]}`}>
                        {ctrl.status.replace("_", " ")}
                      </span>
                    </TableCell>
                    <TableCell className="text-xs text-gray-500 max-w-[200px] truncate">{ctrl.evidence}</TableCell>
                    <TableCell className="text-sm text-gray-600">{ctrl.affected_count}</TableCell>
                    <TableCell className="text-xs text-gray-500 max-w-[180px] truncate">
                      {ctrl.remediation ?? <span className="text-gray-300">—</span>}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </>
      ) : null}
    </div>
  )
}
