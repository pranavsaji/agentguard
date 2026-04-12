"use client"

import { useEffect, useState } from "react"
import { useAuth } from "@clerk/nextjs"
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts"
import { apiClient, NHIIdentity, Severity } from "@/lib/api-client"
import { AlertTriangle, ShieldCheck, Shield, ShieldX } from "lucide-react"

const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#22c55e",
}

interface SeverityCount { severity: Severity; count: number }

function SeverityCard({ severity, count, icon: Icon }: { severity: Severity; count: number; icon: any }) {
  return (
    <div className="rounded-lg border bg-white p-5 shadow-sm">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-500">{severity}</p>
          <p className="text-3xl font-bold mt-1" style={{ color: SEVERITY_COLORS[severity] }}>{count}</p>
        </div>
        <Icon className="h-8 w-8 opacity-20" style={{ color: SEVERITY_COLORS[severity] }} />
      </div>
    </div>
  )
}

export default function RiskPage() {
  const { getToken } = useAuth()
  const [identities, setIdentities] = useState<NHIIdentity[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    ;(async () => {
      const token = await getToken()
      if (!token) return
      const data = await apiClient.identities.list(token, { page_size: "500" })
      setIdentities(data.items)
      setLoading(false)
    })()
  }, [getToken])

  const withScores = identities.filter(i => i.risk_score)
  const bySeverity = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(s => ({
    severity: s as Severity,
    count: withScores.filter(i => i.risk_score?.severity === s).length,
  }))

  const topRisked = [...withScores]
    .sort((a, b) => (b.risk_score?.score ?? 0) - (a.risk_score?.score ?? 0))
    .slice(0, 10)

  if (loading) return <div className="p-6 text-gray-400">Loading risk data…</div>

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Risk Overview</h1>
        <p className="text-sm text-gray-500 mt-1">{withScores.length} identities scored</p>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-4 gap-4">
        <SeverityCard severity="CRITICAL" count={bySeverity[0].count} icon={ShieldX} />
        <SeverityCard severity="HIGH" count={bySeverity[1].count} icon={AlertTriangle} />
        <SeverityCard severity="MEDIUM" count={bySeverity[2].count} icon={Shield} />
        <SeverityCard severity="LOW" count={bySeverity[3].count} icon={ShieldCheck} />
      </div>

      {/* Distribution chart */}
      <div className="rounded-lg border bg-white p-5 shadow-sm">
        <h2 className="text-sm font-semibold text-gray-700 mb-4">Severity Distribution</h2>
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={bySeverity}>
            <XAxis dataKey="severity" tick={{ fontSize: 12 }} />
            <YAxis tick={{ fontSize: 12 }} />
            <Tooltip />
            <Bar dataKey="count" radius={[4, 4, 0, 0]}>
              {bySeverity.map(entry => (
                <Cell key={entry.severity} fill={SEVERITY_COLORS[entry.severity]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Top risk table */}
      <div className="rounded-lg border bg-white shadow-sm overflow-hidden">
        <div className="p-4 border-b bg-gray-50">
          <h2 className="text-sm font-semibold text-gray-700">Top 10 Highest Risk Identities</h2>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b text-left text-gray-500">
              <th className="px-4 py-2 font-medium">Identity</th>
              <th className="px-4 py-2 font-medium">Provider</th>
              <th className="px-4 py-2 font-medium">Score</th>
              <th className="px-4 py-2 font-medium">Top Risk Factor</th>
            </tr>
          </thead>
          <tbody>
            {topRisked.map(identity => {
              const topFactor = identity.risk_score?.factors.reduce((a, b) =>
                a.contribution > b.contribution ? a : b
              )
              return (
                <tr key={identity.id} className="border-b hover:bg-gray-50">
                  <td className="px-4 py-3">
                    <div className="font-medium text-gray-900">{identity.name}</div>
                    <div className="text-xs text-gray-400">{identity.type}</div>
                  </td>
                  <td className="px-4 py-3 text-gray-600">{identity.provider}</td>
                  <td className="px-4 py-3">
                    <span
                      className="font-bold"
                      style={{ color: SEVERITY_COLORS[identity.risk_score!.severity] }}
                    >
                      {identity.risk_score!.score.toFixed(1)}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-gray-500 text-xs max-w-xs truncate">
                    {topFactor?.remediation ?? topFactor?.name ?? "—"}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
