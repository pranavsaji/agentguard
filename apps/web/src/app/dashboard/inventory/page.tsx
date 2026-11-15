"use client"

import { useEffect, useState, useCallback } from "react"
import { useAuth } from "@clerk/nextjs"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { apiClient, NHIIdentity, Provider, NHIStatus } from "@/lib/api-client"
import { RefreshCw, Shield, AlertTriangle, RotateCcw, XCircle } from "lucide-react"

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "bg-red-100 text-red-800 border-red-200",
  HIGH: "bg-orange-100 text-orange-800 border-orange-200",
  MEDIUM: "bg-yellow-100 text-yellow-800 border-yellow-200",
  LOW: "bg-green-100 text-green-800 border-green-200",
}

const PROVIDER_ICONS: Record<Provider, string> = {
  AWS: "🟠",
  AZURE: "🔵",
  GCP: "🟡",
  GITHUB: "⚫",
  GITLAB: "🟠",
}

const STATUS_COLORS: Record<NHIStatus, string> = {
  ACTIVE: "bg-green-100 text-green-800",
  STALE: "bg-yellow-100 text-yellow-800",
  ORPHANED: "bg-red-100 text-red-800",
  REVOKED: "bg-gray-100 text-gray-600",
}

function RiskBadge({ score, severity }: { score: number; severity: string }) {
  return (
    <div className="flex items-center gap-1.5">
      <div className={`text-xs font-semibold px-2 py-0.5 rounded-full border ${SEVERITY_COLORS[severity] ?? "bg-gray-100 text-gray-600"}`}>
        {severity}
      </div>
      <span className="text-sm font-mono text-gray-600">{score.toFixed(0)}</span>
    </div>
  )
}

export default function InventoryPage() {
  const { getToken } = useAuth()
  const [identities, setIdentities] = useState<NHIIdentity[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [scanning, setScanning] = useState(false)
  const [search, setSearch] = useState("")
  const [provider, setProvider] = useState<string>("all")
  const [status, setStatus] = useState<string>("all")
  const [page, setPage] = useState(1)

  const fetchIdentities = useCallback(async () => {
    setLoading(true)
    try {
      const token = await getToken()
      if (!token) return
      const params: Record<string, string> = { page: String(page), page_size: "50" }
      if (provider !== "all") params.provider = provider
      if (status !== "all") params.status = status
      const data = await apiClient.identities.list(token, params)
      setIdentities(data.items)
      setTotal(data.total)
    } finally {
      setLoading(false)
    }
  }, [getToken, page, provider, status])

  useEffect(() => { fetchIdentities() }, [fetchIdentities])

  const handleScan = async () => {
    setScanning(true)
    try {
      const token = await getToken()
      if (token) await apiClient.identities.triggerScan(token)
    } finally {
      setTimeout(() => { setScanning(false); fetchIdentities() }, 3000)
    }
  }

  const handleRotate = async (id: string) => {
    const token = await getToken()
    if (token) { await apiClient.identities.rotate(token, id); fetchIdentities() }
  }

  const handleRevoke = async (id: string) => {
    if (!confirm("Revoke this credential? This cannot be undone.")) return
    const token = await getToken()
    if (token) { await apiClient.identities.revoke(token, id, "Manual revocation via dashboard"); fetchIdentities() }
  }

  const filtered = identities.filter(i =>
    !search || i.name.toLowerCase().includes(search.toLowerCase()) || i.external_id.includes(search)
  )

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Identity Inventory</h1>
          <p className="text-sm text-gray-500 mt-1">{total.toLocaleString()} non-human identities across all providers</p>
        </div>
        <Button onClick={handleScan} disabled={scanning} variant="outline" size="sm">
          <RefreshCw className={`h-4 w-4 mr-2 ${scanning ? "animate-spin" : ""}`} />
          {scanning ? "Scanning…" : "Scan Now"}
        </Button>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <Input
          placeholder="Search by name or ID…"
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="max-w-sm"
        />
        <Select value={provider} onValueChange={v => setProvider(v ?? "all")}>
          <SelectTrigger className="w-36"><SelectValue placeholder="Provider" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Providers</SelectItem>
            {(["AWS", "AZURE", "GCP", "GITHUB"] as Provider[]).map(p => (
              <SelectItem key={p} value={p}>{PROVIDER_ICONS[p]} {p}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={status} onValueChange={v => setStatus(v ?? "all")}>
          <SelectTrigger className="w-32"><SelectValue placeholder="Status" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Status</SelectItem>
            {(["ACTIVE", "STALE", "ORPHANED", "REVOKED"] as NHIStatus[]).map(s => (
              <SelectItem key={s} value={s}>{s}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Table */}
      <div className="rounded-lg border bg-white shadow-sm overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow className="bg-gray-50">
              <TableHead>Identity</TableHead>
              <TableHead>Provider</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Classification</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Risk Score</TableHead>
              <TableHead>Last Used</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              <TableRow><TableCell colSpan={8} className="text-center py-12 text-gray-400">Loading…</TableCell></TableRow>
            ) : filtered.length === 0 ? (
              <TableRow><TableCell colSpan={8} className="text-center py-12 text-gray-400">No identities found</TableCell></TableRow>
            ) : filtered.map(identity => (
              <TableRow key={identity.id} className="hover:bg-gray-50">
                <TableCell>
                  <div className="font-medium text-gray-900 truncate max-w-[200px]">{identity.name}</div>
                  <div className="text-xs text-gray-400 font-mono truncate max-w-[200px]">{identity.external_id}</div>
                </TableCell>
                <TableCell>
                  <span>{PROVIDER_ICONS[identity.provider]} {identity.provider}</span>
                </TableCell>
                <TableCell>
                  <Badge variant="outline" className="text-xs">{identity.type.replace("_", " ")}</Badge>
                </TableCell>
                <TableCell>
                  <span className="text-xs text-gray-600">{identity.classification}</span>
                </TableCell>
                <TableCell>
                  <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${STATUS_COLORS[identity.status]}`}>
                    {identity.status}
                  </span>
                </TableCell>
                <TableCell>
                  {identity.risk_score ? (
                    <RiskBadge score={identity.risk_score.score} severity={identity.risk_score.severity} />
                  ) : (
                    <span className="text-gray-400 text-xs">—</span>
                  )}
                </TableCell>
                <TableCell>
                  <span className="text-xs text-gray-500">
                    {identity.last_used_at
                      ? new Date(identity.last_used_at).toLocaleDateString()
                      : <span className="text-red-500">Never</span>}
                  </span>
                </TableCell>
                <TableCell className="text-right">
                  <div className="flex items-center justify-end gap-1">
                    {identity.status === "ACTIVE" && (
                      <>
                        <Button
                          variant="ghost" size="icon"
                          onClick={() => handleRotate(identity.id)}
                          title="Rotate credential"
                          className="h-7 w-7 text-blue-600 hover:text-blue-800"
                        >
                          <RotateCcw className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          variant="ghost" size="icon"
                          onClick={() => handleRevoke(identity.id)}
                          title="Revoke credential"
                          className="h-7 w-7 text-red-600 hover:text-red-800"
                        >
                          <XCircle className="h-3.5 w-3.5" />
                        </Button>
                      </>
                    )}
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      {/* Pagination */}
      {total > 50 && (
        <div className="flex items-center justify-between text-sm text-gray-500">
          <span>Page {page} of {Math.ceil(total / 50)}</span>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" disabled={page === 1} onClick={() => setPage(p => p - 1)}>Previous</Button>
            <Button variant="outline" size="sm" disabled={page >= Math.ceil(total / 50)} onClick={() => setPage(p => p + 1)}>Next</Button>
          </div>
        </div>
      )}
    </div>
  )
}
