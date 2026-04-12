"use client"

import { useEffect, useState, useCallback } from "react"
import { useAuth } from "@clerk/nextjs"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table"
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select"
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter,
} from "@/components/ui/dialog"
import { apiClient, PolicyRule, ViolationItem } from "@/lib/api-client"
import { Plus, FileText } from "lucide-react"

const ENFORCEMENT_COLORS: Record<string, string> = {
  MONITOR: "bg-gray-100 text-gray-700",
  ALERT: "bg-yellow-100 text-yellow-800",
  ENFORCE: "bg-orange-100 text-orange-800",
  AUTO_REMEDIATE: "bg-red-100 text-red-800",
}

function EnforcementBadge({ mode }: { mode: string }) {
  return (
    <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${ENFORCEMENT_COLORS[mode] ?? "bg-gray-100 text-gray-700"}`}>
      {mode.replace("_", " ")}
    </span>
  )
}

function PolicyCard({ policy }: { policy: PolicyRule }) {
  return (
    <div className="rounded-lg border bg-white p-4 shadow-sm space-y-2">
      <div className="flex items-start justify-between gap-2">
        <div>
          <p className="font-medium text-gray-900 text-sm">{policy.name}</p>
          {policy.description && (
            <p className="text-xs text-gray-500 mt-0.5">{policy.description}</p>
          )}
        </div>
        <EnforcementBadge mode={policy.enforcement_mode} />
      </div>
      {policy.compliance_mappings.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {policy.compliance_mappings.map(m => (
            <span key={m} className="text-xs bg-blue-50 text-blue-700 px-1.5 py-0.5 rounded border border-blue-100">{m}</span>
          ))}
        </div>
      )}
      <div className="flex items-center gap-2 text-xs text-gray-400">
        <span>{policy.enabled ? "✓ Enabled" : "✗ Disabled"}</span>
        <span>·</span>
        <span>Created {new Date(policy.created_at).toLocaleDateString()}</span>
      </div>
    </div>
  )
}

function NewPolicyDialog({ onCreated }: { onCreated: () => void }) {
  const { getToken } = useAuth()
  const [open, setOpen] = useState(false)
  const [name, setName] = useState("")
  const [yaml, setYaml] = useState("")
  const [mode, setMode] = useState("MONITOR")
  const [saving, setSaving] = useState(false)

  const handleSave = async () => {
    if (!name || !yaml) return
    setSaving(true)
    try {
      const token = await getToken()
      if (token) {
        await apiClient.policies.create(token, { name, yaml_definition: yaml, enforcement_mode: mode })
        setOpen(false)
        setName(""); setYaml(""); setMode("MONITOR")
        onCreated()
      }
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger render={<Button size="sm"><Plus className="h-4 w-4 mr-1" />New Policy</Button>} />
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>New Policy</DialogTitle>
        </DialogHeader>
        <div className="space-y-3 py-2">
          <div>
            <label className="text-xs font-medium text-gray-700 block mb-1">Name</label>
            <Input value={name} onChange={e => setName(e.target.value)} placeholder="Policy name" />
          </div>
          <div>
            <label className="text-xs font-medium text-gray-700 block mb-1">Enforcement Mode</label>
            <Select value={mode} onValueChange={v => { if (v) setMode(v) }}>
              <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
              <SelectContent>
                {["MONITOR", "ALERT", "ENFORCE", "AUTO_REMEDIATE"].map(m => (
                  <SelectItem key={m} value={m}>{m}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <label className="text-xs font-medium text-gray-700 block mb-1">YAML Definition</label>
            <textarea
              value={yaml}
              onChange={e => setYaml(e.target.value)}
              className="w-full h-40 text-xs font-mono rounded-lg border border-input bg-transparent px-3 py-2 outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 resize-none"
              placeholder="# Policy YAML definition"
            />
          </div>
        </div>
        <DialogFooter>
          <Button onClick={handleSave} disabled={saving || !name || !yaml} size="sm">
            {saving ? "Saving…" : "Save Policy"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export default function PoliciesPage() {
  const { getToken } = useAuth()
  const [tab, setTab] = useState<"rules" | "violations">("rules")
  const [policies, setPolicies] = useState<PolicyRule[]>([])
  const [violations, setViolations] = useState<ViolationItem[]>([])
  const [loading, setLoading] = useState(true)

  const fetchData = useCallback(async () => {
    setLoading(true)
    try {
      const token = await getToken()
      if (!token) return
      const [p, v] = await Promise.all([
        apiClient.policies.list(token),
        apiClient.policies.violations(token),
      ])
      setPolicies(p)
      setViolations(v)
    } finally {
      setLoading(false)
    }
  }, [getToken])

  useEffect(() => { fetchData() }, [fetchData])

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Policy Engine</h1>
          <p className="text-sm text-gray-500 mt-1">{policies.length} rules · {violations.filter(v => !v.resolved_at).length} open violations</p>
        </div>
        <NewPolicyDialog onCreated={fetchData} />
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b">
        {(["rules", "violations"] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm font-medium capitalize border-b-2 transition-colors ${
              tab === t ? "border-blue-600 text-blue-600" : "border-transparent text-gray-500 hover:text-gray-700"
            }`}
          >
            {t === "rules" ? `Rules (${policies.length})` : `Violations (${violations.length})`}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="text-center py-12 text-gray-400">Loading…</div>
      ) : tab === "rules" ? (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {policies.length === 0 ? (
            <div className="col-span-full text-center py-12 text-gray-400">
              <FileText className="h-8 w-8 mx-auto mb-2 opacity-30" />
              No policies defined yet
            </div>
          ) : policies.map(p => <PolicyCard key={p.id} policy={p} />)}
        </div>
      ) : (
        <div className="rounded-lg border bg-white shadow-sm overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow className="bg-gray-50">
                <TableHead>Policy</TableHead>
                <TableHead>Identity</TableHead>
                <TableHead>Detected</TableHead>
                <TableHead>Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {violations.length === 0 ? (
                <TableRow><TableCell colSpan={4} className="text-center py-12 text-gray-400">No violations found</TableCell></TableRow>
              ) : violations.map(v => (
                <TableRow key={v.id}>
                  <TableCell className="font-medium text-sm">{v.policy_name}</TableCell>
                  <TableCell className="font-mono text-xs text-gray-500">{v.nhi_id.slice(0, 12)}…</TableCell>
                  <TableCell className="text-xs text-gray-500">{new Date(v.detected_at).toLocaleString()}</TableCell>
                  <TableCell>
                    {v.resolved_at ? (
                      <span className="text-xs bg-green-100 text-green-700 px-2 py-0.5 rounded-full">Resolved</span>
                    ) : (
                      <span className="text-xs bg-red-100 text-red-700 px-2 py-0.5 rounded-full">Open</span>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  )
}
