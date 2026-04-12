"use client"

import { useEffect, useState, useCallback } from "react"
import { useAuth } from "@clerk/nextjs"
import { Button } from "@/components/ui/button"
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
import { apiClient, JITGrant, NHIIdentity } from "@/lib/api-client"
import { Key, Plus, Trash2, RefreshCw } from "lucide-react"

const TTL_OPTIONS = [15, 30, 60, 120, 240]

function timeRemaining(expiresAt: string): string {
  const diff = new Date(expiresAt).getTime() - Date.now()
  if (diff <= 0) return "Expired"
  const mins = Math.floor(diff / 60000)
  const hrs = Math.floor(mins / 60)
  if (hrs > 0) return `expires in ${hrs}h ${mins % 60}m`
  return `expires in ${mins}m`
}

function isExpired(expiresAt: string): boolean {
  return new Date(expiresAt).getTime() <= Date.now()
}

function RequestAccessDialog({ identities, onCreated }: { identities: NHIIdentity[]; onCreated: () => void }) {
  const { getToken } = useAuth()
  const [open, setOpen] = useState(false)
  const [nhiId, setNhiId] = useState("")
  const [scope, setScope] = useState("{}")
  const [reason, setReason] = useState("")
  const [ttl, setTtl] = useState(60)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = async () => {
    setError(null)
    let parsedScope: object
    try { parsedScope = JSON.parse(scope) } catch { setError("Invalid JSON in scope"); return }
    setSaving(true)
    try {
      const token = await getToken()
      if (token) {
        await apiClient.jit.create(token, { nhi_id: nhiId, scope: parsedScope, reason, ttl_minutes: ttl })
        setOpen(false)
        setNhiId(""); setScope("{}"); setReason(""); setTtl(60)
        onCreated()
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create grant")
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger render={<Button size="sm"><Plus className="h-4 w-4 mr-1" />Request Access</Button>} />
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Request JIT Access</DialogTitle>
        </DialogHeader>
        <div className="space-y-3 py-2">
          <div>
            <label className="text-xs font-medium text-gray-700 block mb-1">Identity</label>
            <Select value={nhiId} onValueChange={v => { if (v) setNhiId(v) }}>
              <SelectTrigger className="w-full"><SelectValue placeholder="Select identity…" /></SelectTrigger>
              <SelectContent>
                {identities.map(i => (
                  <SelectItem key={i.id} value={i.id}>{i.name}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <label className="text-xs font-medium text-gray-700 block mb-1">Scope (JSON)</label>
            <textarea
              value={scope}
              onChange={e => setScope(e.target.value)}
              className="w-full h-24 text-xs font-mono rounded-lg border border-input bg-transparent px-3 py-2 outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 resize-none"
              placeholder='{"resource": "s3:bucket-name", "actions": ["s3:GetObject"]}'
            />
          </div>
          <div>
            <label className="text-xs font-medium text-gray-700 block mb-1">Reason</label>
            <Input value={reason} onChange={e => setReason(e.target.value)} placeholder="Why is this access needed?" />
          </div>
          <div>
            <label className="text-xs font-medium text-gray-700 block mb-1">TTL: {ttl} minutes</label>
            <div className="flex gap-2 flex-wrap">
              {TTL_OPTIONS.map(t => (
                <button
                  key={t}
                  onClick={() => setTtl(t)}
                  className={`px-3 py-1 text-xs rounded-full border transition-colors ${
                    ttl === t ? "bg-blue-600 text-white border-blue-600" : "border-gray-200 text-gray-600 hover:bg-gray-50"
                  }`}
                >
                  {t >= 60 ? `${t / 60}h` : `${t}m`}
                </button>
              ))}
            </div>
          </div>
          {error && <p className="text-xs text-red-600">{error}</p>}
        </div>
        <DialogFooter>
          <Button onClick={handleSubmit} disabled={saving || !nhiId || !reason} size="sm">
            {saving ? "Creating…" : "Create Grant"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export default function JITPage() {
  const { getToken } = useAuth()
  const [grants, setGrants] = useState<JITGrant[]>([])
  const [identities, setIdentities] = useState<NHIIdentity[]>([])
  const [loading, setLoading] = useState(true)

  const fetchGrants = useCallback(async () => {
    try {
      const token = await getToken()
      if (!token) return
      const [g, ids] = await Promise.all([
        apiClient.jit.list(token),
        apiClient.identities.list(token, { page_size: "200" }),
      ])
      setGrants(g)
      setIdentities(ids.items)
    } finally {
      setLoading(false)
    }
  }, [getToken])

  useEffect(() => {
    fetchGrants()
    const interval = setInterval(fetchGrants, 30000)
    return () => clearInterval(interval)
  }, [fetchGrants])

  const handleRevoke = async (id: string) => {
    if (!confirm("Revoke this JIT grant?")) return
    const token = await getToken()
    if (token) { await apiClient.jit.revoke(token, id); fetchGrants() }
  }

  const activeGrants = grants.filter(g => !isExpired(g.expires_at))
  const expiredGrants = grants.filter(g => isExpired(g.expires_at))

  const identityName = (id: string) => identities.find(i => i.id === id)?.name ?? id.slice(0, 12) + "…"

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
            <Key className="h-6 w-6 text-blue-500" />
            JIT Access
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            <span className="font-medium text-green-600">{activeGrants.length} active</span> grants
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={fetchGrants}>
            <RefreshCw className="h-4 w-4" />
          </Button>
          <RequestAccessDialog identities={identities} onCreated={fetchGrants} />
        </div>
      </div>

      {loading ? (
        <div className="text-center py-12 text-gray-400">Loading grants…</div>
      ) : (
        <div className="rounded-lg border bg-white shadow-sm overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow className="bg-gray-50">
                <TableHead>Identity</TableHead>
                <TableHead>Scope</TableHead>
                <TableHead>Reason</TableHead>
                <TableHead>Issued</TableHead>
                <TableHead>Expires</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {grants.length === 0 ? (
                <TableRow><TableCell colSpan={6} className="text-center py-12 text-gray-400">No active grants</TableCell></TableRow>
              ) : (
                <>
                  {activeGrants.map(grant => (
                    <TableRow key={grant.id} className="hover:bg-gray-50">
                      <TableCell className="font-medium text-sm">{identityName(grant.nhi_id)}</TableCell>
                      <TableCell className="font-mono text-xs text-gray-500 max-w-[160px] truncate">
                        {JSON.stringify(grant.scope).slice(0, 60)}{JSON.stringify(grant.scope).length > 60 ? "…" : ""}
                      </TableCell>
                      <TableCell className="text-sm text-gray-600 max-w-[150px] truncate">{grant.reason}</TableCell>
                      <TableCell className="text-xs text-gray-500">{new Date(grant.issued_at).toLocaleString()}</TableCell>
                      <TableCell className="text-xs text-green-600 font-medium">{timeRemaining(grant.expires_at)}</TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="ghost" size="icon-sm"
                          onClick={() => handleRevoke(grant.id)}
                          className="text-red-500 hover:text-red-700"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                  {expiredGrants.map(grant => (
                    <TableRow key={grant.id} className="opacity-50">
                      <TableCell className="font-medium text-sm text-gray-400">{identityName(grant.nhi_id)}</TableCell>
                      <TableCell className="font-mono text-xs text-gray-400 max-w-[160px] truncate">
                        {JSON.stringify(grant.scope).slice(0, 60)}{JSON.stringify(grant.scope).length > 60 ? "…" : ""}
                      </TableCell>
                      <TableCell className="text-sm text-gray-400 max-w-[150px] truncate">{grant.reason}</TableCell>
                      <TableCell className="text-xs text-gray-400">{new Date(grant.issued_at).toLocaleString()}</TableCell>
                      <TableCell>
                        <span className="text-xs bg-gray-100 text-gray-500 px-2 py-0.5 rounded-full">EXPIRED</span>
                      </TableCell>
                      <TableCell />
                    </TableRow>
                  ))}
                </>
              )}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  )
}
