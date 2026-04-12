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
import { apiClient, Webhook, AlertItem, WebhookType } from "@/lib/api-client"
import { Plus, Trash2, Play, Link } from "lucide-react"

const WEBHOOK_TYPES: WebhookType[] = ["SLACK", "PAGERDUTY", "GENERIC", "SPLUNK", "DATADOG"]
const WEBHOOK_TYPE_COLORS: Record<WebhookType, string> = {
  SLACK: "bg-purple-100 text-purple-800",
  PAGERDUTY: "bg-green-100 text-green-800",
  GENERIC: "bg-gray-100 text-gray-700",
  SPLUNK: "bg-orange-100 text-orange-800",
  DATADOG: "bg-blue-100 text-blue-800",
}
const EVENT_OPTIONS = ["POLICY_VIOLATION", "ANOMALY", "ROTATION_FAILED", "JIT_EXPIRED"]

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "bg-red-100 text-red-800",
  HIGH: "bg-orange-100 text-orange-800",
  MEDIUM: "bg-yellow-100 text-yellow-800",
  LOW: "bg-green-100 text-green-800",
}

function maskUrl(url: string): string {
  try {
    const u = new URL(url)
    return `${u.protocol}//${u.hostname}/***`
  } catch { return url.slice(0, 30) + "…" }
}

function AddWebhookDialog({ onCreated }: { onCreated: () => void }) {
  const { getToken } = useAuth()
  const [open, setOpen] = useState(false)
  const [name, setName] = useState("")
  const [url, setUrl] = useState("")
  const [type, setType] = useState<WebhookType>("GENERIC")
  const [events, setEvents] = useState<string[]>([])
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const toggleEvent = (e: string) => {
    setEvents(prev => prev.includes(e) ? prev.filter(x => x !== e) : [...prev, e])
  }

  const handleSave = async () => {
    setError(null)
    if (!name || !url || events.length === 0) { setError("Name, URL and at least one event are required"); return }
    setSaving(true)
    try {
      const token = await getToken()
      if (token) {
        await apiClient.integrations.webhooks.create(token, { name, url, type, events })
        setOpen(false)
        setName(""); setUrl(""); setType("GENERIC"); setEvents([])
        onCreated()
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create webhook")
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger render={<Button size="sm"><Plus className="h-4 w-4 mr-1" />Add Webhook</Button>} />
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Add Webhook</DialogTitle>
        </DialogHeader>
        <div className="space-y-3 py-2">
          <div>
            <label className="text-xs font-medium text-gray-700 block mb-1">Name</label>
            <Input value={name} onChange={e => setName(e.target.value)} placeholder="My Slack webhook" />
          </div>
          <div>
            <label className="text-xs font-medium text-gray-700 block mb-1">Type</label>
            <Select value={type} onValueChange={v => { if (v) setType(v as WebhookType) }}>
              <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
              <SelectContent>
                {WEBHOOK_TYPES.map(t => <SelectItem key={t} value={t}>{t}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
          <div>
            <label className="text-xs font-medium text-gray-700 block mb-1">URL</label>
            <Input value={url} onChange={e => setUrl(e.target.value)} placeholder="https://hooks.example.com/…" />
          </div>
          <div>
            <label className="text-xs font-medium text-gray-700 block mb-1">Events</label>
            <div className="flex flex-wrap gap-2">
              {EVENT_OPTIONS.map(e => (
                <button
                  key={e}
                  type="button"
                  onClick={() => toggleEvent(e)}
                  className={`text-xs px-2.5 py-1 rounded-full border transition-colors ${
                    events.includes(e) ? "bg-blue-600 text-white border-blue-600" : "border-gray-200 text-gray-600 hover:bg-gray-50"
                  }`}
                >
                  {e.replace("_", " ")}
                </button>
              ))}
            </div>
          </div>
          {error && <p className="text-xs text-red-600">{error}</p>}
        </div>
        <DialogFooter>
          <Button onClick={handleSave} disabled={saving} size="sm">
            {saving ? "Saving…" : "Save Webhook"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function WebhookCard({ webhook, onTest, onDelete }: {
  webhook: Webhook
  onTest: (id: string) => Promise<void>
  onDelete: (id: string) => Promise<void>
}) {
  const [testing, setTesting] = useState(false)

  const handleTest = async () => {
    setTesting(true)
    try { await onTest(webhook.id) } finally { setTesting(false) }
  }

  return (
    <div className="rounded-lg border bg-white p-4 shadow-sm space-y-2">
      <div className="flex items-start justify-between gap-2">
        <div>
          <p className="font-medium text-sm text-gray-900">{webhook.name}</p>
          <p className="text-xs text-gray-400 font-mono mt-0.5">{maskUrl(webhook.url)}</p>
        </div>
        <span className={`text-xs font-medium px-2 py-0.5 rounded-full whitespace-nowrap ${WEBHOOK_TYPE_COLORS[webhook.type]}`}>
          {webhook.type}
        </span>
      </div>
      <div className="flex flex-wrap gap-1">
        {webhook.events.map(e => (
          <span key={e} className="text-xs bg-gray-50 text-gray-600 px-1.5 py-0.5 rounded border border-gray-100">{e}</span>
        ))}
      </div>
      {webhook.last_error && (
        <p className="text-xs text-red-600 truncate">{webhook.last_error}</p>
      )}
      <div className="flex items-center justify-between text-xs text-gray-400">
        <span>{webhook.enabled ? "✓ Enabled" : "✗ Disabled"}</span>
        {webhook.last_triggered_at && (
          <span>Last: {new Date(webhook.last_triggered_at).toLocaleDateString()}</span>
        )}
      </div>
      <div className="flex gap-2 pt-1">
        <Button variant="outline" size="sm" onClick={handleTest} disabled={testing}>
          <Play className="h-3.5 w-3.5 mr-1" />{testing ? "Testing…" : "Test"}
        </Button>
        <Button variant="ghost" size="sm" onClick={() => onDelete(webhook.id)} className="text-red-500 hover:text-red-700">
          <Trash2 className="h-3.5 w-3.5" />
        </Button>
      </div>
    </div>
  )
}

export default function IntegrationsPage() {
  const { getToken } = useAuth()
  const [webhooks, setWebhooks] = useState<Webhook[]>([])
  const [alerts, setAlerts] = useState<AlertItem[]>([])
  const [alertFilter, setAlertFilter] = useState<string>("ALL")
  const [loading, setLoading] = useState(true)

  const fetchData = useCallback(async () => {
    setLoading(true)
    try {
      const token = await getToken()
      if (!token) return
      const [w, a] = await Promise.all([
        apiClient.integrations.webhooks.list(token),
        apiClient.integrations.alerts.list(token),
      ])
      setWebhooks(w)
      setAlerts(a)
    } finally {
      setLoading(false)
    }
  }, [getToken])

  useEffect(() => { fetchData() }, [fetchData])

  const handleTest = async (id: string) => {
    const token = await getToken()
    if (!token) return
    const result = await apiClient.integrations.webhooks.test(token, id)
    if (result.success) alert("Test succeeded!")
    else alert(`Test failed: ${result.error}`)
  }

  const handleDelete = async (id: string) => {
    if (!confirm("Delete this webhook?")) return
    const token = await getToken()
    if (token) { await apiClient.integrations.webhooks.delete(token, id); fetchData() }
  }

  const handleAcknowledge = async (id: string) => {
    const token = await getToken()
    if (token) { await apiClient.integrations.alerts.acknowledge(token, id); fetchData() }
  }

  const filteredAlerts = alerts.filter(a => alertFilter === "ALL" || a.status === alertFilter)

  return (
    <div className="p-6 space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
          <Link className="h-6 w-6 text-blue-500" />
          Integrations
        </h1>
      </div>

      {/* Webhooks */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-gray-800">Webhooks</h2>
          <AddWebhookDialog onCreated={fetchData} />
        </div>
        {loading ? (
          <div className="text-sm text-gray-400">Loading webhooks…</div>
        ) : webhooks.length === 0 ? (
          <div className="rounded-lg border border-dashed p-8 text-center text-gray-400 text-sm">
            No webhooks configured
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {webhooks.map(w => (
              <WebhookCard key={w.id} webhook={w} onTest={handleTest} onDelete={handleDelete} />
            ))}
          </div>
        )}
      </section>

      {/* Alerts */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-gray-800">Alerts</h2>
          <div className="flex gap-1">
            {["ALL", "OPEN", "ACKNOWLEDGED"].map(f => (
              <button
                key={f}
                onClick={() => setAlertFilter(f)}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                  alertFilter === f ? "bg-blue-600 text-white" : "text-gray-500 hover:bg-gray-100"
                }`}
              >
                {f}
              </button>
            ))}
          </div>
        </div>
        <div className="rounded-lg border bg-white shadow-sm overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow className="bg-gray-50">
                <TableHead>Severity</TableHead>
                <TableHead>Title</TableHead>
                <TableHead>Description</TableHead>
                <TableHead>Resource</TableHead>
                <TableHead>Time</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                <TableRow><TableCell colSpan={6} className="text-center py-8 text-gray-400">Loading alerts…</TableCell></TableRow>
              ) : filteredAlerts.length === 0 ? (
                <TableRow><TableCell colSpan={6} className="text-center py-8 text-gray-400">No alerts found</TableCell></TableRow>
              ) : filteredAlerts.map(alert => (
                <TableRow key={alert.id} className="hover:bg-gray-50">
                  <TableCell>
                    <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${SEVERITY_COLORS[alert.severity] ?? "bg-gray-100 text-gray-700"}`}>
                      {alert.severity}
                    </span>
                  </TableCell>
                  <TableCell className="font-medium text-sm">{alert.title}</TableCell>
                  <TableCell className="text-xs text-gray-500 max-w-[200px] truncate">
                    {alert.description ?? <span className="text-gray-300">—</span>}
                  </TableCell>
                  <TableCell className="text-xs text-gray-500">
                    {alert.resource_type && alert.resource_id
                      ? `${alert.resource_type}: ${alert.resource_id.slice(0, 12)}…`
                      : <span className="text-gray-300">—</span>}
                  </TableCell>
                  <TableCell className="text-xs text-gray-500">{new Date(alert.created_at).toLocaleString()}</TableCell>
                  <TableCell className="text-right">
                    {alert.status === "OPEN" && (
                      <Button variant="outline" size="sm" onClick={() => handleAcknowledge(alert.id)}>
                        Acknowledge
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </section>
    </div>
  )
}
