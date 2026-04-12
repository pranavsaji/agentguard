"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { Shield, AlertTriangle, FileText, Key, CheckSquare, Link as LinkIcon, User } from "lucide-react"

const NAV = [
  { href: "/dashboard/inventory", label: "Inventory", icon: Shield },
  { href: "/dashboard/risk", label: "Risk", icon: AlertTriangle },
  { href: "/dashboard/policies", label: "Policies", icon: FileText },
  { href: "/dashboard/jit", label: "JIT Access", icon: Key },
  { href: "/dashboard/compliance", label: "Compliance", icon: CheckSquare },
  { href: "/dashboard/integrations", label: "Integrations", icon: LinkIcon },
]

function Sidebar() {
  const pathname = usePathname()

  return (
    <aside className="w-56 bg-gray-900 flex flex-col">
      <div className="flex items-center gap-2 px-5 py-5 border-b border-gray-800">
        <Shield className="h-5 w-5 text-blue-400" />
        <span className="font-bold text-white text-sm">AgentGuard</span>
      </div>
      <nav className="flex-1 px-3 py-4 space-y-1">
        {NAV.map(item => {
          const active = pathname.startsWith(item.href)
          const Icon = item.icon
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-2.5 px-3 py-2 text-sm rounded-md transition-colors ${
                active
                  ? "bg-blue-600 text-white"
                  : "text-gray-300 hover:bg-gray-800 hover:text-white"
              }`}
            >
              <Icon className="h-4 w-4 shrink-0" />
              {item.label}
            </Link>
          )
        })}
      </nav>
      <div className="px-5 py-4 border-t border-gray-800 flex items-center gap-2">
        <div className="h-7 w-7 rounded-full bg-blue-600 flex items-center justify-center">
          <User className="h-4 w-4 text-white" />
        </div>
        <span className="text-xs text-gray-400 truncate">Security Admin</span>
      </div>
    </aside>
  )
}

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-gray-50 flex">
      <Sidebar />
      <main className="flex-1 overflow-auto">{children}</main>
    </div>
  )
}
