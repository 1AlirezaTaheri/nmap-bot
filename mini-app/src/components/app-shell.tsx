import * as React from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { Activity, AlertTriangle, Network, ScanLine, Settings, LayoutDashboard } from 'lucide-react'
import { cn } from '@/lib/utils'
import { haptic } from '@/lib/telegram'

/**
 * Bottom tab bar.
 *
 * Paths are relative to the router's basename, which is "" here: the Mini App
 * is served under /app but the router's base is /app, so an internal link is
 * written as "/targets" and resolves to /app/targets.
 */
const TABS = [
  { to: '/', label: 'Home', icon: LayoutDashboard, end: true },
  { to: '/targets', label: 'Targets', icon: Network },
  { to: '/scan', label: 'Scan', icon: ScanLine },
  { to: '/changes', label: 'Changes', icon: AlertTriangle },
  { to: '/settings', label: 'Settings', icon: Settings },
] as const

export function AppShell({
  title,
  action,
}: {
  title: string
  action?: React.ReactNode
}): JSX.Element {
  return (
    <div className="flex min-h-screen flex-col bg-bg">
      <header
        className="sticky top-0 z-30 flex items-center gap-3 border-b
          border-hint/10 bg-bg/90 px-4 py-3 backdrop-blur"
      >
        <Activity className="h-5 w-5 shrink-0 text-button" />
        <h1 className="min-w-0 flex-1 truncate text-[17px] font-semibold">
          {title}
        </h1>
        {action}
      </header>

      <main className="flex-1 px-4 pb-[calc(env(safe-area-inset-bottom)+68px)] pt-3">
        <Outlet />
      </main>

      <nav
        className="fixed bottom-0 left-0 right-0 z-30 flex h-tabbar
          border-t border-hint/10 bg-bg/95 pb-[env(safe-area-inset-bottom)]
          backdrop-blur"
      >
        {TABS.map((tab) => (
          <NavLink
            key={tab.to}
            to={tab.to}
            end={'end' in tab ? tab.end : false}
            className={({ isActive }) =>
              cn(
                'flex flex-1 flex-col items-center justify-center gap-0.5',
                'text-[10px] font-medium transition-colors',
                isActive ? 'text-button' : 'text-hint',
              )
            }
            onClick={() => haptic()}
          >
            <tab.icon className="h-[22px] w-[22px]" />
            <span>{tab.label}</span>
          </NavLink>
        ))}
      </nav>
    </div>
  )
}