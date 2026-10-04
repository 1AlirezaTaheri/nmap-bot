import * as React from 'react'
import { NavLink, useLocation, useNavigate } from 'react-router-dom'
import {
  Activity,
  ChevronLeft,
  ChevronRight,
  LayoutDashboard,
  LogOut,
  Moon,
  Network,
  ScrollText,
  Settings as SettingsIcon,
  Sun,
  Users as UsersIcon,
} from 'lucide-react'
import { useUIStore } from '@/store/ui'
import { cn } from '@/lib/utils'
import { Button } from './ui'

interface NavItem {
  to: string
  label: string
  icon: React.ComponentType<{ className?: string }>
  /** Nested routes keep the parent highlighted. */
  end?: boolean
}

// Navigation targets are relative to the router's basename ("/admin"), so a
// link here must be written as "/" or "/users", never "/admin/users".
const NAV: NavItem[] = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/users', label: 'Users', icon: UsersIcon },
  { to: '/targets', label: 'Targets', icon: Network },
  { to: '/audit', label: 'Audit Log', icon: ScrollText },
  { to: '/settings', label: 'Settings', icon: SettingsIcon },
]

// Keyed by the full pathname from useLocation(), so these stay absolute.
const BREADCRUMB: Record<string, string> = {
  '/admin': 'Dashboard',
  '/admin/users': 'Users',
  '/admin/targets': 'Targets',
  '/admin/audit': 'Audit Log',
  '/admin/settings': 'Settings',
}

export function ThemeToggle(): JSX.Element {
  const { theme, toggleTheme } = useUIStore()
  const nextLabel = theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'

  return (
    <Tooltip2 label={nextLabel}>
      <Button variant="ghost" size="icon" onClick={toggleTheme} aria-label={nextLabel}>
        {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
      </Button>
    </Tooltip2>
  )
}

/** Minimal tooltip wrapper so the shell does not import the Radix provider
 *  everywhere; the real provider is mounted once in App. */
function Tooltip2({
  label,
  children,
}: {
  label: string
  children: React.ReactNode
}): JSX.Element {
  return (
    <span title={label} className="inline-flex">
      {children}
    </span>
  )
}

export function Sidebar({
  username,
  role,
  onLogout,
}: {
  username: string
  role: string
  onLogout: () => void
}): JSX.Element {
  const collapsed = useUIStore((s) => s.sidebarCollapsed)
  const toggleSidebar = useUIStore((s) => s.toggleSidebar)

  return (
    <aside
      className={cn(
        'hidden shrink-0 border-r border-border bg-surface transition-[width] duration-200 md:flex md:flex-col',
        collapsed ? 'w-16' : 'w-60',
      )}
    >
      <div className={cn('flex h-14 items-center border-b border-border', collapsed ? 'justify-center px-2' : 'px-4')}>
        <div className="flex items-center gap-2 overflow-hidden">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-primary">
            <Activity className="h-4 w-4 text-primary-fg" />
          </div>
          {!collapsed ? (
            <div className="min-w-0">
              <p className="truncate text-sm font-semibold text-fg">NetSentinel</p>
              <p className="truncate text-[11px] text-muted">admin panel</p>
            </div>
          ) : null}
        </div>
      </div>

      <nav className="flex-1 space-y-1 p-2">
        {NAV.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) =>
              cn(
                'flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors',
                collapsed && 'justify-center px-2',
                isActive
                  ? 'bg-primary-soft font-medium text-primary'
                  : 'text-muted hover:bg-elevated hover:text-fg',
              )
            }
            title={collapsed ? item.label : undefined}
          >
            <item.icon className="h-4 w-4 shrink-0" />
            {!collapsed ? <span className="truncate">{item.label}</span> : null}
          </NavLink>
        ))}
      </nav>

      <div className="border-t border-border p-2">
        <div className={cn('mb-2 flex items-center gap-2 px-1', collapsed && 'justify-center px-0')}>
          {!collapsed ? (
            <div className="min-w-0 flex-1">
              <p className="truncate text-xs font-medium text-fg">{username}</p>
              <p className="truncate text-[11px] text-primary">{role}</p>
            </div>
          ) : null}
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8"
            aria-label="Sign out"
            onClick={onLogout}
          >
            <LogOut className="h-4 w-4" />
          </Button>
        </div>
        <Button
          variant="ghost"
          size="sm"
          className={cn('w-full', collapsed && 'px-0')}
          onClick={toggleSidebar}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
          {!collapsed ? <span>Collapse</span> : null}
        </Button>
      </div>
    </aside>
  )
}

export function Topbar({
  onLogout,
  onRefresh,
}: {
  onLogout: () => void
  onRefresh: () => void
}): JSX.Element {
  const location = useLocation()
  const navigate = useNavigate()
  const [menuOpen, setMenuOpen] = React.useState(false)

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center justify-between gap-3 border-b border-border bg-bg/85 px-4 backdrop-blur">
      <nav className="flex items-center gap-2 text-sm">
        <span className="text-muted">NetSentinel</span>
        <span className="text-muted">/</span>
        <span className="font-medium text-fg">
          {BREADCRUMB[location.pathname] ?? 'Admin'}
        </span>
      </nav>

      <div className="flex items-center gap-1">
        <Button variant="ghost" size="sm" onClick={onRefresh}>
          Refresh
        </Button>
        <ThemeToggle />
        <div className="relative">
          <Button
            variant="ghost"
            size="icon"
            aria-label="Account"
            onClick={() => setMenuOpen((v) => !v)}
          >
            <UsersIcon className="h-4 w-4" />
          </Button>
          {menuOpen ? (
            <>
              <button
                className="fixed inset-0 z-40 cursor-default"
                aria-hidden
                onClick={() => setMenuOpen(false)}
              />
              <div className="absolute right-0 z-50 mt-1 w-44 rounded-md border border-border bg-surface p-1 shadow-lg animate-fade-in">
                <button
                  className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-left text-sm text-fg transition-colors hover:bg-elevated"
                  onClick={() => {
                    setMenuOpen(false)
                    navigate('/settings')
                  }}
                >
                  <SettingsIcon className="h-4 w-4 text-muted" />
                  Settings
                </button>
                <button
                  className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-left text-sm text-danger transition-colors hover:bg-danger-soft"
                  onClick={() => {
                    setMenuOpen(false)
                    onLogout()
                  }}
                >
                  <LogOut className="h-4 w-4" />
                  Sign out
                </button>
              </div>
            </>
          ) : null}
        </div>
      </div>
    </header>
  )
}

export function AppShell({
  username,
  role,
  onLogout,
  onRefresh,
  children,
}: {
  username: string
  role: string
  onLogout: () => void
  onRefresh: () => void
  children: React.ReactNode
}): JSX.Element {
  return (
    <div className="flex min-h-screen bg-bg">
      <Sidebar username={username} role={role} onLogout={onLogout} />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar onLogout={onLogout} onRefresh={onRefresh} />
        <main className="flex-1 p-4 md:p-6">
          <div className="mx-auto max-w-7xl space-y-5">{children}</div>
        </main>
      </div>
    </div>
  )
}