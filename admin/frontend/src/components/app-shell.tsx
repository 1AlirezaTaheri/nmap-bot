import * as React from 'react'
import { NavLink, useLocation, useNavigate } from 'react-router-dom'
import * as DropdownMenu from '@radix-ui/react-dropdown-menu'
import {
  Activity,
  ChevronLeft,
  ChevronRight,
  ChevronsUpDown,
  LayoutDashboard,
  LogOut,
  Moon,
  Network,
  RefreshCw,
  Paintbrush,
  ScrollText,
  Search,
  Settings as SettingsIcon,
  Sun,
  Users as UsersIcon,
} from 'lucide-react'
import { useUIStore } from '@/store/ui'
import { avatarColor, cn, initials } from '@/lib/utils'
import { Badge, Button, Tooltip, TooltipContent, TooltipTrigger } from './ui'
import { CommandPalette, useCommandPalette } from './command-palette'

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
  { to: '/telegram-users', label: 'Telegram Users', icon: UsersIcon },
  { to: '/targets', label: 'Targets', icon: Network },
  { to: '/audit', label: 'Audit Log', icon: ScrollText },
  { to: '/settings', label: 'Settings', icon: SettingsIcon },
  // Imports every Phase 1 component so they are built and shipped rather
  // than tree-shaken away as unused exports.
  { to: '/style-guide', label: 'Style Guide', icon: Paintbrush },
]

/**
 * Breadcrumb trail for a pathname.
 *
 * Keys are basename-relative. react-router strips `basename` from
 * `useLocation().pathname`, so the value here is "/targets", never
 * "/admin/targets" -- the previous map was keyed on the absolute form, every
 * lookup missed, and the crumb fell through to the literal "Admin" on every
 * page.
 *
 * A first segment that is not a known page is rendered as-is rather than
 * dropped, so a detail route like /targets/12 still produces a useful trail.
 */
function breadcrumbs(pathname: string): Array<{ label: string; to: string | null }> {
  const segments = pathname.split('/').filter(Boolean)

  // "/" has no segments; it is the dashboard.
  if (segments.length === 0) {
    return [{ label: 'Dashboard', to: null }]
  }

  const first = segments[0]
  if (first === undefined) return [{ label: 'Dashboard', to: null }]

  const known = NAV.find((item) =>
    item.to === `/${first}`,
  )
  const headLabel = known?.label ?? first
  const crumbs: Array<{ label: string; to: string | null }> = [
    { label: headLabel, to: segments.length > 1 ? known?.to ?? null : null },
  ]

  // Anything deeper: show the segment, link only the intermediates.
  for (let index = 1; index < segments.length; index += 1) {
    const segment = segments[index]
    if (segment === undefined) continue
    const isLast = index === segments.length - 1
    const to = isLast ? null : `/${segments.slice(0, index + 1).join('/')}`
    crumbs.push({
      label: isLast ? decodeURIComponent(segment) : decodeURIComponent(segment),
      to,
    })
  }

  return crumbs
}

export function ThemeToggle(): JSX.Element {
  const theme = useUIStore((s) => s.theme)
  const toggleTheme = useUIStore((s) => s.toggleTheme)
  const nextLabel = theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button variant="ghost" size="icon" onClick={toggleTheme} aria-label={nextLabel}>
          {theme === 'dark' ? (
            <Sun className="h-4 w-4" aria-hidden />
          ) : (
            <Moon className="h-4 w-4" aria-hidden />
          )}
        </Button>
      </TooltipTrigger>
      <TooltipContent>{nextLabel}</TooltipContent>
    </Tooltip>
  )
}

/** Real Radix tooltip, used only when the sidebar is collapsed. */
function CollapsedHint({
  label,
  children,
}: {
  label: string
  children: React.ReactNode
}): JSX.Element {
  return (
    <Tooltip>
      <TooltipTrigger asChild>{children}</TooltipTrigger>
      <TooltipContent side="right">{label}</TooltipContent>
    </Tooltip>
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
        'hidden shrink-0 border-r border-border bg-surface transition-[width] duration-normal ease-standard md:flex md:flex-col',
        collapsed ? 'w-16' : 'w-60',
      )}
    >
      <div
        className={cn(
          'flex h-14 items-center border-b border-border',
          collapsed ? 'justify-center px-2' : 'px-4',
        )}
      >
        <div className="flex items-center gap-2 overflow-hidden">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-primary">
            <Activity className="h-4 w-4 text-primary-fg" aria-hidden />
          </div>
          {!collapsed ? (
            <div className="min-w-0">
              <p className="truncate text-sm font-semibold text-fg">NetSentinel</p>
              <p className="truncate text-[11px] text-muted">admin panel</p>
            </div>
          ) : null}
        </div>
      </div>

      <nav className="flex-1 space-y-1 p-2" aria-label="Main">
        {NAV.map((item) => {
          const link = (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              // aria-current comes from NavLink itself; the visual treatment is
              // driven by data-active so the active row is unambiguous rather
              // than only a background tint.
              className={({ isActive }) =>
                cn(
                  'group flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors',
                  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40',
                  collapsed && 'justify-center px-2',
                  isActive
                    ? 'bg-primary-soft font-medium text-primary'
                    : 'text-muted hover:bg-elevated hover:text-fg',
                )
              }
            >
              {({ isActive }) => (
                <>
                  {/* Active rail, so the current page reads at a glance even
                      when the label is hidden. */}
                  <span
                    className={cn(
                      'h-4 w-0.5 shrink-0 rounded-full transition-colors',
                      isActive ? 'bg-primary' : 'bg-transparent',
                    )}
                    aria-hidden
                  />
                  <item.icon className="h-4 w-4 shrink-0" aria-hidden />
                  {!collapsed ? <span className="truncate">{item.label}</span> : null}
                </>
              )}
            </NavLink>
          )

          return collapsed ? (
            <CollapsedHint key={item.to} label={item.label}>
              {link}
            </CollapsedHint>
          ) : (
            <React.Fragment key={item.to}>{link}</React.Fragment>
          )
        })}
      </nav>

      <div className="border-t border-border p-2">
        <div
          className={cn(
            'mb-2 flex items-center gap-2 px-1',
            collapsed && 'justify-center px-0',
          )}
        >
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
            <LogOut className="h-4 w-4" aria-hidden />
          </Button>
        </div>
        <Button
          variant="ghost"
          size="sm"
          className={cn('w-full', collapsed && 'px-0')}
          onClick={toggleSidebar}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? (
            <ChevronRight className="h-4 w-4" aria-hidden />
          ) : (
            <ChevronLeft className="h-4 w-4" aria-hidden />
          )}
          {!collapsed ? <span>Collapse</span> : null}
        </Button>
      </div>
    </aside>
  )
}

export function Topbar({
  username,
  role,
  onLogout,
  onRefresh,
  onOpenPalette,
}: {
  username: string
  role: string
  onLogout: () => void
  onRefresh: () => void
  onOpenPalette: () => void
}): JSX.Element {
  const location = useLocation()
  const navigate = useNavigate()
  const crumbs = breadcrumbs(location.pathname)

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center justify-between gap-3 border-b border-border bg-bg/85 px-4 backdrop-blur">
      <nav aria-label="Breadcrumb" className="flex min-w-0 items-center gap-1.5 text-sm">
        {crumbs.map((crumb, index) => {
          const last = index === crumbs.length - 1
          return (
            <React.Fragment key={`${crumb.label}-${index}`}>
              {index > 0 ? (
                <ChevronsUpDown className="h-3 w-3 shrink-0 -rotate-90 text-faint" aria-hidden />
              ) : null}
              {crumb.to && !last ? (
                <button
                  type="button"
                  onClick={() => navigate(crumb.to as string)}
                  className="truncate text-muted transition-colors hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40"
                >
                  {crumb.label}
                </button>
              ) : (
                <span
                  className={cn('truncate', last ? 'font-medium text-fg' : 'text-muted')}
                  aria-current={last ? 'page' : undefined}
                >
                  {crumb.label}
                </span>
              )}
            </React.Fragment>
          )
        })}
      </nav>

      <div className="flex items-center gap-1">
        <button
          type="button"
          onClick={onOpenPalette}
          aria-label="Open command palette"
          className={cn(
            'mr-1 hidden items-center gap-2 rounded-md border border-border px-2.5 py-1.5 text-xs text-muted',
            'transition-colors hover:bg-elevated hover:text-fg',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40',
            'sm:flex',
          )}
        >
          <Search className="h-3.5 w-3.5" aria-hidden />
          <span>Search</span>
          <kbd className="rounded border border-border px-1 font-mono text-[10px]">
            Ctrl K
          </kbd>
        </button>

        <Tooltip>
          <TooltipTrigger asChild>
            <Button variant="ghost" size="icon" onClick={onRefresh} aria-label="Refresh data">
              <RefreshCw className="h-4 w-4" aria-hidden />
            </Button>
          </TooltipTrigger>
          <TooltipContent>Refresh data</TooltipContent>
        </Tooltip>

        <ThemeToggle />

        <DropdownMenu.Root>
          <DropdownMenu.Trigger asChild>
            <button
              type="button"
              aria-label={`Account menu for ${username}`}
              className={cn(
                'ml-1 flex items-center gap-2 rounded-md px-1.5 py-1 transition-colors',
                'hover:bg-elevated focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40',
              )}
            >
              <span
                className={cn(
                  'flex h-7 w-7 items-center justify-center rounded-full text-[11px] font-semibold',
                  avatarColor(username),
                )}
                aria-hidden
              >
                {initials(username)}
              </span>
              <span className="hidden text-xs font-medium text-fg lg:inline">
                {username}
              </span>
            </button>
          </DropdownMenu.Trigger>

          <DropdownMenu.Portal>
            <DropdownMenu.Content
              align="end"
              sideOffset={6}
              className="z-50 w-56 rounded-lg border border-border bg-surface p-1 shadow-lg animate-fade-in"
            >
              <div className="flex items-center gap-2 px-2 py-2">
                <span
                  className={cn(
                    'flex h-8 w-8 items-center justify-center rounded-full text-xs font-semibold',
                    avatarColor(username),
                  )}
                  aria-hidden
                >
                  {initials(username)}
                </span>
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium text-fg">{username}</p>
                  <Badge variant="success" className="mt-0.5">
                    {role}
                  </Badge>
                </div>
              </div>

              <DropdownMenu.Separator className="my-1 h-px bg-border" />

              <DropdownMenu.Item
                onSelect={() => navigate('/settings')}
                className="flex cursor-pointer items-center gap-2 rounded-sm px-2 py-1.5 text-sm text-fg outline-none data-[highlighted]:bg-elevated"
              >
                <SettingsIcon className="h-4 w-4 text-muted" aria-hidden />
                Settings
              </DropdownMenu.Item>

              <DropdownMenu.Item
                onSelect={() => navigate('/telegram-users')}
                className="flex cursor-pointer items-center gap-2 rounded-sm px-2 py-1.5 text-sm text-fg outline-none data-[highlighted]:bg-elevated"
              >
                <UsersIcon className="h-4 w-4 text-muted" aria-hidden />
                Telegram users
              </DropdownMenu.Item>

              <DropdownMenu.Separator className="my-1 h-px bg-border" />

              <DropdownMenu.Item
                onSelect={onLogout}
                className="flex cursor-pointer items-center gap-2 rounded-sm px-2 py-1.5 text-sm text-danger outline-none data-[highlighted]:bg-danger-soft"
              >
                <LogOut className="h-4 w-4" aria-hidden />
                Sign out
              </DropdownMenu.Item>
            </DropdownMenu.Content>
          </DropdownMenu.Portal>
        </DropdownMenu.Root>
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
  const [paletteOpen, setPaletteOpen] = React.useState(false)
  const openPalette = React.useCallback(() => setPaletteOpen(true), [])
  useCommandPalette(openPalette)

  return (
    <div className="flex min-h-screen bg-bg">
      <Sidebar username={username} role={role} onLogout={onLogout} />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar
          username={username}
          role={role}
          onLogout={onLogout}
          onRefresh={onRefresh}
          onOpenPalette={openPalette}
        />
        <main className="flex-1 p-4 md:p-6">
          <div className="mx-auto max-w-7xl space-y-5">{children}</div>
        </main>
      </div>

      <CommandPalette
        open={paletteOpen}
        onOpenChange={setPaletteOpen}
        onLogout={onLogout}
        onRefresh={onRefresh}
      />
    </div>
  )
}