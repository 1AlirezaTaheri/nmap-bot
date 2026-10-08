import * as React from 'react'
import { NavLink } from 'react-router-dom'
import { Activity, LogOut, X } from 'lucide-react'
import { avatarColor, cn, initials } from '@/lib/utils'

interface MobileNavProps {
  open: boolean
  onClose: () => void
  username: string
  role: string
  onLogout: () => void
  items: ReadonlyArray<{
    to: string
    label: string
    icon: React.ComponentType<{ className?: string }>
    end?: boolean
  }>
}

/**
 * Navigation for small screens.
 *
 * The desktop sidebar is `hidden md:flex`, so below 768px the panel had no
 * navigation at all -- you could reach a page by URL and not by tapping. That
 * is the single largest usability hole in the shell, and it is why this
 * exists rather than a fourth breakpoint on the sidebar: on a 375px screen a
 * persistent rail costs more than it gives.
 *
 * Behaviours that matter on touch:
 *   * closes on navigation, or the drawer covers the page you just asked for;
 *   * closes on Escape and on a backdrop tap;
 *   * locks body scroll while open, so the page behind does not scroll under
 *     the finger;
 *   * focus moves into the panel and returns to the trigger on close.
 */
export function MobileNav({
  open,
  onClose,
  username,
  role,
  onLogout,
  items,
}: MobileNavProps): JSX.Element | null {
  const panel = React.useRef<HTMLDivElement | null>(null)
  const trigger = React.useRef<HTMLElement | null>(null)

  // Remember what had focus so it can be restored on close. Without this the
  // keyboard user lands back at the top of the document after every visit.
  React.useEffect(() => {
    if (!open) return
    trigger.current = document.activeElement as HTMLElement | null

    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'

    panel.current?.focus()

    function onKeyDown(event: KeyboardEvent): void {
      if (event.key === 'Escape') {
        onClose()
        return
      }
      if (event.key !== 'Tab' || !panel.current) return

      // Focus trap. Without it Tab walks out of the dialog into the page
      // behind, which is still visible around the backdrop.
      const focusable = panel.current?.querySelectorAll<HTMLElement>(
        'a[href], button:not([disabled]), [tabindex]:not([tabindex="-1"])',
      )
      if (!focusable || focusable.length === 0) return
      const first = focusable[0]
      const last = focusable[focusable.length - 1]
      if (!first || !last) return

      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault()
        first.focus()
      }
    }

    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('keydown', onKeyDown)
      document.body.style.overflow = previousOverflow
      trigger.current?.focus()
    }
  }, [open, onClose])

  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 md:hidden" role="presentation">
      <button
        type="button"
        aria-label="Close navigation"
        onClick={onClose}
        className="absolute inset-0 bg-black/60 backdrop-blur-sm data-[state=open]:animate-fade-in"
      />
      <div
        ref={panel}
        role="dialog"
        aria-modal="true"
        aria-label="Navigation"
        tabIndex={-1}
        className="absolute inset-y-0 left-0 flex w-72 max-w-[85vw] flex-col border-r border-border bg-surface shadow-2xl animate-slide-in-right"
      >
        <div className="flex h-14 items-center justify-between border-b border-border px-4">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary">
              <Activity className="h-4 w-4 text-primary-fg" aria-hidden />
            </div>
            <div className="min-w-0">
              <p className="truncate text-sm font-semibold text-fg">NetSentinel</p>
              <p className="truncate text-[11px] text-muted">admin panel</p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close navigation"
            className="rounded-md p-1.5 text-muted transition-colors hover:bg-elevated hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40"
          >
            <X className="h-4 w-4" aria-hidden />
          </button>
        </div>

        <nav className="flex-1 space-y-1 overflow-y-auto p-3" aria-label="Main">
          {items.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              onClick={onClose}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-3 rounded-md px-3 py-2.5 text-sm transition-colors',
                  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40',
                  isActive
                    ? 'bg-primary-soft font-medium text-primary'
                    : 'text-muted hover:bg-elevated hover:text-fg',
                )
              }
            >
              <item.icon className="h-4 w-4 shrink-0" aria-hidden />
              <span className="truncate">{item.label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="border-t border-border p-3">
          <div className="mb-2 flex items-center gap-2 px-1">
            <span
              className={cn(
                'flex h-8 w-8 items-center justify-center rounded-full text-xs font-semibold',
                avatarColor(username),
              )}
              aria-hidden
            >
              {initials(username)}
            </span>
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm font-medium text-fg">{username}</p>
              <p className="truncate text-xs text-primary">{role}</p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => {
              onClose()
              onLogout()
            }}
            className={cn(
              'flex w-full items-center gap-2 rounded-md px-3 py-2 text-sm text-danger',
              'transition-colors hover:bg-danger-soft',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40',
            )}
          >
            <LogOut className="h-4 w-4" aria-hidden />
            Sign out
          </button>
        </div>
      </div>
    </div>
  )
}