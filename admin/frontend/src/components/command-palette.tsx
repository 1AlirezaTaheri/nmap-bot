import * as React from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  LayoutDashboard,
  LogOut,
  Network,
  Paintbrush,
  PlusCircle,
  RefreshCw,
  ScrollText,
  Search,
  Settings as SettingsIcon,
  Users as UsersIcon,
} from 'lucide-react'
import { api } from '@/lib/api'
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
  CommandShortcut,
} from './command'

/** Navigation targets, relative to the router basename ("/admin"). */
const PAGES: ReadonlyArray<{
  label: string
  to: string
  icon: React.ComponentType<{ className?: string }>
}> = [
  { label: 'Dashboard', to: '/', icon: LayoutDashboard },
  { label: 'Telegram Users', to: '/telegram-users', icon: UsersIcon },
  { label: 'Targets', to: '/targets', icon: Network },
  { label: 'Audit Log', to: '/audit', icon: ScrollText },
  { label: 'Settings', to: '/settings', icon: SettingsIcon },
  { label: 'Style Guide', to: '/style-guide', icon: Paintbrush },
]

interface PaletteProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onLogout: () => void
  onRefresh: () => void
}

export function CommandPalette({
  open,
  onOpenChange,
  onLogout,
  onRefresh,
}: PaletteProps): JSX.Element {
  const navigate = useNavigate()

  // Fetched only while the palette is open, so it costs nothing at rest. The
  // existing 'targets' query is reused when it is already warm, which is the
  // common case for an operator who has the targets page open.
  const { data: targets } = useQuery({
    queryKey: ['targets'],
    queryFn: ({ signal }) => api.listTargets(signal),
    enabled: open,
    staleTime: 30_000,
  })

  function go(to: string): void {
    onOpenChange(false)
    navigate(to)
  }

  function run(action: () => void): void {
    onOpenChange(false)
    action()
  }

  return (
    <CommandDialog open={open} onOpenChange={onOpenChange}>
      <CommandInput placeholder="Search pages and targets…" />

      <CommandList>
        <CommandEmpty>No matches.</CommandEmpty>

        <CommandGroup heading="Go to">
          {PAGES.map((page) => (
            <CommandItem
              key={page.to}
              value={`go ${page.label}`}
              onSelect={() => go(page.to)}
            >
              <page.icon className="h-4 w-4 text-muted" aria-hidden />
              <span>{page.label}</span>
            </CommandItem>
          ))}
        </CommandGroup>

        {targets && targets.targets.length > 0 ? (
          <CommandGroup heading="Targets">
            {/* Every target, not a truncated list: cmdk filters as the user
                types, so showing all of them makes the palette a real search
                rather than a jump-to-first-five. */}
            {targets.targets.map((target) => (
              <CommandItem
                key={target.id}
                value={`target ${target.name} ${target.value}`}
                onSelect={() => go(`/targets?target=${encodeURIComponent(target.name)}`)}
              >
                <Network className="h-4 w-4 text-muted" aria-hidden />
                <span className="truncate">{target.name}</span>
                <span className="ml-auto truncate font-mono text-xs text-muted">
                  {target.value}
                </span>
              </CommandItem>
            ))}
          </CommandGroup>
        ) : null}

        <CommandSeparator />

        <CommandGroup heading="Actions">
          <CommandItem value="action add target" onSelect={() => go('/targets?new=1')}>
            <PlusCircle className="h-4 w-4 text-muted" aria-hidden />
            <span>Add target</span>
          </CommandItem>
          <CommandItem value="action refresh data" onSelect={() => run(onRefresh)}>
            <RefreshCw className="h-4 w-4 text-muted" aria-hidden />
            <span>Refresh data</span>
            <CommandShortcut>R</CommandShortcut>
          </CommandItem>
          <CommandItem value="action sign out" onSelect={() => run(onLogout)}>
            <LogOut className="h-4 w-4 text-danger" aria-hidden />
            <span className="text-danger">Sign out</span>
          </CommandItem>
        </CommandGroup>
      </CommandList>

      <div className="flex items-center gap-3 border-t border-border px-3 py-2 text-[11px] text-muted">
        <span className="flex items-center gap-1">
          <Search className="h-3 w-3" aria-hidden />
          Type to filter
        </span>
        <span className="ml-auto flex items-center gap-1">
          <kbd className="rounded border border-border px-1">↑</kbd>
          <kbd className="rounded border border-border px-1">↓</kbd>
          navigate
        </span>
        <span className="flex items-center gap-1">
          <kbd className="rounded border border-border px-1">Enter</kbd>
          select
        </span>
        <span className="flex items-center gap-1">
          <kbd className="rounded border border-border px-1">Esc</kbd>
          close
        </span>
      </div>
    </CommandDialog>
  )
}

/**
 * Open the palette on Ctrl+K / Cmd+K, and on the "r" key when no text field
 * has focus.
 *
 * The modifier variant is the one users expect. The bare "r" is deliberately
 * skipped while focus is in an input, textarea or contenteditable, otherwise
 * typing "r" into the filter box would fire a data refresh.
 */
export function useCommandPalette(
  onOpen: () => void,
): void {
  React.useEffect(() => {
    function onKeyDown(event: KeyboardEvent): void {
      const target = event.target as HTMLElement | null
      const inField =
        target instanceof HTMLInputElement ||
        target instanceof HTMLTextAreaElement ||
        target instanceof HTMLSelectElement ||
        target?.isContentEditable === true

      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        onOpen()
        return
      }
      if (!inField && !event.metaKey && !event.ctrlKey && !event.altKey) {
        if (event.key.toLowerCase() === 'r') {
          event.preventDefault()
          onOpen()
        }
      }
    }

    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [onOpen])
}