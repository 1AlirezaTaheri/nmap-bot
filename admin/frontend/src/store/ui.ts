import { create } from 'zustand'

export type Theme = 'dark' | 'light'

interface UIState {
  theme: Theme
  sidebarCollapsed: boolean
  setTheme: (theme: Theme) => void
  toggleTheme: () => void
  toggleSidebar: () => void
}

const STORAGE_KEY = 'ns-theme'
const SIDEBAR_KEY = 'ns-sidebar-collapsed'

/**
 * Resolve the initial theme.
 *
 * Order of preference: an explicit previous choice, then the OS
 * `prefers-color-scheme`, then dark. The same logic runs in the inline
 * script in index.html so the very first paint is already correct.
 */
function initialTheme(): Theme {
  if (typeof window === 'undefined') return 'dark'
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY)
    if (stored === 'light' || stored === 'dark') return stored
  } catch {
    // Private-mode browsers can throw on localStorage access.
  }
  try {
    if (window.matchMedia('(prefers-color-scheme: light)').matches) return 'light'
  } catch {
    // matchMedia is unavailable in some embedded webviews.
  }
  return 'dark'
}

function applyTheme(theme: Theme, animate = true): void {
  if (typeof document === 'undefined') return
  const root = document.documentElement
  if (animate) {
    // Only animate a deliberate switch, never the initial mount.
    root.classList.add('theme-transition')
    window.setTimeout(() => root.classList.remove('theme-transition'), 200)
  }
  root.setAttribute('data-theme', theme)
}

function readSidebar(): boolean {
  if (typeof window === 'undefined') return false
  try {
    return window.localStorage.getItem(SIDEBAR_KEY) === 'true'
  } catch {
    return false
  }
}

function persist(key: string, value: string): void {
  try {
    window.localStorage.setItem(key, value)
  } catch {
    // Non-fatal: the theme still applies for this session.
  }
}

export const useUIStore = create<UIState>((set, get) => ({
  theme: initialTheme(),

  sidebarCollapsed: readSidebar(),

  setTheme: (theme) => {
    applyTheme(theme)
    persist(STORAGE_KEY, theme)
    set({ theme })
  },

  toggleTheme: () => {
    get().setTheme(get().theme === 'dark' ? 'light' : 'dark')
  },

  toggleSidebar: () => {
    const next = !get().sidebarCollapsed
    persist(SIDEBAR_KEY, String(next))
    set({ sidebarCollapsed: next })
  },
}))

// Apply the stored theme on first module evaluation.
applyTheme(useUIStore.getState().theme, false)