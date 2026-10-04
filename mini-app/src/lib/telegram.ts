/**
 * Telegram WebApp bindings, isolated behind one module.
 *
 * Everything the Mini App needs from Telegram lives here so the rest of the
 * code never touches the global, and so the app still runs in a plain browser
 * (`npm run dev`, or a linter) where the SDK is absent.
 */

import WebApp from '@twa-dev/sdk'

/** True when actually running inside Telegram. */
export const inTelegram = (() => {
  try {
    return Boolean(WebApp.initData)
  } catch {
    return false
  }
})()

/** The signed blob the backend verifies. Empty outside Telegram. */
export function initData(): string {
  try {
    return WebApp.initData ?? ''
  } catch {
    return ''
  }
}

interface TelegramUserUnsafe {
  id: number
  first_name?: string
  last_name?: string
  username?: string
  language_code?: string
}

/**
 * Telegram's *unverified* view of the user, for the greeting only.
 *
 * Never use this for authorization: the values are whatever the client claims.
 * The server re-derives identity from the signature and its own database.
 */
export function userUnsafe(): TelegramUserUnsafe | null {
  try {
    return WebApp.initDataUnsafe?.user ?? null
  } catch {
    return null
  }
}

type ColorScheme = 'light' | 'dark'

function applyTheme(): void {
  const root = document.documentElement
  let theme: Record<string, string> = {}
  let scheme: ColorScheme = 'light'

  try {
    // ThemeParams is a named interface with no index signature, so TypeScript
    // will not let it stand in for Record<string, string> even though every
    // value is a string. Widened via unknown at this one boundary rather than
    // cast at each of the seven use sites below.
    theme = {
      ...((WebApp.themeParams ?? {}) as unknown as Record<string, string>),
    }
    scheme = (WebApp.colorScheme as ColorScheme) ?? 'light'
  } catch {
    /* fall through to the defaults already in index.css */
  }

  root.setAttribute('data-color-scheme', scheme)

  const set = (name: string, fallback: string) =>
    root.style.setProperty(name, theme[name] || fallback)

  set('--tg-bg', scheme === 'dark' ? '#17212b' : '#ffffff')
  set('--tg-secondary-bg', scheme === 'dark' ? '#0e1621' : '#f2f2f7')
  set('--tg-text', scheme === 'dark' ? '#f5f5f5' : '#000000')
  set('--tg-hint', scheme === 'dark' ? '#7d8590' : '#707579')
  set('--tg-link', '#2aabee')
  set('--tg-button', '#2aabee')
  set('--tg-button-text', '#ffffff')
}

/** Tell the host app we are ready and want the full height. */
export function init(): void {
  try {
    WebApp.ready()
    WebApp.expand()
    WebApp.setHeaderColor('secondary_bg_color')
    WebApp.setBackgroundColor('bg_color')
    // The app draws its own chrome, so hide Telegram's BackButton until a
    // sheet is open; pages drive it via setBackVisible().
    WebApp.BackButton.hide()
    WebApp.enableClosingConfirmation()
  } catch {
    /* outside Telegram: the UI still works, just unthemed */
  }
  applyTheme()
}

/** Subscribe to Telegram theme changes. Returns an unsubscribe function. */
export function onThemeChange(handler: () => void): () => void {
  try {
    WebApp.onEvent('themeChanged', () => {
      applyTheme()
      handler()
    })
    return () => WebApp.offEvent('themeChanged', handler)
  } catch {
    return () => {}
  }
}

export function setBackVisible(visible: boolean): void {
  try {
    if (visible) WebApp.BackButton.show()
    else WebApp.BackButton.hide()
  } catch {
    /* no-op outside Telegram */
  }
}

/** Register the hardware/gesture Back action while a sheet is open. */
export function onBack(handler: () => void): () => void {
  try {
    WebApp.BackButton.onClick(handler)
    return () => WebApp.BackButton.offClick(handler)
  } catch {
    return () => {}
  }
}

export function haptic(style: 'light' | 'medium' | 'heavy' | 'success' | 'error' = 'light'): void {
  try {
    if (style === 'success' || style === 'error') {
      WebApp.HapticFeedback.notificationOccurred(style)
    } else {
      WebApp.HapticFeedback.impactOccurred(style)
    }
  } catch {
    /* no-op */
  }
}

/** Transient confirmation, native to Telegram. */
export function toast(message: string): void {
  try {
    // showToast landed in Bot API 8.0 but is absent from the SDK 8.0 type
    // definitions. Probed rather than assumed, so an older runtime (or a
    // browser) simply does nothing instead of throwing.
    const host = WebApp as unknown as { showToast?: (text: string) => void }
    host.showToast?.(message)
  } catch {
    /* no-op */
  }
}

/** Destructive confirmation. Resolves false when the user declines. */
export function confirmDestructive(message: string): Promise<boolean> {
  return new Promise((resolve) => {
    try {
      WebApp.showPopup(
        {
          title: 'Are you sure?',
          message,
          buttons: [{ type: 'cancel' }, { type: 'destructive', text: 'Delete' }],
        },
        // Telegram types the callback id as optional (it omits it for some
        // button types), so the parameter has to accept undefined.
        (id?: string) => resolve(id === 'destructive'),
      )
    } catch {
      // Outside Telegram there is no popup, so fall back to the browser
      // confirm rather than silently doing nothing.
      resolve(window.confirm(message))
    }
  })
}

export function close(): void {
  try {
    WebApp.close()
  } catch {
    /* no-op */
  }
}

/** The Telegram user's display name, from the unverified payload. */
export function displayName(fallback: string): string {
  const user = userUnsafe()
  if (!user) return fallback
  return [user.first_name, user.last_name].filter(Boolean).join(' ') || fallback
}

/** Read a value out of WebApp.initDataUnsafe's start_param. */
export function startParam(): string | null {
  try {
    return WebApp.initDataUnsafe?.start_param ?? null
  } catch {
    return null
  }
}