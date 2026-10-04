/**
 * Every colour resolves to a CSS variable, and every variable is fed from
 * Telegram's themeParams at runtime (see src/lib/telegram.ts). Nothing here
 * hardcodes a hex, so the app inherits Telegram's palette in both themes
 * without a single conditional class.
 *
 * The status colours are the exception: green and red mean success and danger
 * everywhere in the app, and must stay legible against both themes.
 */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: 'rgb(var(--tg-bg) / <alpha-value>)',
        secondary: 'rgb(var(--tg-secondary-bg) / <alpha-value>)',
        text: 'rgb(var(--tg-text) / <alpha-value>)',
        hint: 'rgb(var(--tg-hint) / <alpha-value>)',
        link: 'rgb(var(--tg-link) / <alpha-value>)',
        button: 'rgb(var(--tg-button) / <alpha-value>)',
        'button-text': 'rgb(var(--tg-button-text) / <alpha-value>)',
        // Fixed, not themed: a "good" result must read as good in both.
        good: 'rgb(var(--ns-good) / <alpha-value>)',
        'good-soft': 'rgb(var(--ns-good-soft) / <alpha-value>)',
        bad: 'rgb(var(--ns-bad) / <alpha-value>)',
        'bad-soft': 'rgb(var(--ns-bad-soft) / <alpha-value>)',
        warn: 'rgb(var(--ns-warn) / <alpha-value>)',
        'warn-soft': 'rgb(var(--ns-warn-soft) / <alpha-value>)',
        info: 'rgb(var(--ns-info) / <alpha-value>)',
        'info-soft': 'rgb(var(--ns-info-soft) / <alpha-value>)',
      },
      fontFamily: {
        sans: ['-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      borderRadius: {
        lg: '0.75rem',
        md: '0.625rem',
        sm: '0.4375rem',
      },
      spacing: {
        // Telegram's own tab bar height, so the layout matches the host app.
        tabbar: '56px',
      },
      keyframes: {
        'fade-in': { from: { opacity: '0' }, to: { opacity: '1' } },
        'slide-up': {
          from: { transform: 'translateY(100%)' },
          to: { transform: 'translateY(0)' },
        },
        shimmer: { '100%': { transform: 'translateX(100%)' } },
      },
      animation: {
        'fade-in': 'fade-in 140ms ease-out',
        'slide-up': 'slide-up 220ms cubic-bezier(0.32, 0.72, 0, 1)',
      },
    },
  },
  plugins: [],
}