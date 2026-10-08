/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ['class'],
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Every colour is a CSS variable so the theme toggle only has to
        // flip attributes on <html>; Tailwind never hardcodes a hex.
        bg: 'rgb(var(--bg) / <alpha-value>)',
        surface: 'rgb(var(--surface) / <alpha-value>)',
        elevated: 'rgb(var(--elevated) / <alpha-value>)',
        border: 'rgb(var(--border) / <alpha-value>)',
        input: 'rgb(var(--input) / <alpha-value>)',
        fg: 'rgb(var(--fg) / <alpha-value>)',
        muted: 'rgb(var(--muted) / <alpha-value>)',
        faint: 'rgb(var(--faint) / <alpha-value>)',
        primary: {
          DEFAULT: 'rgb(var(--primary) / <alpha-value>)',
          fg: 'rgb(var(--primary-fg) / <alpha-value>)',
          soft: 'rgb(var(--primary-soft) / <alpha-value>)',
        },
        danger: {
          DEFAULT: 'rgb(var(--danger) / <alpha-value>)',
          fg: 'rgb(var(--danger-fg) / <alpha-value>)',
          soft: 'rgb(var(--danger-soft) / <alpha-value>)',
        },
        warning: {
          DEFAULT: 'rgb(var(--warning) / <alpha-value>)',
          soft: 'rgb(var(--warning-soft) / <alpha-value>)',
        },
        info: {
          DEFAULT: 'rgb(var(--info) / <alpha-value>)',
          soft: 'rgb(var(--info-soft) / <alpha-value>)',
        },
        success: {
          DEFAULT: 'rgb(var(--success) / <alpha-value>)',
          soft: 'rgb(var(--success-soft) / <alpha-value>)',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      borderRadius: {
        xl: '0.75rem',
        lg: '0.5rem',
        md: '0.375rem',
        sm: '0.25rem',
      },
      // Named so a shadow can express depth rather than an arbitrary
      // Tailwind step. Sized and coloured per theme in index.css, because a
      // shadow that works on an opaque dark surface is wrong on a
      // translucent light one.
      boxShadow: {
        sm: 'var(--shadow-sm)',
        md: 'var(--shadow-md)',
        lg: 'var(--shadow-lg)',
        // For focus rings and the active nav item. Tinted with the theme's
        // own accent rather than pure black, so it reads as glow.
        glow: 'var(--shadow-glow)',
      },
      // Only durations the app actually uses are declared: Tailwind emits a
      // utility only if the scanned source references it, so an unreferenced
      // entry is dead config that reads as coverage but provides none.
      transitionDuration: {
        fast: '150ms',
        normal: '250ms',
        // Matches the accordion keyframes exactly. Shared with them rather
        // than reusing `normal`, so a motion change cannot desync the panel
        // from its animation.
        accordion: '200ms',
      },
      transitionTimingFunction: {
        standard: 'cubic-bezier(0.2, 0, 0.2, 1)',
        entrance: 'cubic-bezier(0, 0, 0.2, 1)',
        exit: 'cubic-bezier(0.4, 0, 1, 1)',
      },
      keyframes: {
        'fade-in': { from: { opacity: '0' }, to: { opacity: '1' } },
        'slide-up': {
          from: { opacity: '0', transform: 'translateY(6px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
        'slide-in-right': {
          from: { transform: 'translateX(100%)' },
          to: { transform: 'translateX(0)' },
        },
        shake: {
          '0%, 100%': { transform: 'translateX(0)' },
          '15%, 45%, 75%': { transform: 'translateX(-6px)' },
          '30%, 60%, 90%': { transform: 'translateX(6px)' },
        },
        shimmer: {
          '100%': { transform: 'translateX(100%)' },
        },
        // Grid-template-rows disclosure, used by Accordion. Animating a
        // measured pixel height would need a ref and a ResizeObserver per
        // panel; 1fr/0fr needs neither and handles a resize for free.
        'accordion-down': {
          from: { gridTemplateRows: '0fr' },
          to: { gridTemplateRows: '1fr' },
        },
        'accordion-up': {
          from: { gridTemplateRows: '1fr' },
          to: { gridTemplateRows: '0fr' },
        },
      },
      animation: {
        'fade-in': 'fade-in 150ms ease-out',
        'slide-up': 'slide-up 180ms ease-out',
        'slide-in-right': 'slide-in-right 200ms ease-out',
        shake: 'shake 400ms ease-in-out',
        shimmer: 'shimmer 1.6s infinite',
        'accordion-down': 'accordion-down 200ms cubic-bezier(0, 0, 0.2, 1)',
        'accordion-up': 'accordion-up 200ms cubic-bezier(0.4, 0, 1, 1)',
      },
    },
  },
  plugins: [],
}