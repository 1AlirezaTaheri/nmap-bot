import * as React from 'react'
import { Command as CommandPrimitive } from 'cmdk'
import { Search } from 'lucide-react'
import { cn } from '@/lib/utils'
import { Dialog, DialogContent } from './ui'

/* -------------------------------------------------------------------------- */
/* Command palette                                                            */
/* -------------------------------------------------------------------------- */

/**
 * Palette shell. `cmdk` supplies the combobox semantics, fuzzy filtering and
 * arrow-key navigation; the Radix Dialog around it supplies the focus trap,
 * Escape handling and scroll lock. Neither does the other's job well.
 */
export const Command = CommandPrimitive

export function CommandDialog({
  children,
  className,
  ...props
}: React.ComponentProps<typeof Dialog> & { className?: string }): JSX.Element {
  return (
    <Dialog {...props}>
      {/* className is taken off Root explicitly: Radix's DialogProps has no
          className, so it must be forwarded to the Content that accepts one. */}
      <DialogContent
        className={cn(
          'top-[12%] translate-y-0 p-0',
          'w-[calc(100vw-2rem)] max-w-xl overflow-hidden',
          className,
        )}
      >
        <Command
          // cmdk needs a label; visually hidden so it does not shift layout.
          label="Command palette"
          className="flex flex-col"
        >
          {children}
        </Command>
      </DialogContent>
    </Dialog>
  )
}

export function CommandInput({
  className,
  ...props
}: React.ComponentProps<typeof CommandPrimitive.Input>): JSX.Element {
  return (
    <div className="flex items-center gap-2 border-b border-border px-3">
      <Search className="h-4 w-4 shrink-0 text-muted" aria-hidden />
      <CommandPrimitive.Input
        className={cn(
          'h-11 w-full bg-transparent text-sm text-fg outline-none',
          'placeholder:text-faint disabled:opacity-50',
          className,
        )}
        {...props}
      />
    </div>
  )
}

export function CommandList({
  className,
  ...props
}: React.ComponentProps<typeof CommandPrimitive.List>): JSX.Element {
  return (
    <CommandPrimitive.List
      className={cn('max-h-80 overflow-y-auto p-1', className)}
      {...props}
    />
  )
}

export function CommandEmpty(
  props: React.ComponentProps<typeof CommandPrimitive.Empty>,
): JSX.Element {
  return (
    <CommandPrimitive.Empty
      className="py-8 text-center text-sm text-muted"
      {...props}
    />
  )
}

export function CommandGroup({
  className,
  heading,
  children,
  ...props
}: React.ComponentProps<typeof CommandPrimitive.Group>): JSX.Element {
  return (
    <CommandPrimitive.Group
      className={cn('mb-1 last:mb-0', className)}
      {...props}
    >
      {heading ? (
        <div className="px-2 py-1.5 text-[11px] font-semibold uppercase tracking-wide text-faint">
          {heading}
        </div>
      ) : null}
      {children}
    </CommandPrimitive.Group>
  )
}

export function CommandItem({
  className,
  children,
  ...props
}: React.ComponentProps<typeof CommandPrimitive.Item>): JSX.Element {
  return (
    <CommandPrimitive.Item
      className={cn(
        'flex cursor-pointer items-center gap-2.5 rounded-md px-2 py-2 text-sm text-fg',
        'transition-colors',
        // cmdk marks the highlighted row with data-selected.
        'data-[selected=true]:bg-elevated data-[selected=true]:text-fg',
        'data-[disabled=true]:pointer-events-none data-[disabled=true]:opacity-50',
        className,
      )}
      {...props}
    >
      {children}
    </CommandPrimitive.Item>
  )
}

export function CommandSeparator({
  className,
  ...props
}: React.ComponentProps<typeof CommandPrimitive.Separator>): JSX.Element {
  return (
    <CommandPrimitive.Separator
      className={cn('my-1 h-px bg-border', className)}
      {...props}
    />
  )
}

export function CommandShortcut({
  className,
  ...props
}: React.HTMLAttributes<HTMLSpanElement>): JSX.Element {
  return (
    <span
      className={cn(
        'ml-auto shrink-0 rounded border border-border px-1.5 py-0.5',
        'font-mono text-[10px] text-muted',
        className,
      )}
      {...props}
    />
  )
}