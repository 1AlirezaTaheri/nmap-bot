import * as React from 'react'
import * as DialogPrimitive from '@radix-ui/react-dialog'
import * as AlertDialogPrimitive from '@radix-ui/react-alert-dialog'
import * as SelectPrimitive from '@radix-ui/react-select'
import * as SwitchPrimitive from '@radix-ui/react-switch'
import * as TooltipPrimitive from '@radix-ui/react-tooltip'
import * as TabsPrimitive from '@radix-ui/react-tabs'
import * as PopoverPrimitive from '@radix-ui/react-popover'
import { cva, type VariantProps } from 'class-variance-authority'
import { Check, ChevronDown, X } from 'lucide-react'
import { cn } from '@/lib/utils'

/* -------------------------------------------------------------------------- */
/* Button                                                                     */
/* -------------------------------------------------------------------------- */

const buttonVariants = cva(
  'inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium ' +
    'transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40 ' +
    'disabled:pointer-events-none disabled:opacity-50',
  {
    variants: {
      variant: {
        default: 'bg-primary text-primary-fg hover:opacity-90',
        secondary: 'bg-elevated text-fg hover:bg-border',
        outline: 'border border-border bg-transparent text-fg hover:bg-elevated',
        ghost: 'text-muted hover:bg-elevated hover:text-fg',
        danger: 'bg-danger text-danger-fg hover:opacity-90',
        link: 'text-primary underline-offset-4 hover:underline',
      },
      size: {
        sm: 'h-8 px-3 text-xs',
        default: 'h-9 px-4',
        lg: 'h-11 px-6',
        icon: 'h-9 w-9',
      },
    },
    defaultVariants: { variant: 'default', size: 'default' },
  },
)

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, ...props }, ref) => (
    <button
      ref={ref}
      className={cn(buttonVariants({ variant, size }), className)}
      {...props}
    />
  ),
)
Button.displayName = 'Button'

/* -------------------------------------------------------------------------- */
/* Card                                                                       */
/* -------------------------------------------------------------------------- */

export function CardHeader({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>): JSX.Element {
  return <div className={cn('flex items-start justify-between gap-3 p-4', className)} {...props} />
}

export function CardTitle({
  className,
  ...props
}: React.HTMLAttributes<HTMLHeadingElement>): JSX.Element {
  return <h3 className={cn('text-sm font-semibold text-fg', className)} {...props} />
}

export function CardContent({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>): JSX.Element {
  return <div className={cn('p-4 pt-0', className)} {...props} />
}

/* -------------------------------------------------------------------------- */
/* Tabs (Radix)                                                                */
/* -------------------------------------------------------------------------- */

/**
 * Tabs, driven entirely by Radix so the roving-tabindex, arrow-key navigation
 * and ARIA roles are correct rather than approximated.
 *
 * Uncontrolled by default (`defaultValue`); pass `value` plus
 * `onValueChange` to control it. Keyboard: Left/Right move between tabs,
 * Home/End jump to the ends, which is what Radix provides for free.
 */
export interface TabsProps
  extends React.ComponentPropsWithoutRef<typeof TabsPrimitive.Root> {
  items: ReadonlyArray<{
    value: string
    label: React.ReactNode
    /** Optional count rendered as a badge after the label. */
    count?: number
    disabled?: boolean
  }>
}

export function Tabs({
  items,
  className,
  children,
  ...props
}: TabsProps): JSX.Element {
  return (
    <TabsPrimitive.Root
      className={cn('flex flex-col', className)}
      defaultValue={items.find((item) => !item.disabled)?.value}
      {...props}
    >
      <TabsPrimitive.List
        className="flex gap-1 overflow-x-auto border-b border-border"
        role="tablist"
      >
        {items.map((item) => (
          <TabsPrimitive.Trigger
            key={item.value}
            value={item.value}
            disabled={item.disabled}
            className={cn(
              'relative shrink-0 whitespace-nowrap px-3 py-2 text-sm font-medium text-muted',
              'transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40',
              'hover:text-fg disabled:pointer-events-none disabled:opacity-50',
              // The underline is the active indicator. `after` rather than a
              // border so the list's own bottom border is not doubled.
              'after:absolute after:inset-x-2 after:-bottom-px after:h-0.5 after:rounded-full',
              'after:bg-transparent after:transition-colors',
              'data-[state=active]:text-fg data-[state=active]:after:bg-primary',
            )}
          >
            {item.label}
            {typeof item.count === 'number' ? (
              <span className="ml-1.5 rounded-full bg-elevated px-1.5 py-0.5 text-[10px] tabular-nums text-muted">
                {item.count}
              </span>
            ) : null}
          </TabsPrimitive.Trigger>
        ))}
      </TabsPrimitive.List>
      {children}
    </TabsPrimitive.Root>
  )
}

export const TabsContent = TabsPrimitive.Content

/* -------------------------------------------------------------------------- */
/* Popover (Radix)                                                            */
/* -------------------------------------------------------------------------- */

export const Popover = PopoverPrimitive.Root
export const PopoverTrigger = PopoverPrimitive.Trigger
export const PopoverAnchor = PopoverPrimitive.Anchor

export function PopoverContent({
  className,
  align = 'center',
  sideOffset = 6,
  ...props
}: React.ComponentPropsWithoutRef<typeof PopoverPrimitive.Content>): JSX.Element {
  return (
    <PopoverPrimitive.Portal>
      <PopoverPrimitive.Content
        align={align}
        sideOffset={sideOffset}
        collisionPadding={8}
        className={cn(
          'z-50 w-72 rounded-lg border border-border bg-surface p-3 text-fg shadow-lg',
          'animate-fade-in',
          className,
        )}
        {...props}
      />
    </PopoverPrimitive.Portal>
  )
}

/* -------------------------------------------------------------------------- */
/* Card variants                                                              */
/* -------------------------------------------------------------------------- */

const cardVariants = cva('rounded-lg transition-colors', {
  variants: {
    variant: {
      // Flat surface, no edge. Quietest; for stacked content where the
      // background alone separates the block.
      default: 'border border-transparent bg-surface',
      // The default look today: an explicit edge, no shadow.
      bordered: 'border border-border bg-surface',
      // Lifted: a shadow instead of relying on the border. Used for panels
      // that sit above the page (dropdowns, floating cards).
      elevated: 'border border-border bg-elevated shadow-lg',
      // Clickable surface. Adds the hover/focus affordances a button would,
      // and only when the caller passes an onClick -- otherwise a card that
      // looks clickable but is not is a dark pattern.
      interactive:
        'cursor-pointer border border-border bg-surface hover:border-primary/50 hover:bg-elevated ' +
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40',
    },
  },
  defaultVariants: { variant: 'bordered' },
})

export type CardElement = 'div' | 'button' | 'a' | 'section' | 'article'

export interface CardProps extends React.HTMLAttributes<HTMLElement> {
  variant?: NonNullable<VariantProps<typeof cardVariants>['variant']>
  /**
   * Element to render. An interactive card should be `button` or `a` so it is
   * reachable by keyboard and announced correctly; a plain `div` is neither.
   *
   * The prop bag is typed as HTMLAttributes<HTMLElement> rather than per-tag,
   * because a union of tags makes React try to satisfy every member's handler
   * types at once and fails. That means tag-specific attributes (`href`,
   * `disabled`, ...) are not type-checked here and must be supplied by the
   * caller; TS cannot express "the props depend on the tag" without a generic
   * wrapper, which would cost every call site an explicit type argument.
   */
  as?: CardElement
  /** Only meaningful when `as` is `button`. Defaults to "button", never
   *  "submit", so a card inside a form cannot submit it by accident. */
  type?: 'button' | 'submit' | 'reset'
}

export function Card({
  className,
  variant,
  as: Tag = 'div',
  type,
  ...props
}: CardProps): JSX.Element {
  const isButton = Tag === 'button'
  return (
    <Tag
      className={cn(
        'card',
        cardVariants({ variant }),
        // <button> centres its content by default and carries UA font
        // styling, both wrong for a text block.
        isButton && 'text-left font-normal',
        className,
      )}
      {...(isButton ? { type: type ?? 'button' } : {})}
      {...props}
    />
  )
}

/* -------------------------------------------------------------------------- */
/* Accordion (hand-rolled on Radix-free primitives)                            */
/* -------------------------------------------------------------------------- */

export interface AccordionItem {
  value: string
  title: React.ReactNode
  content: React.ReactNode
  disabled?: boolean
}

export interface AccordionProps {
  items: readonly AccordionItem[]
  /** Values that start open. Uncontrolled afterwards. */
  defaultOpen?: readonly string[]
  type?: 'single' | 'multiple'
  className?: string
}

/**
 * Disclosure list.
 *
 * Hand-rolled rather than on @radix-ui/react-accordion: the panel needs one
 * controlled disclosure with a chevron and a height transition, and Radix
 * would add a dependency (~3 kB gzip) plus a context provider for behaviour
 * this component already has. Keyboard and ARIA follow the WAI-ARIA
 * disclosure pattern: each header is a <button> in a heading, with
 * aria-expanded and aria-controls, so Tab reaches every header and
 * Enter/Space toggles.
 *
 * The height animation uses a grid-template-rows trick rather than a measured
 * pixel height, so no ref and no ResizeObserver: `1fr` when open, `0fr` when
 * closed, which animates to whatever the content height turns out to be.
 */
export function Accordion({
  items,
  defaultOpen = [],
  type = 'single',
  className,
}: AccordionProps): JSX.Element {
  const [open, setOpen] = React.useState<ReadonlySet<string>>(
    () => new Set(defaultOpen),
  )

  function toggle(value: string): void {
    setOpen((previous) => {
      const next = new Set(previous)
      if (next.has(value)) {
        next.delete(value)
      } else if (type === 'single') {
        // Single mode: opening one closes the rest.
        next.clear()
        next.add(value)
      } else {
        next.add(value)
      }
      return next
    })
  }

  const baseId = React.useId()

  return (
    <div className={cn('divide-y divide-border', className)}>
      {items.map((item) => {
        const isOpen = open.has(item.value)
        const headerId = `${baseId}-h-${item.value}`
        const panelId = `${baseId}-p-${item.value}`

        return (
          <div key={item.value}>
            <h3>
              <button
                type="button"
                id={headerId}
                aria-expanded={isOpen}
                aria-controls={panelId}
                disabled={item.disabled}
                onClick={() => toggle(item.value)}
                className={cn(
                  'flex w-full items-center justify-between gap-3 px-1 py-3 text-left text-sm font-medium text-fg',
                  'transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40',
                  'rounded-sm hover:text-primary disabled:pointer-events-none disabled:opacity-50',
                )}
              >
                <span className="min-w-0 truncate">{item.title}</span>
                <ChevronDown
                  className={cn(
                    'h-4 w-4 shrink-0 text-muted transition-transform duration-normal',
                    isOpen && 'rotate-180',
                  )}
                  aria-hidden
                />
              </button>
            </h3>
            <div
              id={panelId}
              role="region"
              aria-labelledby={headerId}
              className={cn(
                'grid transition-[grid-template-rows] duration-accordion',
                isOpen ? 'grid-rows-[1fr]' : 'grid-rows-[0fr]',
              )}
            >
              <div className="overflow-hidden">
                <div className="px-1 pb-3 pt-0 text-sm text-muted">{item.content}</div>
              </div>
            </div>
          </div>
        )
      })}
    </div>
  )
}

/* -------------------------------------------------------------------------- */
/* Badge                                                                      */
/* -------------------------------------------------------------------------- */

const badgeVariants = cva(
  'inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium',
  {
    variants: {
      variant: {
        default: 'bg-elevated text-muted',
        // --success, not --primary: a succeeded operation and the brand
        // accent are different things and the badge should read as one or the
        // other, not both.
        success: 'bg-success-soft text-success',
        danger: 'bg-danger-soft text-danger',
        warning: 'bg-warning-soft text-warning',
        info: 'bg-info-soft text-info',
        muted: 'bg-elevated text-faint',
      },
    },
    defaultVariants: { variant: 'default' },
  },
)

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps): JSX.Element {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />
}

/* -------------------------------------------------------------------------- */
/* Dialog                                                                     */
/* -------------------------------------------------------------------------- */

export const Dialog = DialogPrimitive.Root
export const DialogTrigger = DialogPrimitive.Trigger
export const DialogClose = DialogPrimitive.Close

export function DialogContent({
  className,
  children,
  ...props
}: React.ComponentPropsWithoutRef<typeof DialogPrimitive.Content>): JSX.Element {
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm data-[state=open]:animate-fade-in duration-fast" />
      <DialogPrimitive.Content
        className={cn(
          'fixed left-1/2 top-1/2 z-50 w-[calc(100vw-2rem)] max-w-lg -translate-x-1/2 -translate-y-1/2',
          'rounded-lg border border-border bg-surface p-5 shadow-2xl',
          'data-[state=open]:animate-slide-up',
          className,
        )}
        {...props}
      >
        {children}
        <DialogPrimitive.Close
          className="absolute right-3 top-3 rounded p-1 text-muted transition-colors hover:bg-elevated hover:text-fg focus:outline-none"
          aria-label="Close"
        >
          <X className="h-4 w-4" />
        </DialogPrimitive.Close>
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  )
}

export function DialogHeader({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>): JSX.Element {
  return <div className={cn('mb-4 space-y-1', className)} {...props} />
}

export function DialogTitle({
  className,
  ...props
}: React.ComponentPropsWithoutRef<typeof DialogPrimitive.Title>): JSX.Element {
  return (
    <DialogPrimitive.Title
      className={cn('text-base font-semibold text-fg', className)}
      {...props}
    />
  )
}

export function DialogDescription({
  className,
  ...props
}: React.ComponentPropsWithoutRef<typeof DialogPrimitive.Description>): JSX.Element {
  return (
    <DialogPrimitive.Description className={cn('text-sm text-muted', className)} {...props} />
  )
}

export function DialogFooter({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>): JSX.Element {
  return (
    <div className={cn('mt-5 flex justify-end gap-2', className)} {...props} />
  )
}

/* -------------------------------------------------------------------------- */
/* AlertDialog (destructive confirmation)                                     */
/* -------------------------------------------------------------------------- */

export const AlertDialog = AlertDialogPrimitive.Root
export const AlertDialogTrigger = AlertDialogPrimitive.Trigger

export function AlertDialogContent({
  className,
  children,
  ...props
}: React.ComponentPropsWithoutRef<typeof AlertDialogPrimitive.Content>): JSX.Element {
  return (
    <AlertDialogPrimitive.Portal>
      <AlertDialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm data-[state=open]:animate-fade-in duration-fast" />
      <AlertDialogPrimitive.Content
        className={cn(
          'fixed left-1/2 top-1/2 z-50 w-[calc(100vw-2rem)] max-w-md -translate-x-1/2 -translate-y-1/2',
          'rounded-lg border border-border bg-surface p-5 shadow-2xl data-[state=open]:animate-slide-up',
          className,
        )}
        {...props}
      >
        {children}
      </AlertDialogPrimitive.Content>
    </AlertDialogPrimitive.Portal>
  )
}

export function AlertDialogTitle({
  className,
  ...props
}: React.ComponentPropsWithoutRef<typeof AlertDialogPrimitive.Title>): JSX.Element {
  return (
    <AlertDialogPrimitive.Title className={cn('text-base font-semibold', className)} {...props} />
  )
}

export function AlertDialogDescription({
  className,
  ...props
}: React.ComponentPropsWithoutRef<typeof AlertDialogPrimitive.Description>): JSX.Element {
  return (
    <AlertDialogPrimitive.Description className={cn('text-sm text-muted', className)} {...props} />
  )
}

export function AlertDialogFooter({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>): JSX.Element {
  return <div className={cn('mt-5 flex justify-end gap-2', className)} {...props} />
}

export const AlertDialogCancel = AlertDialogPrimitive.Cancel
export const AlertDialogAction = AlertDialogPrimitive.Action

/* -------------------------------------------------------------------------- */
/* Switch (green when on)                                                     */
/* -------------------------------------------------------------------------- */

export function Switch({
  className,
  ...props
}: React.ComponentPropsWithoutRef<typeof SwitchPrimitive.Root>): JSX.Element {
  return (
    <SwitchPrimitive.Root
      className={cn(
        'peer inline-flex h-5 w-9 shrink-0 cursor-pointer items-center rounded-full',
        'border-2 border-transparent transition-colors',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40',
        'disabled:cursor-not-allowed disabled:opacity-50',
        // The thumb is the inverse of the track, so "on" reads as a solid
        // green pill with a white dot in both themes.
        'data-[state=checked]:bg-primary data-[state=unchecked]:bg-border',
        className,
      )}
      {...props}
    >
      <SwitchPrimitive.Thumb className="pointer-events-none block h-4 w-4 rounded-full bg-white shadow transition-transform data-[state=checked]:translate-x-4 data-[state=unchecked]:translate-x-0" />
    </SwitchPrimitive.Root>
  )
}

/* -------------------------------------------------------------------------- */
/* Select                                                                     */
/* -------------------------------------------------------------------------- */

export const Select = SelectPrimitive.Root
export const SelectValue = SelectPrimitive.Value

export function SelectTrigger({
  className,
  children,
  ...props
}: React.ComponentPropsWithoutRef<typeof SelectPrimitive.Trigger>): JSX.Element {
  return (
    <SelectPrimitive.Trigger
      className={cn(
        'flex h-9 w-full items-center justify-between gap-2 rounded-md border border-input bg-bg px-3 py-2',
        'text-sm text-fg outline-none transition-colors',
        'focus:border-primary focus:ring-2 focus:ring-primary/25',
        'disabled:cursor-not-allowed disabled:opacity-50',
        '[&>span]:truncate',
        className,
      )}
      {...props}
    >
      {children}
      <SelectPrimitive.Icon asChild>
        <ChevronDown className="h-4 w-4 shrink-0 text-muted" />
      </SelectPrimitive.Icon>
    </SelectPrimitive.Trigger>
  )
}

export function SelectContent({
  className,
  children,
  position = 'popper',
  ...props
}: React.ComponentPropsWithoutRef<typeof SelectPrimitive.Content>): JSX.Element {
  return (
    <SelectPrimitive.Portal>
      <SelectPrimitive.Content
        position={position}
        className={cn(
          'relative z-50 max-h-72 min-w-[8rem] overflow-hidden rounded-md border border-border',
          'bg-surface text-fg shadow-lg data-[state=open]:animate-fade-in duration-fast',
          position === 'popper' && 'data-[side=bottom]:translate-y-1 data-[side=top]:-translate-y-1',
          className,
        )}
        {...props}
      >
        <SelectPrimitive.Viewport
          className={cn(
            'p-1',
            position === 'popper' && 'w-full min-w-[var(--radix-select-trigger-width)]',
          )}
        >
          {children}
        </SelectPrimitive.Viewport>
      </SelectPrimitive.Content>
    </SelectPrimitive.Portal>
  )
}

export function SelectItem({
  className,
  children,
  ...props
}: React.ComponentPropsWithoutRef<typeof SelectPrimitive.Item>): JSX.Element {
  return (
    <SelectPrimitive.Item
      className={cn(
        'relative flex w-full cursor-pointer select-none items-center rounded-sm py-1.5 pl-8 pr-2 text-sm',
        'outline-none data-[highlighted]:bg-elevated data-[state=checked]:text-primary',
        'data-[disabled]:pointer-events-none data-[disabled]:opacity-50',
        className,
      )}
      {...props}
    >
      <span className="absolute left-2 flex h-3.5 w-3.5 items-center justify-center">
        <SelectPrimitive.ItemIndicator>
          <Check className="h-4 w-4" />
        </SelectPrimitive.ItemIndicator>
      </span>
      <SelectPrimitive.ItemText>{children}</SelectPrimitive.ItemText>
    </SelectPrimitive.Item>
  )
}

/* -------------------------------------------------------------------------- */
/* Tooltip                                                                    */
/* -------------------------------------------------------------------------- */

export function TooltipProvider({
  delayDuration = 200,
  ...props
}: React.ComponentProps<typeof TooltipPrimitive.Provider>): JSX.Element {
  return <TooltipPrimitive.Provider delayDuration={delayDuration} {...props} />
}

export function Tooltip({
  ...props
}: React.ComponentPropsWithoutRef<typeof TooltipPrimitive.Root>): JSX.Element {
  return <TooltipPrimitive.Root {...props} />
}

export function TooltipTrigger({
  ...props
}: React.ComponentPropsWithoutRef<typeof TooltipPrimitive.Trigger>): JSX.Element {
  return <TooltipPrimitive.Trigger {...props} />
}

export function TooltipContent({
  className,
  sideOffset = 6,
  ...props
}: React.ComponentPropsWithoutRef<typeof TooltipPrimitive.Content>): JSX.Element {
  return (
    <TooltipPrimitive.Portal>
      <TooltipPrimitive.Content
        sideOffset={sideOffset}
        className={cn(
          'z-50 max-w-xs rounded-md border border-border bg-elevated px-2.5 py-1.5',
          'text-xs text-fg shadow-lg animate-fade-in',
          className,
        )}
        {...props}
      />
    </TooltipPrimitive.Portal>
  )
}

/* -------------------------------------------------------------------------- */
/* Form primitives                                                            */
/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
/* Checkbox                                                                   */
/* -------------------------------------------------------------------------- */

export interface CheckboxProps
  extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'type' | 'size'> {
  indeterminate?: boolean
  /**
   * Radix-shaped callback: receives the new checked state.
   *
   * A native input only offers onChange, which receives an event and reads as
   * `event.target.checked`. Accepting this too means a call site can move
   * between a real Radix checkbox and this one without changing shape, which
   * matters because the rest of the component set is Radix.
   */
  onCheckedChange?: (checked: boolean) => void
}

/**
 * Checkbox, visually replaced but semantically a real <input type="checkbox">.
 *
 * Kept as an input rather than a div with role="checkbox" so it participates in
 * forms and screen readers announce it as a checkbox without extra ARIA.
 * `indeterminate` is set through the DOM property, which React has no attribute
 * for, and re-applied in an effect because a re-render resets it.
 */
export const Checkbox = React.forwardRef<HTMLInputElement, CheckboxProps>(
  ({ className, indeterminate = false, onCheckedChange, onChange, ...props }, ref) => {
    const inner = React.useRef<HTMLInputElement | null>(null)

    React.useEffect(() => {
      if (inner.current) inner.current.indeterminate = indeterminate
    }, [indeterminate])

    function handleChange(event: React.ChangeEvent<HTMLInputElement>): void {
      onChange?.(event)
      onCheckedChange?.(event.target.checked)
    }

    return (
      <span className={cn('relative inline-flex h-4 w-4 shrink-0', className)}>
        <input
          ref={(node) => {
            inner.current = node
            if (typeof ref === 'function') ref(node)
            else if (ref) ref.current = node
          }}
          type="checkbox"
          aria-checked={indeterminate ? 'mixed' : undefined}
          className={cn(
            'peer h-4 w-4 cursor-pointer appearance-none rounded border border-input bg-bg',
            'transition-colors',
            'checked:border-primary checked:bg-primary',
            'indeterminate:border-primary indeterminate:bg-primary',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40',
            'disabled:cursor-not-allowed disabled:opacity-50',
            // The tick is a rotated border, so no SVG and no icon import here.
            'checked:after:absolute checked:after:left-[5px] checked:after:top-[1px]',
            'checked:after:h-2 checked:after:w-1 checked:after:rotate-45',
            'checked:after:border-b-2 checked:after:border-r-2 checked:after:border-primary-fg',
            'indeterminate:after:absolute indeterminate:after:left-[3px] indeterminate:after:top-[7px]',
            'indeterminate:after:h-0.5 indeterminate:after:w-2 indeterminate:after:bg-primary-fg',
          )}
          onChange={handleChange}
          {...props}
        />
      </span>
    )
  },
)
Checkbox.displayName = 'Checkbox'

export function Label({
  className,
  ...props
}: React.LabelHTMLAttributes<HTMLLabelElement>): JSX.Element {
  return <label className={cn('label', className)} {...props} />
}

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, type = 'text', ...props }, ref) => (
    <input ref={ref} type={type} className={cn('input', className)} {...props} />
  ),
)
Input.displayName = 'Input'

export function FieldError({ children }: { children?: string }): JSX.Element | null {
  if (!children) return null
  return <p className="mt-1 text-xs text-danger">{children}</p>
}