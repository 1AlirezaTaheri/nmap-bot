import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Loader2, Radio, ScanLine } from 'lucide-react'
import { toast } from 'sonner'
import { api, ApiError } from '@/lib/api'
import { cn } from '@/lib/utils'
import { Badge, Button, type ButtonProps } from '@/components/ui'

export interface ScanButtonProps
  extends Omit<ButtonProps, 'onClick' | 'children'> {
  targetId: number
  targetName: string
  /** Poll interval for the live status while a scan is running. */
  pollMs?: number
  /** Called after a scan is successfully queued. */
  onQueued?: (jobId: number) => void
}

/**
 * Queue a scan of one target, and reflect what is already running.
 *
 * Two behaviours worth explaining:
 *
 * It polls `/scan/active` rather than tracking its own request. A scan can be
 * started from Telegram or by the scheduler, and a button that only knew about
 * its own click would happily queue a duplicate while the first one was still
 * running -- which the server would refuse anyway, but the operator would see
 * an error instead of the truth.
 *
 * The disabled state is derived from that poll, so after clicking, the button
 * becomes a live indicator rather than resetting optimistically. That also
 * means the panel reflects a scan someone else started.
 */
export function ScanButton({
  targetId,
  targetName,
  pollMs = 5_000,
  size = 'sm',
  variant = 'outline',
  className,
  onQueued,
}: ScanButtonProps): JSX.Element {
  const queryClient = useQueryClient()

  const active = useQuery({
    queryKey: ['target', targetId, 'scan', 'active'],
    queryFn: ({ signal }) => api.activeTargetScan(targetId, signal),
    // Only poll while something is plausibly running; a static target would
    // otherwise be polled forever for no change.
    refetchInterval: (query) => (query.state.data?.scan ? pollMs : false),
    refetchOnWindowFocus: true,
  })

  const start = useMutation({
    mutationFn: () => api.startScan(targetId),
    onSuccess: (result) => {
      toast.success(
        `Scan queued for ${result.target}`,
        { description: `profile ${result.profile} Â· job ${result.job_id}` },
      )
      onQueued?.(result.job_id)
      void queryClient.invalidateQueries({ queryKey: ['target', targetId] })
    },
    onError: (error) => {
      // The messages the server sends here are policy decisions, not generic
      // failures: a rule refusal, a scope refusal, a rate limit. Showing the
      // server's own text is the whole point.
      toast.error(
        error instanceof ApiError ? error.message : 'Could not start the scan.',
      )
      void queryClient.invalidateQueries({ queryKey: ['target', targetId] })
    },
  })

  const running = active.data?.scan ?? null
  const busy = running !== null
  const pending = start.isPending

  return (
    <Button
      size={size}
      variant={busy ? 'secondary' : variant}
      className={cn('gap-1.5', className)}
      disabled={busy || pending}
      onClick={() => start.mutate()}
      aria-label={
        busy
          ? `A scan of ${targetName} is already running`
          : `Scan ${targetName}`
      }
    >
      {pending ? (
        <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
      ) : busy ? (
        <Radio className="h-4 w-4 animate-pulse text-info" aria-hidden />
      ) : (
        <ScanLine className="h-4 w-4" aria-hidden />
      )}
      <span>{pending ? 'Queueingâ€¦' : busy ? 'Scanning' : 'Scan now'}</span>
      {busy ? (
        <Badge variant="info" className="ml-1">
          {running.profile}
        </Badge>
      ) : null}
    </Button>
  )
}

/**
 * A compact live indicator for lists, where a full button per row would be
 * too heavy. Reads the same active-scan query, so the two stay consistent.
 */
export function ScanStatusDot({
  targetId,
  className,
}: {
  targetId: number
  className?: string
}): JSX.Element | null {
  const { data } = useQuery({
    queryKey: ['target', targetId, 'scan', 'active'],
    queryFn: ({ signal }) => api.activeTargetScan(targetId, signal),
    refetchInterval: 10_000,
  })

  const scan = data?.scan ?? null
  if (!scan) return null

  return (
    <span
      className={cn('inline-flex items-center gap-1 text-[11px] text-info', className)}
      title={`${scan.status} Â· profile ${scan.profile}`}
    >
      <Radio className="h-3 w-3 animate-pulse" aria-hidden />
      <span className="sr-only">Scan in progress</span>
    </span>
  )
}