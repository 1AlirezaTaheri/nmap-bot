import * as React from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { FlaskConical } from 'lucide-react'
import { api, type Rule } from '@/lib/api'
import { haptic, toast } from '@/lib/telegram'
import { cn, relative } from '@/lib/utils'
import {
  Badge,
  EmptyState,
  ErrorState,
  Fab,
  Sheet,
  Skeleton,
} from '@/components/ui'

/**
 * An example value per rule type.
 *
 * Shown in the test sheet, where the operator has to type a target but not a
 * value: without a worked example the rule types read as opaque identifiers.
 */
const VALUE_EXAMPLES: ReadonlyArray<{ type: string; example: string }> = [
  { type: 'allow_cidr', example: '192.168.1.0/24' },
  { type: 'deny_cidr', example: '169.254.169.254/32' },
  { type: 'allow_port', example: '22,80,8000-9000' },
  { type: 'rate_limit', example: '60' },
  { type: 'max_scan_time', example: '120' },
  { type: 'time_window', example: '08:00-22:00 (UTC)' },
]

export function RulesPage(): JSX.Element {
  const queryClient = useQueryClient()
  const [detail, setDetail] = React.useState<Rule | null>(null)
  const [testing, setTesting] = React.useState(false)

  const rules = useQuery({
    queryKey: ['rules'],
    queryFn: ({ signal }) => api.rules(signal),
  })

  if (rules.isError) {
    return (
      <ErrorState
        message={(rules.error as Error).message}
        onRetry={() => void rules.refetch()}
      />
    )
  }

  const rows = rules.data?.rules ?? []

  return (
    <div className="space-y-3">
      <button className="btn-quiet w-full" onClick={() => setTesting(true)}>
        <FlaskConical className="h-4 w-4" />
        Test the rule set
      </button>

      <p className="text-[12px] text-hint">
        Rules are edited in the web panel for now. This tab is read-only, and
        the test sheet below is a dry run: it decides nothing and records
        nothing.
      </p>

      {rules.isLoading ? (
        <div className="space-y-2">
          <Skeleton className="h-16" />
          <Skeleton className="h-16" />
        </div>
      ) : rows.length === 0 ? (
        <EmptyState
          icon="🛡"
          title="No rules"
          description="Without rules every allowed target is scanned, at the rate limit in settings."
        />
      ) : (
        <ul className="space-y-2">
          {rows.map((rule) => (
            <li key={rule.id}>
              <button
                className="card w-full text-left active:opacity-70"
                onClick={() => {
                  haptic()
                  setDetail(rule)
                }}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0 flex-1">
                    <div className="mb-1 flex items-center gap-1.5">
                      <Badge
                        className={
                          rule.enabled ? 'bg-good-soft text-good' : 'bg-secondary text-hint'
                        }
                      >
                        {rule.rule_type}
                      </Badge>
                      {!rule.enabled ? (
                        <Badge className="bg-warn-soft text-warn">disabled</Badge>
                      ) : null}
                    </div>
                    <p className="truncate text-[15px] font-semibold">{rule.name}</p>
                    <p className="truncate font-mono text-[12px] text-hint">
                      {rule.value}
                    </p>
                  </div>
                  <span className="shrink-0 text-[12px] tabular-nums text-hint">
                    #{rule.priority}
                  </span>
                </div>
                <div className="mt-1.5 flex items-center gap-2 text-[12px] text-hint">
                  <span>{rule.hit_count} hits</span>
                  {rule.last_hit_at ? (
                    <span>· {relative(rule.last_hit_at)}</span>
                  ) : null}
                  {rule.scope !== 'global' ? (
                    <span>
                      · {rule.scope}
                      {rule.scope_id ? ` ${rule.scope_id}` : ''}
                    </span>
                  ) : null}
                </div>
              </button>
            </li>
          ))}
        </ul>
      )}

      <Fab
        label="Add rule"
        onClick={() =>
          toast('Rules are created in the web panel for now')
        }
      />

      {detail ? (
        <RuleSheet rule={detail} onClose={() => setDetail(null)} />
      ) : null}

      <TestSheet
        open={testing}
        onClose={() => setTesting(false)}
        onChanged={() => void queryClient.invalidateQueries({ queryKey: ['rules'] })}
      />
    </div>
  )
}

function RuleSheet({
  rule,
  onClose,
}: {
  rule: Rule
  onClose: () => void
}): JSX.Element {
  const hits = useQuery({
    queryKey: ['rule-hits', rule.id],
    queryFn: ({ signal }) => api.ruleHits(rule.id, 20, signal),
  })

  return (
    <Sheet open title={rule.name} onClose={onClose}>
      <div className="space-y-3">
        <dl className="space-y-2 text-[13px]">
          <Row label="Type" value={rule.rule_type} />
          <Row label="Value" value={rule.value} mono />
          <Row label="Priority" value={String(rule.priority)} />
          <Row label="Scope" value={rule.scope} />
          {rule.scope_id ? <Row label="Subject" value={rule.scope_id} /> : null}
          <Row label="Hits" value={String(rule.hit_count)} />
          <Row label="Last hit" value={relative(rule.last_hit_at)} />
        </dl>

        {rule.description ? (
          <p className="text-[13px] text-hint">{rule.description}</p>
        ) : null}

        <div className="flex items-center justify-between rounded-md bg-secondary px-3 py-2">
          <span className="text-[13px]">{rule.enabled ? 'Active' : 'Disabled'}</span>
          <Badge className={rule.enabled ? 'bg-good-soft text-good' : 'bg-warn-soft text-warn'}>
            {rule.enabled ? 'in force' : 'skipped'}
          </Badge>
        </div>

        <section>
          <h3 className="mb-2 text-[14px] font-semibold">Recent hits</h3>
          {hits.isLoading ? (
            <Skeleton className="h-14" />
          ) : (hits.data?.hits ?? []).length === 0 ? (
            <p className="text-[13px] text-hint">This rule has not fired yet.</p>
          ) : (
            <ul className="divide-y divide-hint/10">
              {(hits.data?.hits ?? []).map((hit) => (
                <li key={hit.id} className="flex items-center gap-2 py-2">
                  <Badge
                    className={
                      hit.decision === 'deny'
                        ? 'bg-bad-soft text-bad'
                        : 'bg-good-soft text-good'
                    }
                  >
                    {hit.decision}
                  </Badge>
                  <span className="min-w-0 flex-1 truncate text-[12px]">
                    {hit.target ?? '—'}
                  </span>
                  <span className="text-[11px] text-hint">
                    {relative(hit.created_at)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </Sheet>
  )
}

function Row({
  label,
  value,
  mono,
}: {
  label: string
  value: string
  mono?: boolean
}): JSX.Element {
  return (
    <div className="flex justify-between gap-3">
      <dt className="shrink-0 text-hint">{label}</dt>
      <dd className={cn('truncate text-right', mono && 'font-mono text-[12px]')}>
        {value}
      </dd>
    </div>
  )
}

function TestSheet({
  open,
  onClose,
}: {
  open: boolean
  onClose: () => void
  onChanged: () => void
}): JSX.Element {
  const [target, setTarget] = React.useState('')

  const test = useMutation({
    mutationFn: () => api.testRules({ target: target.trim() }),
    onSuccess: () => haptic(),
    onError: (error) => toast((error as Error).message),
  })

  React.useEffect(() => {
    if (open) {
      setTarget('')
      test.reset()
    }
    // `test` is a stable mutation object; re-running on its identity would
    // clear the result the user is looking at.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open])

  const result = test.data

  return (
    <Sheet
      open={open}
      title="Test the rule set"
      onClose={onClose}
      footer={
        <button
          className="btn-primary"
          disabled={!target.trim() || test.isPending}
          onClick={() => test.mutate()}
        >
          {test.isPending ? 'Deciding…' : 'Run'}
        </button>
      }
    >
      <div className="space-y-3">
        <p className="text-[13px] text-hint">
          Type a target and see exactly what the engine would decide. Nothing
          is recorded.
        </p>
        <input
          className="input font-mono"
          placeholder="192.168.1.5"
          value={target}
          onChange={(event) => setTarget(event.target.value)}
        />

        <details className="rounded-md bg-secondary px-3 py-2">
          <summary className="cursor-pointer text-[13px] text-hint">
            Rule types and an example value
          </summary>
          <dl className="mt-2 space-y-1 text-[12px]">
            {VALUE_EXAMPLES.map((item) => (
              <div key={item.type} className="flex justify-between gap-3">
                <dt className="font-mono text-hint">{item.type}</dt>
                <dd className="truncate font-mono">{item.example}</dd>
              </div>
            ))}
          </dl>
        </details>

        {result ? (
          <div className="card space-y-2">
            <Badge
              className={result.allowed ? 'bg-good-soft text-good' : 'bg-bad-soft text-bad'}
            >
              {result.allowed ? 'allowed' : 'denied'}
            </Badge>
            <p className="text-[13px]">{result.reason}</p>
            {result.rule_name ? (
              <p className="text-[12px] text-hint">by rule “{result.rule_name}”</p>
            ) : null}
            <p className="text-[12px] text-hint">
              {result.rules_considered} rule(s) considered ·{' '}
              {result.side_effects}
            </p>
            {result.warnings.length > 0 ? (
              <ul className="space-y-0.5 text-[12px] text-warn">
                {result.warnings.map((w) => (
                  <li key={w}>{w}</li>
                ))}
              </ul>
            ) : null}
          </div>
        ) : null}
      </div>
    </Sheet>
  )
}