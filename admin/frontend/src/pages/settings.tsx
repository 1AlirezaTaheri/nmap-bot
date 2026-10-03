import * as React from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Clock, Globe, RotateCcw, Save, ShieldCheck } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import { toast } from 'sonner'
import { api, type SettingInfo, type SettingsResponse } from '@/lib/api'
import { cn } from '@/lib/utils'
import { Badge, Button, Card, CardContent, CardHeader, CardTitle, Input } from '@/components/ui'
import { ErrorState, Skeleton } from '@/components/feedback'

interface Section {
  id: string
  title: string
  icon: React.ComponentType<{ className?: string }>
  keys: string[]
}

const SECTIONS: Section[] = [
  { id: 'bot', title: 'Bot', icon: Globe, keys: ['bot_language', 'default_profile', 'export_max_scans'] },
  { id: 'security', title: 'Security', icon: ShieldCheck, keys: ['allowed_cidrs'] },
  { id: 'retention', title: 'Retention', icon: Clock, keys: ['retention_days', 'retention_max_scans_per_target'] },
  {
    id: 'scheduling',
    title: 'Scheduling',
    icon: AlertTriangle,
    keys: ['schedule_enabled', 'schedule_interval_hours', 'schedule_profile'],
  },
  { id: 'scanning', title: 'Scanning', icon: Save, keys: ['scan_timeout_seconds', 'max_concurrent_scans', 'rate_limit_seconds'] },
]

const CHOICES: Record<string, Array<{ value: string; label: string }>> = {
  bot_language: [
    { value: 'fa', label: 'فارسی (Persian)' },
    { value: 'en', label: 'English' },
  ],
  default_profile: [
    { value: 'quick', label: 'quick — top 100 ports' },
    { value: 'service', label: 'service — top 100 + versions' },
    { value: 'deep', label: 'deep — top 1000 ports' },
  ],
  schedule_profile: [
    { value: 'quick', label: 'quick' },
    { value: 'service', label: 'service' },
    { value: 'deep', label: 'deep' },
  ],
}

/** Preview of the greeting a bot user would see in the selected language. */
function LanguagePreview({ lang }: { lang: string }): JSX.Element {
  const sample =
    lang === 'en'
      ? 'Hello! I am NetSentinel — your network security monitoring assistant.'
      : 'سلام! من NetSentinel هستم — دستیار پایش امنیت شبکه.'
  return (
    <div className="mt-3 rounded-md border border-border bg-bg p-3">
      <p className="mb-1.5 text-[11px] font-medium uppercase tracking-wide text-muted">
        Bot preview — {lang.toUpperCase()}
      </p>
      <p className="whitespace-pre-line text-sm text-fg">{sample}</p>
    </div>
  )
}

function SettingRow({
  name,
  info,
  value,
  dirty,
  onChange,
  onReset,
}: {
  name: string
  info: SettingInfo
  value: string
  dirty: boolean
  onChange: (value: string) => void
  onReset: () => void
}): JSX.Element {
  const choices = CHOICES[name]
  const isBool = info.kind === 'bool'
  const isInt = typeof info.kind === 'string' && info.kind.startsWith('int:')

  return (
    <div className={cn('border-b border-border py-3.5 last:border-0', dirty && 'bg-primary-soft/20 -mx-3 px-3 rounded-md')}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <label htmlFor={name} className="font-mono text-sm font-medium text-fg">
              {name}
            </label>
            {dirty ? <Badge variant="info">modified</Badge> : null}
          </div>
          <p className="mt-0.5 text-xs text-muted">{info.description}</p>
          <p className="mt-1 text-[11px] text-faint">
            default: <span className="font-mono">{String(info.default)}</span>
            {info.updated_by ? (
              <>
                {' · '}last changed by <span className="font-mono">{info.updated_by}</span>
                {info.updated_at
                  ? ` ${formatDistanceToNow(new Date(info.updated_at), { addSuffix: true })}`
                  : ''}
              </>
            ) : null}
          </p>
        </div>

        <div className="flex shrink-0 items-center gap-2">
          {choices ? (
            <select
              id={name}
              className="input h-8 w-44 text-xs"
              value={value}
              onChange={(event) => onChange(event.target.value)}
            >
              {choices.map((choice) => (
                <option key={choice.value} value={choice.value}>
                  {choice.label}
                </option>
              ))}
            </select>
          ) : isBool ? (
            <select
              id={name}
              className="input h-8 w-24 text-xs"
              value={value}
              onChange={(event) => onChange(event.target.value)}
            >
              <option value="true">true</option>
              <option value="false">false</option>
            </select>
          ) : (
            <Input
              id={name}
              type={isInt ? 'number' : 'text'}
              className="h-8 w-44 text-xs"
              value={value}
              onChange={(event) => onChange(event.target.value)}
            />
          )}
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8 text-muted hover:text-primary"
            aria-label={`Reset ${name}`}
            title="Reset to default"
            onClick={onReset}
            disabled={!dirty}
          >
            <RotateCcw className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>

      {name === 'bot_language' ? <LanguagePreview lang={value} /> : null}
    </div>
  )
}

export function SettingsPage(): JSX.Element {
  const queryClient = useQueryClient()
  const [draft, setDraft] = React.useState<Record<string, string>>({})

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['settings'],
    queryFn: ({ signal }) => api.getSettings(signal),
  })

  const save = useMutation({
    mutationFn: (values: Record<string, string>) => api.patchSettings(values),
    onSuccess: () => {
      toast.success('Settings saved', {
        description: 'The bot picks these up without a restart.',
      })
      setDraft({})
      void queryClient.invalidateQueries({ queryKey: ['settings'] })
    },
    onError: (error) => toast.error(error instanceof Error ? error.message : 'Save failed'),
  })

  const settings: SettingsResponse = data?.settings ?? {}

  const dirtyKeys = Object.keys(draft).filter(
    (key) => settings[key] && String(settings[key].value) !== draft[key],
  )

  function setValue(key: string, value: string): void {
    setDraft((prev) => ({ ...prev, [key]: value }))
  }

  function reset(key: string): void {
    const info = settings[key]
    if (!info) return
    setDraft((prev) => {
      const next = { ...prev }
      delete next[key]
      return next
    })
  }

  if (isError) {
    return <ErrorState description="Could not load settings." onRetry={() => void refetch()} />
  }

  return (
    <div className="space-y-4 pb-20">
      {isLoading ? (
        <Card className="space-y-3 p-5">
          {Array.from({ length: 8 }).map((_, i) => (
            <Skeleton key={i} className="h-14" />
          ))}
        </Card>
      ) : (
        SECTIONS.map((section) => (
          <Card key={section.id}>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <section.icon className="h-4 w-4 text-primary" />
                {section.title}
              </CardTitle>
            </CardHeader>
            <CardContent className="pt-0">
              {section.keys
                .filter((key) => settings[key])
                .map((key) => {
                  const info = settings[key]
                  if (!info) return null
                  const current = draft[key] ?? String(info.value)
                  const dirty = current !== String(info.value)
                  return (
                    <SettingRow
                      key={key}
                      name={key}
                      info={info}
                      value={current}
                      dirty={dirty}
                      onChange={(value) => setValue(key, value)}
                      onReset={() => reset(key)}
                    />
                  )
                })}
            </CardContent>
          </Card>
        ))
      )}

      {/* Sticky save bar so unsaved edits are always visible. */}
      {dirtyKeys.length > 0 ? (
        <div className="fixed bottom-0 left-0 right-0 z-30 border-t border-border bg-surface/95 backdrop-blur">
          <div className="mx-auto flex max-w-7xl items-center justify-between gap-3 px-4 py-3 md:px-6">
            <p className="text-sm text-muted">
              <span className="font-medium text-primary">{dirtyKeys.length}</span> unsaved change
              {dirtyKeys.length === 1 ? '' : 's'}:{' '}
              <span className="font-mono text-xs text-fg">{dirtyKeys.join(', ')}</span>
            </p>
            <div className="flex gap-2">
              <Button variant="ghost" size="sm" onClick={() => setDraft({})}>
                Discard
              </Button>
              <Button size="sm" onClick={() => save.mutate(Object.fromEntries(dirtyKeys.map((k) => [k, draft[k] ?? String(settings[k]?.value ?? '')])))} disabled={save.isPending}>
                {save.isPending ? 'Saving…' : 'Save changes'}
              </Button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  )
}