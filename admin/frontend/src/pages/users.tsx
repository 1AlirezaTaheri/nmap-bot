import * as React from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { formatDistanceToNow } from 'date-fns'
import { Copy, Search, Trash2, UserPlus } from 'lucide-react'
import { toast } from 'sonner'
import { z } from 'zod'
import { api, type TelegramUser, type TelegramRole, type Language } from '@/lib/api'
import { avatarColor, cn, formatNumber, initials } from '@/lib/utils'
import {
  Badge,
  Button,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Input,
  Label,
  FieldError,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Switch,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui'
import { Spinner } from '@/components/feedback'
import { DataTable, Pagination, type Column, type SortDirection } from '@/components/data-table'

const ROLES: TelegramRole[] = ['viewer', 'operator', 'admin']

type Filter = 'all' | 'enabled' | 'disabled' | 'admins' | 'operators'

const FILTERS: Array<{ key: Filter; label: string }> = [
  { key: 'all', label: 'All' },
  { key: 'enabled', label: 'Enabled' },
  { key: 'disabled', label: 'Disabled' },
  { key: 'admins', label: 'Admins' },
  { key: 'operators', label: 'Operators' },
]

const PAGE_SIZE = 15

function Avatar({ user }: { user: TelegramUser }): JSX.Element {
  return (
    <span
      className={cn(
        'flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-xs font-semibold',
        avatarColor(user.telegram_user_id),
      )}
      aria-hidden
    >
      {initials(user.username ?? String(user.telegram_user_id))}
    </span>
  )
}

function CopyableId({ id }: { id: number }): JSX.Element {
  const [copied, setCopied] = React.useState(false)
  return (
    <button
      className="group inline-flex items-center gap-1.5 font-mono text-xs text-muted transition-colors hover:text-fg"
      onClick={() => {
        void navigator.clipboard.writeText(String(id)).then(() => {
          setCopied(true)
          window.setTimeout(() => setCopied(false), 1200)
        })
      }}
      title="Copy Telegram ID"
    >
      {id}
      <Copy className={cn('h-3 w-3', copied ? 'text-primary' : 'opacity-0 group-hover:opacity-60')} />
    </button>
  )
}

const schema = z.object({
  telegram_user_id: z
    .string()
    .min(1, 'Required')
    .refine((v) => /^\d+$/.test(v), 'Must be numeric')
    .refine((v) => Number(v) > 0, 'Must be positive'),
  username: z.string().max(64).optional(),
  role: z.enum(['viewer', 'operator', 'admin']),
})

/** Raw form state: the Telegram ID is a string until it is validated. */
type FormValues = z.infer<typeof schema>

/** Validated payload sent to the API, with the ID coerced to a number. */
interface NewUserPayload {
  telegram_user_id: number
  username?: string
  role: TelegramRole
}

export function UsersPage(): JSX.Element {
  const queryClient = useQueryClient()
  const [search, setSearch] = React.useState('')
  const [debounced, setDebounced] = React.useState('')
  const [filter, setFilter] = React.useState<Filter>('all')
  const [page, setPage] = React.useState(1)
  const [sortKey, setSortKey] = React.useState<string | null>('last_seen_at')
  const [sortDirection, setSortDirection] = React.useState<SortDirection>('desc')
  const [addOpen, setAddOpen] = React.useState(false)

  // Debounce so typing does not fire a request per keystroke.
  React.useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(search.trim()), 250)
    return () => window.clearTimeout(timer)
  }, [search])

  React.useEffect(() => {
    setPage(1)
  }, [debounced, filter])

  const { data, isLoading } = useQuery({
    queryKey: ['users'],
    queryFn: ({ signal }) => api.listUsers(signal),
  })

  const patch = useMutation({
    mutationFn: ({ id, body }: { id: number; body: Parameters<typeof api.patchUser>[1] }) =>
      api.patchUser(id, body),
    // Optimistic: reflect the change immediately, roll back on failure.
    onMutate: async ({ id, body }) => {
      await queryClient.cancelQueries({ queryKey: ['users'] })
      const previous = queryClient.getQueryData<{ users: TelegramUser[] }>(['users'])
      queryClient.setQueryData<{ users: TelegramUser[] }>(['users'], (old) =>
        old
          ? { users: old.users.map((u) => (u.telegram_user_id === id ? { ...u, ...body } : u)) }
          : old,
      )
      return { previous }
    },
    onError: (error, _variables, context) => {
      if (context?.previous) queryClient.setQueryData(['users'], context.previous)
      toast.error(error instanceof Error ? error.message : 'Update failed')
    },
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: ['users'] })
    },
  })

  const remove = useMutation({
    mutationFn: (id: number) => api.deleteUser(id),
    onSuccess: () => {
      toast.success('User removed')
      void queryClient.invalidateQueries({ queryKey: ['users'] })
    },
    onError: (error) => toast.error(error instanceof Error ? error.message : 'Delete failed'),
  })

  const create = useMutation({
    mutationFn: api.addUser,
    onSuccess: () => {
      toast.success('User added')
      setAddOpen(false)
      void queryClient.invalidateQueries({ queryKey: ['users'] })
    },
    onError: (error) => toast.error(error instanceof Error ? error.message : 'Could not add user'),
  })

  const all = data?.users ?? []

  const filtered = React.useMemo(() => {
    const needle = debounced.toLowerCase()
    return all.filter((user) => {
      if (needle) {
        const haystack = `${user.telegram_user_id} ${user.username ?? ''}`.toLowerCase()
        if (!haystack.includes(needle)) return false
      }
      if (filter === 'enabled') return user.enabled
      if (filter === 'disabled') return !user.enabled
      if (filter === 'admins') return user.role === 'admin'
      if (filter === 'operators') return user.role === 'operator'
      return true
    })
  }, [all, debounced, filter])

  const pageRows = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)

  const columns: Column<TelegramUser>[] = [
    {
      key: 'user',
      header: 'User',
      sortable: true,
      sortValue: (u) => u.username ?? u.telegram_user_id,
      cell: (u) => (
        <div className="flex items-center gap-3">
          <Avatar user={u} />
          <div className="min-w-0">
            <p className="truncate text-sm font-medium text-fg">{u.username ?? '—'}</p>
            <CopyableId id={u.telegram_user_id} />
          </div>
        </div>
      ),
    },
    {
      key: 'role',
      header: 'Role',
      sortable: true,
      sortValue: (u) => u.role,
      cell: (u) => (
        <Select
          value={u.role}
          onValueChange={(value) => patch.mutate({ id: u.telegram_user_id, body: { role: value as TelegramRole } })}
          disabled={patch.isPending}
        >
          <SelectTrigger className="h-8 w-32 text-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {ROLES.map((role) => (
              <SelectItem key={role} value={role} className="text-xs">
                {role}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      ),
    },
    {
      key: 'language',
      header: 'Language',
      sortable: true,
      sortValue: (u) => u.language,
      cell: (u) => (
        <Select
          value={u.language}
          onValueChange={(value) => patch.mutate({ id: u.telegram_user_id, body: { language: value as Language } })}
          disabled={patch.isPending}
        >
          <SelectTrigger className="h-8 w-24 text-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="fa" className="text-xs">🇮🇷 فارسی</SelectItem>
            <SelectItem value="en" className="text-xs">🇬🇧 English</SelectItem>
          </SelectContent>
        </Select>
      ),
    },
    {
      key: 'enabled',
      header: 'Enabled',
      cell: (u) => (
        <div className="flex items-center gap-2">
          <Switch
            checked={u.enabled}
            onCheckedChange={(checked) => patch.mutate({ id: u.telegram_user_id, body: { enabled: checked } })}
            aria-label={`Toggle ${u.username ?? u.telegram_user_id}`}
          />
          <Badge variant={u.enabled ? 'success' : 'muted'}>{u.enabled ? 'on' : 'off'}</Badge>
        </div>
      ),
    },
    {
      key: 'scans',
      header: 'Scans',
      sortable: true,
      sortValue: (u) => u.scan_count,
      className: 'text-right tabular-nums text-fg',
      cell: (u) => formatNumber(u.scan_count),
    },
    {
      key: 'last_seen',
      header: 'Last seen',
      sortable: true,
      sortValue: (u) => u.last_seen_at ?? '',
      cell: (u) =>
        u.last_seen_at ? (
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="cursor-default text-xs text-muted">
                {formatDistanceToNow(new Date(u.last_seen_at), { addSuffix: true })}
              </span>
            </TooltipTrigger>
            <TooltipContent>{new Date(u.last_seen_at).toLocaleString()}</TooltipContent>
          </Tooltip>
        ) : (
          <span className="text-xs text-faint">never</span>
        ),
    },
    {
      key: 'actions',
      header: '',
      className: 'text-right',
      cell: (u) => (
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8 text-muted hover:text-danger"
          aria-label="Remove user"
          onClick={() => {
            if (window.confirm(`Remove ${u.username ?? u.telegram_user_id}?`)) {
              remove.mutate(u.telegram_user_id)
            }
          }}
        >
          <Trash2 className="h-4 w-4" />
        </Button>
      ),
    },
  ]

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-56 flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
          <Input
            className="pl-9"
            placeholder="Search by ID or username…"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
        </div>
        <Button onClick={() => setAddOpen(true)}>
          <UserPlus className="h-4 w-4" />
          Add user
        </Button>
      </div>

      <div className="flex flex-wrap gap-1.5">
        {FILTERS.map((chip) => (
          <button
            key={chip.key}
            onClick={() => setFilter(chip.key)}
            className={cn(
              'rounded-full px-3 py-1 text-xs font-medium transition-colors',
              filter === chip.key
                ? 'bg-primary text-primary-fg'
                : 'bg-elevated text-muted hover:text-fg',
            )}
          >
            {chip.label}
            {chip.key === 'all' ? ` (${all.length})` : ''}
          </button>
        ))}
      </div>

      <DataTable
        columns={columns}
        rows={pageRows}
        rowKey={(u) => u.telegram_user_id}
        loading={isLoading}
        emptyTitle={all.length === 0 ? 'No users yet' : 'No users match'}
        emptyDescription={
          all.length === 0
            ? 'Add one here, or have an allowed user send /start in Telegram.'
            : 'Try a different search or filter.'
        }
        sortKey={sortKey}
        sortDirection={sortDirection}
        onSortChange={(key) => {
          if (key === sortKey) {
            setSortDirection((d) => (d === 'asc' ? 'desc' : 'asc'))
          } else {
            setSortKey(key)
            setSortDirection('asc')
          }
        }}
      />

      <Pagination
        page={page}
        pageSize={PAGE_SIZE}
        total={filtered.length}
        onPageChange={setPage}
      />

      <AddUserDialog
        open={addOpen}
        onOpenChange={setAddOpen}
        pending={create.isPending}
        onSubmit={(payload) => create.mutate(payload)}
      />
    </div>
  )
}

function AddUserDialog({
  open,
  onOpenChange,
  pending,
  onSubmit,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  pending: boolean
  onSubmit: (payload: NewUserPayload) => void
}): JSX.Element {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: { telegram_user_id: '', username: '', role: 'operator' },
  })

  React.useEffect(() => {
    if (!open) reset()
  }, [open, reset])

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add Telegram user</DialogTitle>
          <DialogDescription>
            This grants a role and preferences. Access itself still comes from the bot&apos;s
            ALLOWED_USER_IDS allow-list.
          </DialogDescription>
        </DialogHeader>

        <form
          className="space-y-4"
          onSubmit={(event) => {
            void handleSubmit((values) => onSubmit({
              telegram_user_id: Number(values.telegram_user_id),
              ...(values.username ? { username: values.username } : {}),
              role: values.role as TelegramRole,
            }))(event)
          }}
          noValidate
        >
          <div>
            <Label htmlFor="new-id">Telegram ID</Label>
            <Input
              id="new-id"
              inputMode="numeric"
              placeholder="7575983824"
              {...register('telegram_user_id')}
            />
            <FieldError>{errors.telegram_user_id?.message}</FieldError>
          </div>

          <div>
            <Label htmlFor="new-username">Username (optional)</Label>
            <Input id="new-username" placeholder="alice" {...register('username')} />
            <FieldError>{errors.username?.message}</FieldError>
          </div>

          <div>
            <Label>Role</Label>
            <Select defaultValue="operator" {...register('role')}>
              <SelectTrigger>
                <SelectValue placeholder="operator" />
              </SelectTrigger>
              <SelectContent>
                {ROLES.map((role) => (
                  <SelectItem key={role} value={role}>
                    {role}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <FieldError>{errors.role?.message}</FieldError>
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={pending}>
              {pending ? <Spinner /> : null}
              Add user
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}