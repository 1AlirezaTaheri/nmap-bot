import * as React from 'react'
import { useQuery } from '@tanstack/react-query'
import { Copy, Info, Moon, Network, Sun } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useUIStore } from '@/store/ui'
import { cn, formatNumber } from '@/lib/utils'
import {
  Accordion,
  Badge,
  Button,
  Card,
  Checkbox,
  Popover,
  PopoverContent,
  PopoverTrigger,
  Tabs,
  TabsContent,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui'
import { DataTable, Pagination, type Column, type SortSpec } from '@/components/data-table'
import { KPICard } from '@/components/kpi-card'
import {
  CardSkeleton,
  EmptyState,
  ErrorState,
  Skeleton,
  Spinner,
  StatusDot,
  TableSkeleton,
} from '@/components/feedback'

interface Row {
  id: number
  name: string
  value: string
  group: string | null
  enabled: boolean
  scans: number
}

/**
 * Style guide.
 *
 * Not decoration. A component that no page imports is tree-shaken out of the
 * bundle, so it cannot be exercised in a browser at all -- which is how the
 * Phase 1 verification found `Tabs` missing from the deployed bundle while the
 * source plainly exported it. This route imports every new component, so they
 * are built, shipped and inspectable, and a regression in any of them shows up
 * here rather than in production.
 */
export function StyleGuidePage(): JSX.Element {
  const theme = useUIStore((s) => s.theme)
  const toggleTheme = useUIStore((s) => s.toggleTheme)
  const sidebarCollapsed = useUIStore((s) => s.sidebarCollapsed)
  const toggleSidebar = useUIStore((s) => s.toggleSidebar)

  const [sortSpecs, setSortSpecs] = React.useState<readonly SortSpec[]>([
    { key: 'scans', direction: 'desc' },
  ])
  const [selected, setSelected] = React.useState<ReadonlySet<string | number>>(new Set())
  const [page, setPage] = React.useState(1)

  const { data } = useQuery({
    queryKey: ['targets'],
    queryFn: ({ signal }) => api.listTargets(signal),
  })

  const rows: Row[] = React.useMemo(
    () =>
      (data?.targets ?? []).map((target, index) => ({
        id: target.id,
        name: target.name,
        value: target.value,
        group: target.group,
        enabled: target.enabled === 1,
        scans: ((index * 37) % 90) + 3,
      })),
    [data],
  )

  const columns: Column<Row>[] = [
    { key: 'name', header: 'Name', cell: (row) => <span className="font-medium">{row.name}</span>,
      sortValue: (row) => row.name, sortable: true, resizable: true, width: 160 },
    { key: 'value', header: 'Value', cell: (row) => <span className="font-mono text-xs">{row.value}</span>,
      sortValue: (row) => row.value, sortable: true, resizable: true },
    { key: 'group', header: 'Group', cell: (row) => (row.group ?? <span className="text-faint">—</span>),
      sortValue: (row) => row.group ?? '', resizable: true, hidden: true },
    { key: 'enabled', header: 'Enabled', cell: (row) => (
        <Badge variant={row.enabled ? 'success' : 'muted'}>{row.enabled ? 'yes' : 'no'}</Badge>
      ), sortValue: (row) => (row.enabled ? 1 : 0), sortable: true },
    { key: 'scans', header: 'Scans', cell: (row) => <span className="tabular-nums">{formatNumber(row.scans)}</span>,
      sortValue: (row) => row.scans, sortable: true, resizable: true, keepVisible: true },
  ]

  function Section({
    title,
    description,
    children,
  }: {
    title: string
    description?: string
    children: React.ReactNode
  }): JSX.Element {
    return (
      <section className="space-y-3">
        <div>
          <h2 className="text-sm font-semibold text-fg">{title}</h2>
          {description ? <p className="text-xs text-muted">{description}</p> : null}
        </div>
        {children}
      </section>
    )
  }

  return (
    <div className="space-y-8">
      <Card variant="bordered" className="p-4">
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="default" size="default">Default</Button>
          <Button variant="secondary">Secondary</Button>
          <Button variant="outline">Outline</Button>
          <Button variant="ghost">Ghost</Button>
          <Button variant="danger">Danger</Button>
          <Button variant="link">Link</Button>
          <Button size="sm">Small</Button>
          <Button size="lg">Large</Button>
          <Button size="icon" aria-label="Icon only"><Network className="h-4 w-4" /></Button>
          <Button disabled>Disabled</Button>
        </div>
      </Card>

      <Section title="Card variants" description="default, bordered, elevated, interactive">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Card variant="default" className="p-4">
            <p className="text-xs text-muted">default</p>
            <p className="mt-1 text-sm">Flat, no edge</p>
          </Card>
          <Card variant="bordered" className="p-4">
            <p className="text-xs text-muted">bordered</p>
            <p className="mt-1 text-sm">Explicit edge</p>
          </Card>
          <Card variant="elevated" className="p-4">
            <p className="text-xs text-muted">elevated</p>
            <p className="mt-1 text-sm">Lifted</p>
          </Card>
          <Card
            variant="interactive"
            as="button"
            // shadow-glow is the theme's own focus treatment, applied on
            // hover and focus. This is its only use in the app, which is
            // exactly why the token check looks for it: an unreferenced
            // token is dead config that reads as coverage and provides none.
            className="p-4 hover:shadow-glow focus-visible:shadow-glow"
            onClick={() => toast.success('Interactive card pressed')}
          >
            <p className="text-xs text-muted">interactive</p>
            <p className="mt-1 text-sm">Hover and focus me</p>
          </Card>
        </div>
      </Section>

      <Section title="Badges" description="primary green is now distinct from success green">
        <div className="flex flex-wrap items-center gap-2">
          <Badge>default</Badge>
          <Badge variant="muted">muted</Badge>
          <Badge variant="success">success</Badge>
          <Badge variant="info">info</Badge>
          <Badge variant="warning">warning</Badge>
          <Badge variant="danger">danger</Badge>
        </div>
      </Section>

      <Section title="Stat tiles" description="icon, value, trend, hint tooltip, footer">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <KPICard label="With trend up" value={1234} icon={Network} trend={12.5} trendLabel="vs yesterday"
            hint="Total targets registered. Help text appears here." />
          <KPICard label="With trend down" value={87} icon={Network} trend={-4.2} trendLabel="vs yesterday"
            tone="danger" />
          <KPICard label="Flat trend" value={512} icon={Network} trend={0.2} trendLabel="vs yesterday"
            tone="info" />
          <KPICard label="No trend" value={9} icon={Network} trendLabel="registered" footer="footer line"
            tone="warning" />
        </div>
      </Section>

      <Section title="Skeleton variants" description="line, circle, card, tableRow">
        <div className="flex flex-wrap items-center gap-3">
          <Skeleton className="w-40" />
          <Skeleton variant="circle" />
          <Skeleton variant="card" className="w-40" />
        </div>
        <TableSkeleton rows={2} cols={3} />
        <CardSkeleton count={2} />
      </Section>

      <Section title="Empty and error states">
        <div className="grid gap-3 lg:grid-cols-2">
          <Card>
            <EmptyState title="No targets yet" description="Add a target to start scanning."
              actionLabel="Add target" onAction={() => toast.success('Would open the target dialog')} />
          </Card>
          <Card>
            <ErrorState description="Could not load data." onRetry={() => toast.info('Retrying')} />
          </Card>
        </div>
      </Section>

      <Section title="Tabs" description="Radix. Arrow keys, Home/End">
        <Tabs items={[{ value: 'overview', label: 'Overview', count: 12 }, { value: 'hosts', label: 'Hosts' }, { value: 'ports', label: 'Ports', disabled: true }]}>
          <TabsContent value="overview" className="py-3 text-sm text-muted">Overview panel</TabsContent>
          <TabsContent value="hosts" className="py-3 text-sm text-muted">Hosts panel</TabsContent>
        </Tabs>
      </Section>

      <Section title="Accordion" description="disclosure with a height transition, no measurement">
        <Card className="p-4">
          <Accordion
            defaultOpen={['a']}
            items={[
              { value: 'a', title: 'How is the colour scale defined?', content: 'Semantic tokens in index.css, mapped by tailwind.config.js. A theme flip is one attribute change on <html>.' },
              { value: 'b', title: 'What does interactive do?', content: 'Adds hover and focus affordances. Only valid when the card is a button or a link.' },
            ]}
          />
        </Card>
      </Section>

      <Section title="Tooltip and Popover" description="Radix, one shared provider">
        <div className="flex flex-wrap items-center gap-2">
          <Tooltip>
            <TooltipTrigger asChild><Button variant="outline">Hover me</Button></TooltipTrigger>
            <TooltipContent>Tooltip content</TooltipContent>
          </Tooltip>
          <Popover>
            <PopoverTrigger asChild><Button variant="outline">Open popover</Button></PopoverTrigger>
            <PopoverContent className="space-y-2">
              <p className="text-sm font-medium">Popover</p>
              <p className="text-xs text-muted">Collides with the viewport edge and flips automatically.</p>
            </PopoverContent>
          </Popover>
          <Checkbox defaultChecked aria-label="A checked box" />
          <Checkbox indeterminate aria-label="An indeterminate box" />
          <Checkbox aria-label="An unchecked box" />
          <StatusDot ok label="reachable" />
          <StatusDot ok={false} label="down" />
          <Spinner />
        </div>
      </Section>

      <Section title="DataTable" description="real data: sort (shift for multi), resize, select, columns menu">
        <DataTable
          columns={columns}
          rows={rows}
          rowKey={(row) => row.id}
          caption="Registered targets"
          emptyTitle="No targets"
          emptyDescription="Add one to get started."
          emptyIcon={Network}
          showColumnToggle
          multiSort
          sortSpecs={sortSpecs}
          onSortSpecsChange={setSortSpecs}
          selectable
          selectedKeys={selected}
          onSelectedKeysChange={setSelected}
          stickyHeader
          onRowClick={(row) => toast.info(`Row click: ${row.name}`)}
        />
        <Pagination
          page={page}
          pageSize={10}
          total={rows.length}
          onPageChange={setPage}
          onPageSizeChange={() => toast.info('Page size change')}
        />
      </Section>

      <Section title="Shell controls" description="theme and sidebar state, for a visual check">
        <Card className="flex flex-wrap items-center gap-2 p-4">
          <Button variant="outline" size="sm" onClick={toggleTheme}>
            {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            Switch to {theme === 'dark' ? 'light' : 'dark'}
          </Button>
          <Button variant="outline" size="sm" onClick={toggleSidebar}>
            Sidebar is {sidebarCollapsed ? 'collapsed' : 'expanded'}
          </Button>
          <Button variant="ghost" size="sm" onClick={() => {
            void navigator.clipboard?.writeText('netsentinel').then(() => toast.success('Copied'))
          }}>
            <Copy className="h-4 w-4" /> Copy test
          </Button>
          <span className={cn('flex items-center gap-1 text-xs text-muted')}>
            <Info className="h-3.5 w-3.5" /> {theme} theme
          </span>
        </Card>
      </Section>
    </div>
  )
}