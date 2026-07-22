import { type ElementType, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ArrowDown, ArrowUp, Ban, Search, Waypoints } from 'lucide-react';

import { api } from '@/lib/api';
import { cn, fmtBytes } from '@/lib/utils';
import { PageHeader } from '@/components/page-header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';

export default function History() {
  const [host, setHost] = useState('');
  const { data: stats } = useQuery({ queryKey: ['history', 'stats'], queryFn: api.historyStats, refetchInterval: 5000 });
  const { data: recent = [] } = useQuery({
    queryKey: ['history', 'recent', host],
    queryFn: () => api.history(300, host),
    refetchInterval: 5000,
  });

  const maxHour = Math.max(1, ...(stats?.hourly ?? []).map((h) => h.up + h.down));
  const maxTalker = Math.max(1, ...(stats?.top_talkers ?? []).map((t) => t.up + t.down));

  return (
    <div>
      <PageHeader title="History" description="Durable per-connection log — every closed connection, with byte totals, top talkers and hourly trend." />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Stat icon={ArrowUp} label="Total upload" value={fmtBytes(stats?.total_up ?? 0)} tone="primary" />
        <Stat icon={ArrowDown} label="Total download" value={fmtBytes(stats?.total_down ?? 0)} tone="primary" />
        <Stat icon={Waypoints} label="Connections" value={String(stats?.connections ?? 0)} tone="muted" />
        <Stat icon={Ban} label="Blocked" value={String(stats?.blocked ?? 0)} sub={`${stats?.alerts ?? 0} alerts`} tone={stats?.blocked ? 'danger' : 'muted'} />
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader className="pb-2"><CardTitle className="text-sm">Traffic — last 24h</CardTitle></CardHeader>
          <CardContent>
            {(stats?.hourly?.length ?? 0) === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">No traffic recorded yet.</p>
            ) : (
              <div className="flex h-32 items-end gap-1">
                {stats!.hourly.map((h) => {
                  const total = h.up + h.down;
                  return (
                    <div
                      key={h.hour}
                      className="group relative flex-1 rounded-t bg-primary/70 transition-colors hover:bg-primary"
                      style={{ height: `${Math.max(2, (total / maxHour) * 100)}%` }}
                      title={`${new Date(h.hour * 1000).toLocaleTimeString([], { hour: '2-digit' })} · ↑${fmtBytes(h.up)} ↓${fmtBytes(h.down)} · ${h.count} conns`}
                    />
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm">Top talkers</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {(stats?.top_talkers?.length ?? 0) === 0 && <p className="py-4 text-center text-xs text-muted-foreground">—</p>}
            {(stats?.top_talkers ?? []).slice(0, 8).map((t) => (
              <div key={t.host} className="space-y-0.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="truncate pr-2">{t.host}</span>
                  <span className="tnum shrink-0 text-muted-foreground">{fmtBytes(t.up + t.down)}</span>
                </div>
                <div className="h-1.5 overflow-hidden rounded-full bg-muted">
                  <div className="h-full rounded-full bg-primary" style={{ width: `${((t.up + t.down) / maxTalker) * 100}%` }} />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      <Card className="mt-4 overflow-hidden">
        <CardHeader className="flex-row items-center justify-between pb-2">
          <CardTitle className="text-sm">Recent connections</CardTitle>
          <div className="relative">
            <Search className="absolute left-2 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input className="h-8 w-56 pl-7" placeholder="filter by host…" value={host} onChange={(e) => setHost(e.target.value)} />
          </div>
        </CardHeader>
        <CardContent className="px-0 pb-0">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="w-20">Time</TableHead>
                <TableHead>Host</TableHead>
                <TableHead>Process</TableHead>
                <TableHead className="text-right">↑</TableHead>
                <TableHead className="text-right">↓</TableHead>
                <TableHead>Out</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {recent.length === 0 && (
                <TableRow className="hover:bg-transparent">
                  <TableCell colSpan={6} className="py-10 text-center text-muted-foreground">No records</TableCell>
                </TableRow>
              )}
              {recent.map((r, i) => (
                <TableRow key={i} data-state={r.l === 'alert' ? 'alert' : undefined}>
                  <TableCell className="tnum text-xs text-muted-foreground">
                    {r.t ? new Date(r.t).toLocaleTimeString() : '—'}
                  </TableCell>
                  <TableCell>
                    <span className="flex items-center gap-1.5">
                      {r.x && <Badge variant="danger">blocked</Badge>}
                      {r.h}
                    </span>
                    <div className="tnum text-xs text-muted-foreground">{r.d}</div>
                  </TableCell>
                  <TableCell className="max-w-[180px] truncate text-xs text-muted-foreground" title={r.p}>{r.p || '—'}</TableCell>
                  <TableCell className="tnum text-right text-xs">{fmtBytes(r.u)}</TableCell>
                  <TableCell className="tnum text-right text-xs">{fmtBytes(r.dn)}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{r.o}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

const TONES: Record<string, string> = {
  primary: 'text-primary bg-primary/10',
  danger: 'text-destructive bg-destructive/10',
  muted: 'text-muted-foreground bg-muted',
};
function Stat({ icon: Icon, label, value, sub, tone }: { icon: ElementType; label: string; value: string; sub?: string; tone: string }) {
  return (
    <Card>
      <CardContent className="flex items-center gap-4 p-5">
        <div className={cn('grid size-11 shrink-0 place-items-center rounded-lg', TONES[tone])}>
          <Icon className="size-5" />
        </div>
        <div className="min-w-0">
          <div className="text-xs uppercase tracking-wide text-muted-foreground">{label}</div>
          <div className="truncate text-xl font-bold leading-tight">{value}</div>
          {sub && <div className="truncate text-xs text-muted-foreground">{sub}</div>}
        </div>
      </CardContent>
    </Card>
  );
}
