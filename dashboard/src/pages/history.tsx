import { type ElementType, useDeferredValue, useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ArrowDown, ArrowUp, Ban, Waypoints } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { api } from '@/lib/api';
import { cn, fmtBytes } from '@/lib/utils';
import { DEFAULT_PAGE_SIZE } from '@/hooks/use-paged-list';
import { PageHeader } from '@/components/page-header';
import { ListSearch, PaginationBar } from '@/components/pagination-bar';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';

export default function History() {
  const { t } = useTranslation();
  const [q, setQ] = useState('');
  const deferredQ = useDeferredValue(q);
  const [page, setPage] = useState(0);
  const pageSize = DEFAULT_PAGE_SIZE;

  useEffect(() => {
    setPage(0);
  }, [deferredQ]);

  const { data: stats } = useQuery({ queryKey: ['history', 'stats'], queryFn: api.historyStats, refetchInterval: 5000 });
  const { data: hist } = useQuery({
    queryKey: ['history', 'recent', deferredQ, page, pageSize],
    queryFn: () => api.history(pageSize, deferredQ, page * pageSize),
    refetchInterval: 5000,
    placeholderData: (prev) => prev,
  });

  const total = hist?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / pageSize) || 1);
  const safePage = Math.min(page, totalPages - 1);
  useEffect(() => {
    if (safePage !== page) setPage(safePage);
  }, [safePage, page]);
  const recent = hist?.items ?? [];
  const from = total === 0 ? 0 : safePage * pageSize + 1;
  const to = Math.min(total, (safePage + 1) * pageSize);

  const maxHour = Math.max(1, ...(stats?.hourly ?? []).map((h) => h.up + h.down));
  const maxTalker = Math.max(1, ...(stats?.top_talkers ?? []).map((talker) => talker.up + talker.down));

  return (
    <div>
      <PageHeader title={t('pages.history.title')} description={t('pages.history.description')} />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Stat icon={ArrowUp} label={t('pages.history.statTotalUpload')} value={fmtBytes(stats?.total_up ?? 0)} tone="primary" />
        <Stat icon={ArrowDown} label={t('pages.history.statTotalDownload')} value={fmtBytes(stats?.total_down ?? 0)} tone="primary" />
        <Stat icon={Waypoints} label={t('pages.history.statConnections')} value={String(stats?.connections ?? 0)} tone="muted" />
        <Stat
          icon={Ban}
          label={t('pages.history.statBlocked')}
          value={String(stats?.blocked ?? 0)}
          sub={t('pages.history.statBlockedSub', { count: stats?.alerts ?? 0 })}
          tone={stats?.blocked ? 'danger' : 'muted'}
        />
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader className="pb-2"><CardTitle className="text-sm">{t('pages.history.trafficTitle')}</CardTitle></CardHeader>
          <CardContent>
            {(stats?.hourly?.length ?? 0) === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">{t('pages.history.trafficEmpty')}</p>
            ) : (
              <div className="flex h-32 items-end gap-1">
                {stats!.hourly.map((h) => {
                  const totalH = h.up + h.down;
                  return (
                    <div
                      key={h.hour}
                      className="group relative flex-1 rounded-t bg-primary/70 transition-colors hover:bg-primary"
                      style={{ height: `${Math.max(2, (totalH / maxHour) * 100)}%` }}
                      title={t('pages.history.hourTooltip', {
                        time: new Date(h.hour * 1000).toLocaleTimeString([], { hour: '2-digit' }),
                        up: fmtBytes(h.up),
                        down: fmtBytes(h.down),
                        count: h.count,
                      })}
                    />
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm">{t('pages.history.topTalkersTitle')}</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {(stats?.top_talkers?.length ?? 0) === 0 && <p className="py-4 text-center text-xs text-muted-foreground">{t('pages.history.topTalkersEmpty')}</p>}
            {(stats?.top_talkers ?? []).slice(0, 8).map((talker) => (
              <div key={talker.host} className="space-y-0.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="truncate pr-2">{talker.host}</span>
                  <span className="tnum shrink-0 text-muted-foreground">{fmtBytes(talker.up + talker.down)}</span>
                </div>
                <div className="h-1.5 overflow-hidden rounded-full bg-muted">
                  <div className="h-full rounded-full bg-primary" style={{ width: `${((talker.up + talker.down) / maxTalker) * 100}%` }} />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      <Card className="mt-4 overflow-hidden">
        <CardHeader className="flex-row items-center justify-between pb-2">
          <CardTitle className="text-sm">{t('pages.history.recentTitle')}</CardTitle>
          <ListSearch value={q} onChange={setQ} placeholder={t('pages.history.filterPlaceholder')} />
        </CardHeader>
        <CardContent className="px-0 pb-0">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="w-20">{t('pages.history.columnTime')}</TableHead>
                <TableHead>{t('pages.history.columnHost')}</TableHead>
                <TableHead>{t('pages.history.columnProcess')}</TableHead>
                <TableHead className="text-right">↑</TableHead>
                <TableHead className="text-right">↓</TableHead>
                <TableHead>{t('pages.history.columnOut')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {recent.length === 0 && (
                <TableRow className="hover:bg-transparent">
                  <TableCell colSpan={6} className="py-10 text-center text-muted-foreground">{t('pages.history.empty')}</TableCell>
                </TableRow>
              )}
              {recent.map((r, i) => (
                <TableRow key={`${r.t}-${r.h}-${r.d}-${i}`} data-state={r.l === 'alert' ? 'alert' : undefined}>
                  <TableCell className="tnum text-xs text-muted-foreground">
                    {r.t ? new Date(r.t).toLocaleTimeString() : '—'}
                  </TableCell>
                  <TableCell>
                    <span className="flex items-center gap-1.5">
                      {r.x && <Badge variant="danger">{t('pages.history.badgeBlocked')}</Badge>}
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
          <PaginationBar
            page={safePage}
            totalPages={totalPages}
            total={total}
            from={from}
            to={to}
            onPageChange={setPage}
          />
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
