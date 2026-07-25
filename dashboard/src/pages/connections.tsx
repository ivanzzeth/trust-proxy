import { type ElementType, useDeferredValue, useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useSearchParams } from 'react-router-dom';
import { toast } from 'sonner';
import { Ban, Globe, Cpu, MonitorSmartphone, Network, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { api, isIP, splitHost, toCIDR, type DetectionKind, type DetectionAction, WLType } from '@/lib/api';
import { cn, fmtBytes } from '@/lib/utils';
import { matchesQuery, usePagedList, DEFAULT_PAGE_SIZE } from '@/hooks/use-paged-list';
import { PageHeader } from '@/components/page-header';
import { ListSearch, PaginationBar } from '@/components/pagination-bar';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';

type Tab = 'live' | 'closed' | 'alerts';
type Status = 'live' | 'allowed' | 'denied';
interface Row {
  key: string;
  status: Status;
  time?: string;
  host: string;
  dest: string;
  source: string;
  process: string;
  chain: string;
  up: number;
  down: number;
  reasons?: string[];
  liveId?: string;
}

const KINDS: Array<DetectionKind | ''> = ['', 'intel', 'exfil', 'beacon', 'dga'];

export default function Connections() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [params, setParams] = useSearchParams();
  const tabParam = params.get('tab');
  const kindParam = params.get('kind') ?? '';
  const [tab, setTab] = useState<Tab>(tabParam === 'alerts' || tabParam === 'closed' || tabParam === 'live' ? tabParam : 'live');
  const [kind, setKind] = useState<DetectionKind | ''>(
    KINDS.includes(kindParam as DetectionKind) ? (kindParam as DetectionKind) : '',
  );
  const [search, setSearch] = useState('');
  const deferredSearch = useDeferredValue(search);
  const [alertPage, setAlertPage] = useState(0);

  useEffect(() => {
    if (tabParam === 'alerts' || tabParam === 'closed' || tabParam === 'live') setTab(tabParam);
  }, [tabParam]);
  useEffect(() => {
    if (KINDS.includes(kindParam as DetectionKind) || kindParam === '') {
      setKind((kindParam as DetectionKind) || '');
    }
  }, [kindParam]);

  const setTabNav = (v: Tab) => {
    setTab(v);
    const next = new URLSearchParams(params);
    next.set('tab', v);
    if (v !== 'alerts') next.delete('kind');
    setParams(next, { replace: true });
  };
  const setKindNav = (k: DetectionKind | '') => {
    setKind(k);
    setAlertPage(0);
    const next = new URLSearchParams(params);
    next.set('tab', 'alerts');
    if (k) next.set('kind', k);
    else next.delete('kind');
    setParams(next, { replace: true });
  };

  const { data: snap } = useQuery({ queryKey: ['conns'], queryFn: api.connections, refetchInterval: 2000 });
  const { data: events = [] } = useQuery({
    queryKey: ['events'],
    queryFn: () => api.events(false),
    refetchInterval: 3000,
    enabled: tab !== 'alerts',
  });
  const { data: detPage } = useQuery({
    queryKey: ['detections', kind, deferredSearch, alertPage],
    queryFn: () =>
      api.detections({
        kind: kind || undefined,
        q: deferredSearch.trim() || undefined,
        offset: alertPage * DEFAULT_PAGE_SIZE,
        limit: DEFAULT_PAGE_SIZE,
      }),
    refetchInterval: 3000,
    enabled: tab === 'alerts',
  });

  const addWL = useMutation({
    mutationFn: (v: { type: WLType; value: string }) => api.addWL(v.type, v.value),
    onSuccess: (_d, v) => {
      toast.success(t('pages.connections.whitelisted', { type: v.type, value: v.value }));
      qc.invalidateQueries({ queryKey: ['whitelist'] });
      qc.invalidateQueries({ queryKey: ['conns'] });
      qc.invalidateQueries({ queryKey: ['events'] });
    },
    onError: (e) => toast.error(String((e as Error).message)),
  });
  const kill = useMutation({
    mutationFn: api.killConn,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['conns'] }),
  });
  const killAll = useMutation({
    mutationFn: api.killAll,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['conns'] }),
  });

  const { liveRows, closedRows } = useMemo(() => {
    const liveRows: Row[] = (snap?.connections ?? []).map((c) => ({
      key: 'l:' + c.id,
      status: 'live' as const,
      host: c.metadata.host || c.metadata.destinationIP,
      dest: `${c.metadata.destinationIP}:${c.metadata.destinationPort}`,
      source: c.metadata.sourceIP || '',
      process: c.metadata.process || '',
      chain: (c.chains || []).join(' → '),
      up: c.upload,
      down: c.download,
      liveId: c.id,
    }));
    const closedRows: Row[] = events.map((e) => ({
      key: 'e:' + e.id,
      status: (e.denied ? 'denied' : 'allowed') as Status,
      time: e.time,
      host: e.host,
      dest: e.destination,
      source: splitHost(e.source),
      process: e.process || '',
      chain: `${e.outbound} · ${e.network}`,
      up: e.upload,
      down: e.download,
      reasons: e.reasons,
    }));
    return { liveRows, closedRows };
  }, [snap, events]);

  const filtered = useMemo(() => {
    let rows = tab === 'live' ? liveRows : closedRows;
    if (deferredSearch.trim()) {
      rows = rows.filter((r) =>
        matchesQuery(deferredSearch, r.host, r.dest, r.source, r.process, r.chain, ...(r.reasons ?? [])),
      );
    }
    return rows;
  }, [tab, liveRows, closedRows, deferredSearch]);

  const resetKey = `${tab}|${deferredSearch.trim().toLowerCase()}`;
  const page = usePagedList(filtered, resetKey);

  const badge = (r: Row) =>
    r.status === 'live' ? (
      <Badge variant="success">
        <span className="size-1.5 rounded-full bg-primary animate-pulse" /> {t('pages.connections.statusLive')}
      </Badge>
    ) : r.status === 'denied' ? (
      <Badge variant="danger">
        <Ban className="size-3" /> {t('pages.connections.statusBlocked')}
      </Badge>
    ) : (
      <Badge variant="muted">{t('pages.connections.statusAllowed')}</Badge>
    );

  const destIP = (r: Row) => splitHost(r.dest);
  const alertTotal = detPage?.total ?? 0;
  const alertTotalPages = Math.max(1, Math.ceil(alertTotal / DEFAULT_PAGE_SIZE) || 1);

  useEffect(() => {
    if (alertPage > 0 && alertPage >= alertTotalPages) setAlertPage(Math.max(0, alertTotalPages - 1));
  }, [alertPage, alertTotalPages]);

  return (
    <div>
      <PageHeader
        title={t('pages.connections.title')}
        description={t('pages.connections.description')}
        actions={
          tab === 'live' && liveRows.length > 0 ? (
            <Button variant="outline" size="sm" disabled={killAll.isPending} onClick={() => killAll.mutate()}>
              <X className="size-4" /> {t('pages.connections.closeAll')}
            </Button>
          ) : null
        }
      />

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <Tabs value={tab} onValueChange={(v) => setTabNav(v as Tab)}>
          <TabsList>
            <TabsTrigger value="live">
              {t('pages.connections.tabLive')} <span className="tnum text-muted-foreground">{liveRows.length}</span>
            </TabsTrigger>
            <TabsTrigger value="closed">
              {t('pages.connections.tabClosed')} <span className="tnum text-muted-foreground">{closedRows.length}</span>
            </TabsTrigger>
            <TabsTrigger value="alerts">
              {t('pages.connections.tabAlerts')}{' '}
              <span className="tnum text-muted-foreground">{tab === 'alerts' ? alertTotal : '·'}</span>
            </TabsTrigger>
          </TabsList>
        </Tabs>
        <ListSearch
          value={search}
          onChange={(v) => {
            setSearch(v);
            if (tab === 'alerts') setAlertPage(0);
          }}
          placeholder={
            tab === 'alerts' ? t('pages.connections.searchAlerts') : t('pages.connections.searchPlaceholder')
          }
          className="ml-auto"
        />
      </div>

      {tab === 'alerts' && (
        <div className="mb-3 flex flex-wrap gap-1.5">
          {KINDS.map((k) => (
            <Button
              key={k || 'all'}
              size="sm"
              variant={kind === k ? 'default' : 'outline'}
              onClick={() => setKindNav(k)}
            >
              {k === '' ? t('pages.connections.kindAll') : t(`pages.connections.kind.${k}`)}
            </Button>
          ))}
        </div>
      )}

      {tab === 'alerts' ? (
        <Card className="overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="w-20">{t('pages.connections.colTime')}</TableHead>
                <TableHead className="w-24">{t('pages.connections.colKind')}</TableHead>
                <TableHead>{t('pages.connections.colDestination')}</TableHead>
                <TableHead>{t('pages.connections.colProcess')}</TableHead>
                <TableHead className="w-28">{t('pages.connections.colAction')}</TableHead>
                <TableHead>{t('pages.connections.colReason')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {alertTotal === 0 && (
                <TableRow className="hover:bg-transparent">
                  <TableCell colSpan={6} className="py-12 text-center text-muted-foreground">
                    {t('pages.connections.emptyAlerts')}
                  </TableCell>
                </TableRow>
              )}
              {(detPage?.items ?? []).map((d) => (
                <TableRow key={d.id}>
                  <TableCell className="tnum text-xs text-muted-foreground">
                    {new Date(d.time).toLocaleTimeString()}
                  </TableCell>
                  <TableCell>
                    <KindBadge kind={d.kind} />
                  </TableCell>
                  <TableCell>
                    <div className="font-medium">{d.host || '—'}</div>
                    <div className="tnum text-xs text-muted-foreground">{d.destination}</div>
                  </TableCell>
                  <TableCell className="max-w-[180px] truncate text-xs text-muted-foreground" title={d.process}>
                    {d.process || '—'}
                  </TableCell>
                  <TableCell>
                    <ActionBadge action={d.action} />
                  </TableCell>
                  <TableCell className="max-w-[320px]">
                    <span className="text-xs text-destructive">{(d.reasons ?? []).join('; ') || '—'}</span>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <PaginationBar
            page={alertPage}
            totalPages={alertTotalPages}
            total={alertTotal}
            from={alertTotal === 0 ? 0 : alertPage * DEFAULT_PAGE_SIZE + 1}
            to={Math.min(alertTotal, (alertPage + 1) * DEFAULT_PAGE_SIZE)}
            onPageChange={setAlertPage}
          />
        </Card>
      ) : (
        <Card className="overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="w-24">{t('pages.connections.colStatus')}</TableHead>
                <TableHead className="w-20">{t('pages.connections.colTime')}</TableHead>
                <TableHead>{t('pages.connections.colDestination')}</TableHead>
                <TableHead>{t('pages.connections.colProcess')}</TableHead>
                <TableHead>{t('pages.connections.colEgress')}</TableHead>
                <TableHead className="text-right">↑</TableHead>
                <TableHead className="text-right">↓</TableHead>
                <TableHead>{t('pages.connections.colDetail')}</TableHead>
                <TableHead className="text-right">{t('pages.connections.colAddToWhitelist')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {page.total === 0 && (
                <TableRow className="hover:bg-transparent">
                  <TableCell colSpan={9} className="py-12 text-center text-muted-foreground">
                    {t('pages.connections.empty')}
                  </TableCell>
                </TableRow>
              )}
              {page.pageItems.map((r) => (
                <TableRow key={r.key}>
                  <TableCell>{badge(r)}</TableCell>
                  <TableCell className="tnum text-xs text-muted-foreground">
                    {r.time ? new Date(r.time).toLocaleTimeString() : '—'}
                  </TableCell>
                  <TableCell>
                    <div className="font-medium">{r.host}</div>
                    <div className="tnum text-xs text-muted-foreground">{r.dest}</div>
                  </TableCell>
                  <TableCell className="max-w-[180px] truncate text-xs text-muted-foreground" title={r.process}>
                    {r.process || '—'}
                  </TableCell>
                  <TableCell className="max-w-[220px] truncate text-xs" title={r.chain}>
                    {r.chain ? <span className="tnum">{r.chain}</span> : <span className="text-muted-foreground">—</span>}
                  </TableCell>
                  <TableCell className="tnum text-right text-xs">{fmtBytes(r.up)}</TableCell>
                  <TableCell className="tnum text-right text-xs">{fmtBytes(r.down)}</TableCell>
                  <TableCell className="max-w-[240px]">
                    {r.reasons && r.reasons.length > 0 ? (
                      <span className="text-xs text-destructive">{r.reasons.join('; ')}</span>
                    ) : (
                      <span className="text-xs text-muted-foreground">—</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center justify-end gap-1">
                      {r.host && !isIP(r.host) && (
                        <AddBtn
                          icon={Globe}
                          label={t('pages.connections.addDomain')}
                          onClick={() => addWL.mutate({ type: 'domain', value: r.host })}
                        />
                      )}
                      {isIP(destIP(r)) && (
                        <AddBtn
                          icon={Network}
                          label={t('pages.connections.addIP')}
                          onClick={() => addWL.mutate({ type: 'ip', value: toCIDR(destIP(r)) })}
                        />
                      )}
                      {r.process && (
                        <AddBtn
                          icon={Cpu}
                          label={t('pages.connections.addProcess')}
                          onClick={() => addWL.mutate({ type: 'process', value: r.process })}
                        />
                      )}
                      {isIP(r.source) && (
                        <AddBtn
                          icon={MonitorSmartphone}
                          label={t('pages.connections.addDevice')}
                          onClick={() => addWL.mutate({ type: 'device', value: toCIDR(r.source) })}
                        />
                      )}
                      {r.status === 'live' && (
                        <Button variant="ghost" size="xs" className="text-destructive" onClick={() => kill.mutate(r.liveId!)}>
                          <X className="size-3.5" />
                        </Button>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <PaginationBar
            page={page.page}
            totalPages={page.totalPages}
            total={page.total}
            from={page.from}
            to={page.to}
            onPageChange={page.setPage}
          />
        </Card>
      )}
    </div>
  );
}

function KindBadge({ kind }: { kind: DetectionKind }) {
  const { t } = useTranslation();
  const variant = kind === 'intel' || kind === 'exfil' ? 'danger' : 'warning';
  return <Badge variant={variant}>{t(`pages.connections.kind.${kind}`)}</Badge>;
}

function ActionBadge({ action }: { action: DetectionAction }) {
  const { t } = useTranslation();
  if (action === 'banned') return <Badge variant="danger">{t('pages.connections.action.banned')}</Badge>;
  if (action === 'blocked') return <Badge variant="warning">{t('pages.connections.action.blocked')}</Badge>;
  return <Badge variant="muted">{t('pages.connections.action.alert')}</Badge>;
}

function AddBtn({ icon: Icon, label, onClick }: { icon: ElementType; label: string; onClick: () => void }) {
  return (
    <Button variant="ghost" size="xs" className="text-muted-foreground hover:text-primary" onClick={onClick}>
      <Icon className={cn('size-3.5')} /> {label}
    </Button>
  );
}
