import { type ElementType, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Ban, Globe, Cpu, MonitorSmartphone, Network, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { api, isIP, splitHost, toCIDR, WLType } from '@/lib/api';
import { cn, fmtBytes } from '@/lib/utils';
import { PageHeader } from '@/components/page-header';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Switch } from '@/components/ui/switch';

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
  alert: boolean;
  reasons?: string[];
  liveId?: string;
}

export default function Connections() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [tab, setTab] = useState<'all' | 'live' | 'closed'>('all');
  const [alertsOnly, setAlertsOnly] = useState(false);

  const { data: snap } = useQuery({ queryKey: ['conns'], queryFn: api.connections, refetchInterval: 2000 });
  const { data: events = [] } = useQuery({ queryKey: ['events'], queryFn: () => api.events(false), refetchInterval: 3000 });

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
      status: 'live',
      host: c.metadata.host || c.metadata.destinationIP,
      dest: `${c.metadata.destinationIP}:${c.metadata.destinationPort}`,
      source: c.metadata.sourceIP || '',
      process: c.metadata.process || '',
      chain: (c.chains || []).join(' → '),
      up: c.upload,
      down: c.download,
      alert: false,
      liveId: c.id,
    }));
    const closedRows: Row[] = events.map((e) => ({
      key: 'e:' + e.id,
      status: e.denied ? 'denied' : 'allowed',
      time: e.time,
      host: e.host,
      dest: e.destination,
      source: splitHost(e.source),
      process: e.process || '',
      chain: `${e.outbound} · ${e.network}`,
      up: e.upload,
      down: e.download,
      alert: e.level === 'alert',
      reasons: e.reasons,
    }));
    return { liveRows, closedRows };
  }, [snap, events]);

  let rows = tab === 'live' ? liveRows : tab === 'closed' ? closedRows : [...liveRows, ...closedRows];
  if (alertsOnly) rows = rows.filter((r) => r.alert);
  const alertCount = closedRows.filter((r) => r.alert).length;

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

  return (
    <div>
      <PageHeader
        title={t('pages.connections.title')}
        description={t('pages.connections.description')}
        actions={
          <>
            <label className="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer select-none">
              <Switch checked={alertsOnly} onCheckedChange={setAlertsOnly} /> {t('pages.connections.alertsOnly')}
              {alertCount > 0 && <Badge variant="danger">{alertCount}</Badge>}
            </label>
            {liveRows.length > 0 && (
              <Button variant="outline" size="sm" disabled={killAll.isPending} onClick={() => killAll.mutate()}>
                <X className="size-4" /> {t('pages.connections.closeAll')}
              </Button>
            )}
          </>
        }
      />

      <Tabs value={tab} onValueChange={(v) => setTab(v as typeof tab)} className="mb-4">
        <TabsList>
          <TabsTrigger value="all">
            {t('pages.connections.tabAll')} <span className="tnum text-muted-foreground">{liveRows.length + closedRows.length}</span>
          </TabsTrigger>
          <TabsTrigger value="live">
            {t('pages.connections.tabLive')} <span className="tnum text-muted-foreground">{liveRows.length}</span>
          </TabsTrigger>
          <TabsTrigger value="closed">
            {t('pages.connections.tabClosed')} <span className="tnum text-muted-foreground">{closedRows.length}</span>
          </TabsTrigger>
        </TabsList>
      </Tabs>

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
            {rows.length === 0 && (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={9} className="py-12 text-center text-muted-foreground">
                  {t('pages.connections.empty')}
                </TableCell>
              </TableRow>
            )}
            {rows.map((r) => (
              <TableRow key={r.key} data-state={r.alert ? 'alert' : undefined}>
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
      </Card>
    </div>
  );
}

function AddBtn({ icon: Icon, label, onClick }: { icon: ElementType; label: string; onClick: () => void }) {
  return (
    <Button variant="ghost" size="xs" className="text-muted-foreground hover:text-primary" onClick={onClick}>
      <Icon className={cn('size-3.5')} /> {label}
    </Button>
  );
}
