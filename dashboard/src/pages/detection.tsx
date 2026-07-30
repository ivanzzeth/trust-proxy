import { useQuery } from '@tanstack/react-query';
import { SlidersHorizontal } from 'lucide-react';
import { NavLink } from 'react-router-dom';
import { useTranslation } from 'react-i18next';

import { api } from '@/lib/api';
import { PageHeader } from '@/components/page-header';
import { QuarantinePanel } from '@/components/quarantine-panel';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';

// What the detectors *saw*, and the gateway's own quarantine list.
//
// The thresholds used to be edited here too, which put "what is happening" and
// "what would count as suspicious" on one page — and left the ten query/host/JA4
// knobs undrawn because there was no card left to put them in. Tuning now lives
// on Settings with every other knob; this page answers one question, and the
// button below goes to the other one.
//
// Quarantine is deliberately not the deny list — deny is operator policy stored
// in the posture slot, and a Strict<->Split switch replaces it wholesale, which
// would silently un-block something the gateway blocked for cause.
export default function Detection() {
  const { t } = useTranslation();
  const { data: queries } = useQuery({ queryKey: ['dns-query-stats'], queryFn: () => api.dnsQueryStats(8), refetchInterval: 10000 });
  const { data: fps } = useQuery({ queryKey: ['fingerprints'], queryFn: () => api.fingerprints(20), refetchInterval: 15000 });
  const { data: net } = useQuery({ queryKey: ['netcheck'], queryFn: api.netcheck, refetchInterval: 15000 });

  return (
    <div>
      <PageHeader
        title={t('pages.detection.title')}
        description={t('pages.detection.description')}
        actions={
          <Button asChild variant="outline" size="sm">
            <NavLink to="/settings">
              <SlidersHorizontal className="size-3.5" /> {t('pages.detection.tuning')}
            </NavLink>
          </Button>
        }
      />

      {/* Quarantine first: an auto-ban buried below JA4/host/queries looks like
          "remote frps died" (connect then EOF), not a local policy hit. */}
      <div className="mb-6">
        <QuarantinePanel compact />
      </div>

      <Card className="mt-6">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm">{t('pages.detection.ja4Title')}</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="mb-3 text-xs leading-relaxed text-muted-foreground">{t('pages.detection.ja4Hint')}</p>
          {fps?.learning && (
            <p className="mb-3 text-xs text-amber-500">
              {t('pages.detection.ja4Learning')} {fps.learning_until}
            </p>
          )}
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>JA4</TableHead>
                <TableHead className="text-right">{t('pages.detection.ja4Seen')}</TableHead>
                <TableHead>{t('pages.detection.ja4Last')}</TableHead>
                <TableHead>{t('pages.detection.ja4Processes')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(fps?.fingerprints ?? []).length === 0 && (
                <TableRow className="hover:bg-transparent">
                  <TableCell colSpan={4} className="py-6 text-center text-muted-foreground">{t('pages.detection.ja4Empty')}</TableCell>
                </TableRow>
              )}
              {(fps?.fingerprints ?? []).map((f) => (
                <TableRow key={f.ja4}>
                  <TableCell className="font-mono text-xs">{f.ja4}</TableCell>
                  <TableCell className="tnum text-right text-xs">{f.count}</TableCell>
                  <TableCell className="tnum text-xs text-muted-foreground">{f.last_seen}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{(f.processes ?? []).join(', ')}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card className="mt-6">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm">{t('pages.detection.hostTitle')}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-xs">
          <p className="leading-relaxed text-muted-foreground">{t('pages.detection.hostHint')}</p>
          {net?.supported === false ? (
            <p className="text-muted-foreground">{t('pages.detection.hostUnsupported')}</p>
          ) : (
            <div className="flex flex-wrap gap-x-6 gap-y-1">
              <span>{t('pages.detection.hostTunnel')}: <b>{(net?.tun_ifaces ?? []).join(', ') || '—'}</b></span>
              <span>{t('pages.detection.hostDefault')}: <b>{net?.default_via || '—'}</b></span>
              <span>{t('pages.detection.hostRoutes')}: <b className="tnum">{net?.routes?.length ?? 0}</b>
                <span className="text-muted-foreground"> ({net?.host_routes ?? 0} host)</span></span>
              <span>{t('pages.detection.hostLocals')}: <b className="font-mono">{(net?.local_nets ?? []).join(' ') || '—'}</b></span>
            </div>
          )}
        </CardContent>
      </Card>

      <Card className="mt-6">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm">{t('pages.detection.queriesTitle')}</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="mb-3 text-xs leading-relaxed text-muted-foreground">{t('pages.detection.queriesHint')}</p>
          <div className="mb-3 flex flex-wrap gap-4 text-xs">
            <span>{t('pages.detection.queriesTotal')}: <b className="tnum">{queries?.total ?? 0}</b></span>
            <span>
              NXDOMAIN: <b className="tnum">{queries?.nxdomain ?? 0}</b>
              {queries && queries.total > 0 && (
                <span className="text-muted-foreground"> ({((queries.nxdomain / queries.total) * 100).toFixed(1)}%)</span>
              )}
            </span>
            <span>TXT/NULL/ANY: <b className="tnum">{queries?.odd_type ?? 0}</b></span>
          </div>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('pages.detection.colParent')}</TableHead>
                <TableHead className="text-right">{t('pages.detection.colQueries')}</TableHead>
                <TableHead className="text-right">NXDOMAIN</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(queries?.top_parents ?? []).length === 0 && (
                <TableRow className="hover:bg-transparent">
                  <TableCell colSpan={3} className="py-6 text-center text-muted-foreground">{t('pages.detection.queriesEmpty')}</TableCell>
                </TableRow>
              )}
              {(queries?.top_parents ?? []).map((p) => (
                <TableRow key={p.parent}>
                  <TableCell className="font-mono text-xs">{p.parent}</TableCell>
                  <TableCell className="tnum text-right text-xs">{p.queries}</TableCell>
                  <TableCell className="tnum text-right text-xs">{p.nxdomain}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
