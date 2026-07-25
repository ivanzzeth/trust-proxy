import { type ElementType, type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { AlertTriangle, Ban, Radio, ShieldAlert, Waypoints } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { api } from '@/lib/api';
import { cn, fmtBytes, fmtRate } from '@/lib/utils';
import { useTrafficRate } from '@/hooks/use-traffic-rate';
import { PageHeader } from '@/components/page-header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { alertsHref } from '@/lib/alerts';

export default function Overview() {
  const { t } = useTranslation();
  const { data: st } = useQuery({ queryKey: ['status'], queryFn: api.status, refetchInterval: 5000 });
  const { data: snap } = useQuery({ queryKey: ['conns'], queryFn: api.connections, refetchInterval: 2000 });
  const { data: detStats } = useQuery({
    queryKey: ['detections-stats'],
    queryFn: api.detectionsStats,
    refetchInterval: 5000,
  });
  const { data: detRecent } = useQuery({
    queryKey: ['detections', 'recent'],
    queryFn: () => api.detections({ limit: 8, offset: 0 }),
    refetchInterval: 5000,
  });
  const { data: subs = [] } = useQuery({ queryKey: ['subs'], queryFn: api.subs });
  const { data: wl } = useQuery({ queryKey: ['whitelist'], queryFn: api.whitelist });

  const live = snap?.connections?.length ?? 0;
  const { up, down } = useTrafficRate();
  const alerts24 = detStats?.alerts_24h ?? 0;
  const blocked24 = detStats?.blocked_24h ?? 0;
  const banned24 = detStats?.banned_24h ?? 0;
  const intelDomains = detStats?.intel_domains ?? st?.threats.domains ?? 0;
  const intelIps = detStats?.intel_ips ?? st?.threats.ips ?? 0;
  const appliedSub = subs.find((s) => s.applied);
  const recent = detRecent?.items ?? [];

  return (
    <div>
      <PageHeader title={t('pages.overview.title')} description={t('pages.overview.description')} />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatLink to={alertsHref()}>
          <Stat
            icon={ShieldAlert}
            label={t('pages.overview.alerts24h')}
            value={String(alerts24)}
            sub={t('pages.overview.clickAlerts')}
            tone={alerts24 ? 'danger' : 'muted'}
          />
        </StatLink>
        <StatLink to={alertsHref()}>
          <Stat
            icon={Ban}
            label={t('pages.overview.blocked24h')}
            value={String(blocked24)}
            sub={t('pages.overview.clickBlocked')}
            tone={blocked24 ? 'warning' : 'muted'}
          />
        </StatLink>
        <StatLink to={alertsHref()}>
          <Stat
            icon={AlertTriangle}
            label={t('pages.overview.banned24h')}
            value={String(banned24)}
            sub={t('pages.overview.clickBanned')}
            tone={banned24 ? 'danger' : 'muted'}
          />
        </StatLink>
        <Stat
          icon={Radio}
          label={t('pages.overview.threatIntel')}
          value={String(intelDomains + intelIps)}
          sub={t('pages.overview.domainsAndIps', { domains: intelDomains, ips: intelIps })}
          tone="warning"
        />
      </div>

      <div className="mt-4 grid gap-4 sm:grid-cols-2 xl:grid-cols-2">
        <Stat
          icon={Waypoints}
          label={t('pages.overview.liveConnections')}
          value={String(live)}
          sub={`↑ ${fmtRate(up)} · ↓ ${fmtRate(down)} · Σ ↑ ${fmtBytes(snap?.uploadTotal ?? 0)} / ↓ ${fmtBytes(snap?.downloadTotal ?? 0)}`}
          tone="primary"
        />
        <Stat
          icon={Radio}
          label={t('pages.overview.captureMode')}
          value={st ? st.mode : '—'}
          sub={st?.autoBlock ? t('pages.overview.autoBlockOn') : t('pages.overview.autoBlockOff')}
          tone={st?.autoBlock ? 'primary' : 'muted'}
        />
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader className="flex-row items-center justify-between">
            <CardTitle className="flex items-center gap-2 text-sm">
              <AlertTriangle className="size-4 text-destructive" /> {t('pages.overview.recentAlerts')}
            </CardTitle>
            <Link to={alertsHref()} className="text-xs text-primary hover:underline">
              {t('pages.overview.viewAll')}
            </Link>
          </CardHeader>
          <CardContent className="pt-0">
            {recent.length === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">{t('pages.overview.noAlerts')}</p>
            ) : (
              <div className="divide-y divide-border/60">
                {recent.map((e) => (
                  <div key={e.id} className="flex items-center gap-3 py-2.5">
                    <span className="size-1.5 shrink-0 rounded-full bg-destructive" />
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-sm font-medium">
                        <span className="mr-2 text-xs uppercase text-muted-foreground">{e.kind}</span>
                        {e.host || e.destination}
                      </div>
                      <div className="truncate text-xs text-destructive">{(e.reasons ?? []).join('; ')}</div>
                    </div>
                    <span className="tnum shrink-0 text-xs text-muted-foreground">
                      {new Date(e.time).toLocaleTimeString()}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm">{t('pages.overview.activePolicy')}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 pt-0 text-sm">
            <Row label={t('pages.overview.exitNode')}>
              {appliedSub ? <Badge variant="success">{appliedSub.name}</Badge> : <span className="text-muted-foreground">{t('pages.overview.direct')}</span>}
            </Row>
            <Row label={t('pages.overview.whitelistedDomains')}><span className="tnum">{wl?.domains.length ?? 0}</span></Row>
            <Row label={t('pages.overview.whitelistedIps')}><span className="tnum">{wl?.ips.length ?? 0}</span></Row>
            <Row label={t('pages.overview.processGate')}>
              {wl?.processes.length ? <Badge variant="warning">{t('pages.overview.allowedCount', { count: wl.processes.length })}</Badge> : <span className="text-muted-foreground">{t('pages.overview.off')}</span>}
            </Row>
            <Row label={t('pages.overview.deviceGate')}>
              {wl?.devices.length ? <Badge variant="warning">{t('pages.overview.allowedCount', { count: wl.devices.length })}</Badge> : <span className="text-muted-foreground">{t('pages.overview.off')}</span>}
            </Row>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function StatLink({ to, children }: { to: string; children: ReactNode }) {
  return (
    <Link to={to} className="block rounded-xl outline-none transition hover:opacity-90 focus-visible:ring-2 focus-visible:ring-ring">
      {children}
    </Link>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-muted-foreground">{label}</span>
      {children}
    </div>
  );
}

const TONES: Record<string, string> = {
  primary: 'text-primary bg-primary/10',
  danger: 'text-destructive bg-destructive/10',
  warning: 'text-warning bg-warning/15',
  muted: 'text-muted-foreground bg-muted',
};

function Stat({
  icon: Icon,
  label,
  value,
  sub,
  tone,
}: {
  icon: ElementType;
  label: string;
  value: string;
  sub?: string;
  tone: keyof typeof TONES | string;
}) {
  return (
    <Card>
      <CardContent className="flex items-center gap-4 p-5">
        <div className={cn('grid size-11 shrink-0 place-items-center rounded-lg', TONES[tone as string])}>
          <Icon className="size-5" />
        </div>
        <div className="min-w-0">
          <div className="text-xs uppercase tracking-wide text-muted-foreground">{label}</div>
          <div className="truncate text-xl font-bold capitalize leading-tight">{value}</div>
          {sub && <div className="truncate text-xs text-muted-foreground">{sub}</div>}
        </div>
      </CardContent>
    </Card>
  );
}
