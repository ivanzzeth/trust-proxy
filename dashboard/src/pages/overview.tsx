import { type ElementType, type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { AlertTriangle, Ban, Radio, ShieldAlert, Waypoints } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { api } from '@/lib/api';
import { cn, fmtBytes } from '@/lib/utils';
import { PageHeader } from '@/components/page-header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

export default function Overview() {
  const { t } = useTranslation();
  const { data: st } = useQuery({ queryKey: ['status'], queryFn: api.status, refetchInterval: 5000 });
  const { data: snap } = useQuery({ queryKey: ['conns'], queryFn: api.connections, refetchInterval: 2000 });
  const { data: events = [] } = useQuery({ queryKey: ['events'], queryFn: () => api.events(false), refetchInterval: 3000 });
  const { data: subs = [] } = useQuery({ queryKey: ['subs'], queryFn: api.subs });
  const { data: wl } = useQuery({ queryKey: ['whitelist'], queryFn: api.whitelist });

  const live = snap?.connections?.length ?? 0;
  const alerts = events.filter((e) => e.level === 'alert');
  const denied = events.filter((e) => e.denied).length;
  const appliedSub = subs.find((s) => s.applied);

  return (
    <div>
      <PageHeader title={t('pages.overview.title')} description={t('pages.overview.description')} />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Stat
          icon={Radio}
          label={t('pages.overview.captureMode')}
          value={st ? st.mode : '—'}
          sub={st?.autoBlock ? t('pages.overview.autoBlockOn') : t('pages.overview.autoBlockOff')}
          tone={st?.autoBlock ? 'primary' : 'muted'}
        />
        <Stat
          icon={Waypoints}
          label={t('pages.overview.liveConnections')}
          value={String(live)}
          sub={`↑ ${fmtBytes(snap?.uploadTotal ?? 0)} · ↓ ${fmtBytes(snap?.downloadTotal ?? 0)}`}
          tone="primary"
        />
        <Stat
          icon={ShieldAlert}
          label={t('pages.overview.alerts')}
          value={String(alerts.length)}
          sub={t('pages.overview.blockedAttempts', { count: denied })}
          tone={alerts.length ? 'danger' : 'muted'}
        />
        <Stat
          icon={Ban}
          label={t('pages.overview.threatIntel')}
          value={st ? String(st.threats.domains + st.threats.ips) : '—'}
          sub={st ? t('pages.overview.domainsAndIps', { domains: st.threats.domains, ips: st.threats.ips }) : ''}
          tone="warning"
        />
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader className="flex-row items-center justify-between">
            <CardTitle className="flex items-center gap-2 text-sm">
              <AlertTriangle className="size-4 text-destructive" /> {t('pages.overview.recentAlerts')}
            </CardTitle>
            <Link to="/connections" className="text-xs text-primary hover:underline">
              {t('pages.overview.viewAll')}
            </Link>
          </CardHeader>
          <CardContent className="pt-0">
            {alerts.length === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">{t('pages.overview.noAlerts')}</p>
            ) : (
              <div className="divide-y divide-border/60">
                {alerts.slice(0, 8).map((e) => (
                  <div key={e.id} className="flex items-center gap-3 py-2.5">
                    <span className="size-1.5 shrink-0 rounded-full bg-destructive" />
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-sm font-medium">{e.host}</div>
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
