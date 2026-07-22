import { type ElementType, type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { AlertTriangle, Ban, Radio, ShieldAlert, Waypoints } from 'lucide-react';

import { api } from '@/lib/api';
import { cn, fmtBytes } from '@/lib/utils';
import { PageHeader } from '@/components/page-header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

export default function Overview() {
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
      <PageHeader title="Overview" description="Gateway posture at a glance — traffic, detections, and active policy." />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Stat
          icon={Radio}
          label="Capture mode"
          value={st ? st.mode : '—'}
          sub={st?.autoBlock ? 'auto-block on' : 'auto-block off'}
          tone={st?.autoBlock ? 'primary' : 'muted'}
        />
        <Stat
          icon={Waypoints}
          label="Live connections"
          value={String(live)}
          sub={`↑ ${fmtBytes(snap?.uploadTotal ?? 0)} · ↓ ${fmtBytes(snap?.downloadTotal ?? 0)}`}
          tone="primary"
        />
        <Stat
          icon={ShieldAlert}
          label="Alerts"
          value={String(alerts.length)}
          sub={`${denied} blocked attempts`}
          tone={alerts.length ? 'danger' : 'muted'}
        />
        <Stat
          icon={Ban}
          label="Threat intel"
          value={st ? String(st.threats.domains + st.threats.ips) : '—'}
          sub={st ? `${st.threats.domains} domains · ${st.threats.ips} IPs` : ''}
          tone="warning"
        />
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader className="flex-row items-center justify-between">
            <CardTitle className="flex items-center gap-2 text-sm">
              <AlertTriangle className="size-4 text-destructive" /> Recent alerts
            </CardTitle>
            <Link to="/connections" className="text-xs text-primary hover:underline">
              View all →
            </Link>
          </CardHeader>
          <CardContent className="pt-0">
            {alerts.length === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">No alerts — all clear.</p>
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
            <CardTitle className="text-sm">Active policy</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 pt-0 text-sm">
            <Row label="Exit node">
              {appliedSub ? <Badge variant="success">{appliedSub.name}</Badge> : <span className="text-muted-foreground">direct</span>}
            </Row>
            <Row label="Whitelisted domains"><span className="tnum">{wl?.domains.length ?? 0}</span></Row>
            <Row label="Whitelisted IPs"><span className="tnum">{wl?.ips.length ?? 0}</span></Row>
            <Row label="Process gate">
              {wl?.processes.length ? <Badge variant="warning">{wl.processes.length} allowed</Badge> : <span className="text-muted-foreground">off</span>}
            </Row>
            <Row label="Device gate">
              {wl?.devices.length ? <Badge variant="warning">{wl.devices.length} allowed</Badge> : <span className="text-muted-foreground">off</span>}
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
