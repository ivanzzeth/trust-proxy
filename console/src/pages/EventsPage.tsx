import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { tp, WLType } from '~/api/trustproxy';
import Button from '~/components/Button';

import s from './SubscriptionsPage.module.scss';

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const u = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(1)} ${u[i]}`;
}

// splitHost extracts the host from "host:port" / "[v6]:port" / bare host.
const splitHost = (hp: string) => {
  if (!hp) return '';
  if (hp.startsWith('[')) {
    const i = hp.indexOf(']');
    return i > 0 ? hp.slice(1, i) : hp;
  }
  const i = hp.lastIndexOf(':');
  return i > 0 && hp.indexOf(':') === i ? hp.slice(0, i) : hp; // only strip a single :port (v4/host)
};
const isIPv4 = (s: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s);
const isIPv6 = (s: string) => s.includes(':') && /^[0-9a-fA-F:]+$/.test(s);
const isIP = (s: string) => isIPv4(s) || isIPv6(s);
const toCIDR = (ip: string) => (ip.includes('/') ? ip : isIPv6(ip) ? `${ip}/128` : `${ip}/32`);

type Tab = 'all' | 'live' | 'closed';

interface Row {
  key: string;
  status: 'live' | 'allowed' | 'denied';
  time?: string;
  host: string;
  dest: string;
  source: string;
  process: string;
  chain: string;
  up: number;
  down: number;
  level: string;
  reasons?: string[];
  liveId?: string;
}

// Connections: one page, three tabs (All / Live / Closed). Blocked attempts show
// up (routed to the block outbound, so our detector records them with the
// sniffed domain) and each row has one-click add-to-whitelist.
export default function ConnectionsPage() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [tab, setTab] = useState<Tab>('all');
  const [alertsOnly, setAlertsOnly] = useState(false);
  const [err, setErr] = useState('');

  const { data: snap } = useQuery({ queryKey: ['tp', 'conns'], queryFn: tp.connections, refetchInterval: 2000 });
  const { data: events = [] } = useQuery({
    queryKey: ['tp', 'events'],
    queryFn: () => tp.events(false),
    refetchInterval: 3000,
  });

  const liveRows: Row[] = (snap?.connections ?? []).map((c) => ({
    key: 'live:' + c.id,
    status: 'live',
    host: c.metadata.host || c.metadata.destinationIP,
    dest: `${c.metadata.destinationIP}:${c.metadata.destinationPort}`,
    source: c.metadata.sourceIP || '',
    process: c.metadata.process || '',
    chain: (c.chains || []).join(' → '),
    up: c.upload,
    down: c.download,
    level: 'info',
    liveId: c.id,
  }));
  const closedRows: Row[] = events.map((e) => ({
    key: 'ev:' + e.id,
    status: e.denied ? 'denied' : 'allowed',
    time: e.time,
    host: e.host,
    dest: e.destination,
    source: splitHost(e.source),
    process: e.process || '',
    chain: `${e.outbound} · ${e.network}`,
    up: e.upload,
    down: e.download,
    level: e.level,
    reasons: e.reasons,
  }));

  const kill = useMutation({
    mutationFn: (id: string) => fetch(`/api/connections/${id}`, { method: 'DELETE' }).then(() => undefined),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['tp', 'conns'] }),
  });
  const killAll = useMutation({
    mutationFn: () => fetch('/api/connections', { method: 'DELETE' }).then(() => undefined),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['tp', 'conns'] }),
  });
  const addWL = useMutation({
    mutationFn: (v: { type: WLType; value: string }) => tp.addWhitelist(v.type, v.value),
    onSuccess: () => {
      setErr('');
      qc.invalidateQueries({ queryKey: ['tp', 'whitelist'] });
      qc.invalidateQueries({ queryKey: ['tp', 'conns'] });
      qc.invalidateQueries({ queryKey: ['tp', 'events'] });
    },
    onError: (e) => setErr(String((e as Error).message)),
  });
  const busy = addWL.isPending;

  let rows = tab === 'live' ? liveRows : tab === 'closed' ? closedRows : [...liveRows, ...closedRows];
  if (alertsOnly) rows = rows.filter((r) => r.level === 'alert');
  const alertCount = closedRows.filter((r) => r.level === 'alert').length;

  const tabBtn = (id: Tab, label: string, n: number) => (
    <button className={tab === id ? s.tabOn : s.tab} onClick={() => setTab(id)}>
      {label} <span className={s.muted}>{n}</span>
    </button>
  );

  const statusCell = (r: Row) => {
    if (r.status === 'live') return <span className={s.badge}>{t('conn_status_live')}</span>;
    if (r.status === 'denied') return <span className={s.errInline}>{t('conn_status_denied')}</span>;
    return <span className={s.muted}>{t('conn_status_allowed')}</span>;
  };

  return (
    <div className={s.page}>
      <div className={s.rowBetween}>
        <h1 className={s.title}>
          {t('conn_title')} {alertCount > 0 && <span className={`${s.badge} ${s.alertBadge}`}>{alertCount}</span>}
        </h1>
        <span className={s.muted}>
          ↑ {fmtBytes(snap?.uploadTotal ?? 0)} · ↓ {fmtBytes(snap?.downloadTotal ?? 0)}
        </span>
      </div>
      {err && <div className={s.error}>⚠ {err}</div>}

      <div className={s.rowBetween}>
        <div className={s.tabs}>
          {tabBtn('all', t('conn_tab_all'), liveRows.length + closedRows.length)}
          {tabBtn('live', t('conn_tab_live'), liveRows.length)}
          {tabBtn('closed', t('conn_tab_closed'), closedRows.length)}
        </div>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <label className={s.muted} style={{ display: 'flex', gap: 6, alignItems: 'center', cursor: 'pointer' }}>
            <input type="checkbox" checked={alertsOnly} onChange={(e) => setAlertsOnly(e.target.checked)} />
            {t('ev_alerts_only')}
          </label>
          {liveRows.length > 0 && (
            <Button kind="minimal" disabled={killAll.isPending} onClick={() => killAll.mutate()}>
              {t('conn_kill_all')}
            </Button>
          )}
        </div>
      </div>

      <div className={s.tableWrap}>
        <table className={s.table}>
          <thead>
            <tr>
              <th>{t('conn_status')}</th>
              <th>{t('ev_time')}</th>
              <th>{t('ev_host')}</th>
              <th>{t('ev_process')}</th>
              <th>{t('ev_up')}</th>
              <th>{t('ev_down')}</th>
              <th>{t('ev_detail')}</th>
              <th>{t('conn_actions')}</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td colSpan={8} className={s.empty}>
                  {t('conn_empty')}
                </td>
              </tr>
            )}
            {rows.map((r) => (
              <tr key={r.key} className={r.level === 'alert' ? s.alertRow : undefined}>
                <td>{statusCell(r)}</td>
                <td className={s.muted}>{r.time ? new Date(r.time).toLocaleTimeString() : '—'}</td>
                <td>
                  {r.level === 'alert' && <span className={s.alertDot}>●</span>} {r.host}
                  <div className={s.muted}>{r.dest}</div>
                </td>
                <td className={s.proc}>{r.process || '-'}</td>
                <td>{fmtBytes(r.up)}</td>
                <td>{fmtBytes(r.down)}</td>
                <td>
                  {r.reasons && r.reasons.length > 0 ? (
                    <span className={s.errInline}>{r.reasons.join('; ')}</span>
                  ) : (
                    <span className={s.muted}>{r.chain}</span>
                  )}
                </td>
                <td className={s.actions}>
                  {r.host && !isIP(r.host) && (
                    <Button kind="minimal" disabled={busy} onClick={() => addWL.mutate({ type: 'domain', value: r.host })}>
                      {t('conn_add_domain')}
                    </Button>
                  )}
                  {isIP(splitHost(r.dest)) && (
                    <Button
                      kind="minimal"
                      disabled={busy}
                      onClick={() => addWL.mutate({ type: 'ip', value: toCIDR(splitHost(r.dest)) })}
                    >
                      {t('conn_add_ip')}
                    </Button>
                  )}
                  {r.process && (
                    <Button
                      kind="minimal"
                      disabled={busy}
                      onClick={() => addWL.mutate({ type: 'process', value: r.process })}
                    >
                      {t('conn_add_proc')}
                    </Button>
                  )}
                  {isIP(r.source) && (
                    <Button kind="minimal" disabled={busy} onClick={() => addWL.mutate({ type: 'device', value: toCIDR(r.source) })}>
                      {t('conn_add_device')}
                    </Button>
                  )}
                  {r.status === 'live' && (
                    <Button kind="minimal" disabled={kill.isPending} onClick={() => kill.mutate(r.liveId!)}>
                      {t('conn_kill')}
                    </Button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
