import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { tp } from '~/api/trustproxy';

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

export default function EventsPage() {
  const { t } = useTranslation();
  const [alertsOnly, setAlertsOnly] = useState(false);
  const { data: events = [] } = useQuery({
    queryKey: ['tp', 'events', alertsOnly],
    queryFn: () => tp.events(alertsOnly),
    refetchInterval: 3000,
  });

  const alertCount = events.filter((e) => e.level === 'alert').length;

  return (
    <div className={s.page}>
      <div className={s.rowBetween}>
        <h1 className={s.title}>
          {t('Alerts')} {alertCount > 0 && <span className={`${s.badge} ${s.alertBadge}`}>{alertCount}</span>}
        </h1>
        <label className={s.muted} style={{ display: 'flex', gap: 6, alignItems: 'center', cursor: 'pointer' }}>
          <input type="checkbox" checked={alertsOnly} onChange={(e) => setAlertsOnly(e.target.checked)} />
          {t('ev_alerts_only')}
        </label>
      </div>
      <p className={s.muted} style={{ marginBottom: 16 }}>
        {t('ev_hint')}
      </p>

      <div className={s.tableWrap}>
        <table className={s.table}>
          <thead>
            <tr>
              <th>{t('ev_time')}</th>
              <th>{t('ev_host')}</th>
              <th>{t('ev_process')}</th>
              <th>{t('ev_up')}</th>
              <th>{t('ev_down')}</th>
              <th>{t('ev_detail')}</th>
            </tr>
          </thead>
          <tbody>
            {events.length === 0 && (
              <tr>
                <td colSpan={6} className={s.empty}>
                  {t('ev_empty')}
                </td>
              </tr>
            )}
            {events.map((e) => (
              <tr key={e.id} className={e.level === 'alert' ? s.alertRow : undefined}>
                <td className={s.muted}>{new Date(e.time).toLocaleTimeString()}</td>
                <td>
                  {e.level === 'alert' && <span className={s.alertDot}>●</span>} {e.host}
                  <div className={s.muted}>{e.destination}</div>
                </td>
                <td className={s.proc}>{e.process || '-'}</td>
                <td>{fmtBytes(e.upload)}</td>
                <td>{fmtBytes(e.download)}</td>
                <td>
                  {e.reasons && e.reasons.length > 0 ? (
                    <span className={s.errInline}>{e.reasons.join('; ')}</span>
                  ) : (
                    <span className={s.muted}>
                      {e.outbound} · {e.network}
                    </span>
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
