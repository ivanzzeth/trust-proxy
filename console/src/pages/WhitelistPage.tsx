import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { tp, WLType } from '~/api/trustproxy';
import Button from '~/components/Button';

import s from './SubscriptionsPage.module.scss';

const KEY = ['tp', 'whitelist'];

export default function WhitelistPage() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: KEY });
  const [err, setErr] = useState('');
  const onErr = (e: unknown) => setErr(String((e as Error).message));

  const { data: wl } = useQuery({ queryKey: KEY, queryFn: tp.getWhitelist });

  const [domain, setDomain] = useState('');
  const [ip, setIp] = useState('');
  const [proc, setProc] = useState('');
  const [dev, setDev] = useState('');
  const addM = useMutation({
    mutationFn: (v: { type: WLType; value: string }) => tp.addWhitelist(v.type, v.value),
    onSuccess: () => {
      setDomain('');
      setIp('');
      setProc('');
      setDev('');
      setErr('');
      invalidate();
    },
    onError: onErr,
  });
  const delM = useMutation({
    mutationFn: (v: { type: WLType; value: string }) => tp.delWhitelist(v.type, v.value),
    onSuccess: invalidate,
    onError: onErr,
  });
  const busy = addM.isPending || delM.isPending;

  const heading = (type: WLType) =>
    type === 'domain'
      ? t('wl_domains')
      : type === 'ip'
        ? t('wl_ips')
        : type === 'process'
          ? t('wl_processes')
          : t('wl_devices');

  const list = (type: WLType, items: string[], value: string, setValue: (s: string) => void, ph: string) => (
    <div className={s.wlCol}>
      <h2>{heading(type)}</h2>
      <form
        className={s.pasteRow}
        onSubmit={(e) => {
          e.preventDefault();
          if (value.trim()) addM.mutate({ type, value: value.trim() });
        }}
      >
        <input className={s.input} placeholder={ph} value={value} onChange={(e) => setValue(e.target.value)} />
        <Button disabled={busy || !value.trim()}>{t('wl_add')}</Button>
      </form>
      <div className={s.tableWrap}>
        <table className={s.table}>
          <tbody>
            {items.length === 0 && (
              <tr>
                <td className={s.empty}>{t('wl_empty')}</td>
              </tr>
            )}
            {items.map((it) => (
              <tr key={it}>
                <td>{it}</td>
                <td className={s.right}>
                  <Button kind="minimal" disabled={busy} onClick={() => delM.mutate({ type, value: it })}>
                    {t('sub_delete')}
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );

  return (
    <div className={s.page}>
      <h1 className={s.title}>{t('Whitelist')}</h1>
      <p className={s.muted} style={{ marginBottom: 18 }}>
        {t('wl_hint')}
      </p>
      {err && <div className={s.error}>⚠ {err}</div>}
      <div className={s.wlGrid}>
        {list('domain', wl?.domains ?? [], domain, setDomain, 'example.com')}
        {list('ip', wl?.ips ?? [], ip, setIp, '1.2.3.4/32')}
        {list('process', wl?.processes ?? [], proc, setProc, 'curl / /usr/bin/ssh')}
        {list('device', wl?.devices ?? [], dev, setDev, '192.168.1.20 / 192.168.1.0/24')}
      </div>
      <p className={s.muted} style={{ marginTop: 12 }}>
        {t('wl_process_hint')}
      </p>
      <p className={s.muted} style={{ marginTop: 8 }}>
        {t('wl_device_hint')}
      </p>
    </div>
  );
}
