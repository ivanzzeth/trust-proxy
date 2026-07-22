import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { tp } from '~/api/trustproxy';
import Button from '~/components/Button';

import s from './SubscriptionsPage.module.scss';

const KEY = ['tp', 'profiles'];

export default function ProfilesPage() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const invalidate = () => {
    // After a switch, other pages' state changed too.
    for (const k of [['tp', 'profiles'], ['tp', 'rulesets'], ['tp', 'whitelist'], ['tp', 'status'], ['tp', 'subs']]) {
      qc.invalidateQueries({ queryKey: k });
    }
  };
  const [err, setErr] = useState('');
  const [name, setName] = useState('');
  const onErr = (e: unknown) => setErr(String((e as Error).message));

  const { data: profiles } = useQuery({ queryKey: KEY, queryFn: tp.listProfiles });

  const addM = useMutation({
    mutationFn: (n: string) => tp.addProfile(n),
    onSuccess: () => {
      setName('');
      setErr('');
      invalidate();
    },
    onError: onErr,
  });
  const actM = useMutation({ mutationFn: (id: string) => tp.activateProfile(id), onSuccess: invalidate, onError: onErr });
  const delM = useMutation({ mutationFn: (id: string) => tp.delProfile(id), onSuccess: invalidate, onError: onErr });
  const busy = addM.isPending || actM.isPending || delM.isPending;

  return (
    <div className={s.page}>
      <h1 className={s.title}>{t('prof_title')}</h1>
      <p className={s.muted}>{t('prof_hint')}</p>
      {err && <div className={s.errInline}>{err}</div>}

      <form
        className={s.pasteRow}
        onSubmit={(e) => {
          e.preventDefault();
          if (name.trim()) addM.mutate(name.trim());
        }}
      >
        <input className={s.input} placeholder={t('prof_name')} value={name} onChange={(e) => setName(e.target.value)} />
        <Button disabled={busy || !name.trim()}>{t('prof_save_current')}</Button>
      </form>

      <div className={s.tableWrap}>
        <table className={s.table}>
          <tbody>
            {(!profiles || profiles.length === 0) && (
              <tr>
                <td className={s.empty}>{t('prof_empty')}</td>
              </tr>
            )}
            {(profiles || []).map((p) => (
              <tr key={p.id}>
                <td className={s.name}>
                  {p.name} {p.active && <span className={s.badge}>{t('prof_active')}</span>}
                </td>
                <td className={s.muted}>
                  {t('prof_summary', {
                    domains: p.whitelist?.domains?.length ?? 0,
                    ips: p.whitelist?.ips?.length ?? 0,
                    rulesets: p.ruleset_tags?.length ?? 0,
                    mode: p.mode || '-',
                  })}
                </td>
                <td className={s.actions}>
                  <Button disabled={busy || p.active} onClick={() => actM.mutate(p.id)}>
                    {t('prof_activate')}
                  </Button>
                  <Button disabled={busy} onClick={() => delM.mutate(p.id)}>
                    {t('delete')}
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
