import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { tp } from '~/api/trustproxy';
import Button from '~/components/Button';

import s from './SubscriptionsPage.module.scss';

const KEY = ['tp', 'subscriptions'];

export default function SubscriptionsPage() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: KEY });
  const [err, setErr] = useState('');
  const onErr = (e: unknown) => setErr(String((e as Error).message));

  const { data: subs = [], isLoading } = useQuery({
    queryKey: KEY,
    queryFn: tp.listSubs,
    refetchInterval: 5000,
  });

  const [url, setUrl] = useState('');
  const [name, setName] = useState('');
  const [ua, setUa] = useState('');
  const [via, setVia] = useState('');

  const addM = useMutation({
    mutationFn: () => tp.addSub(name, url, ua || undefined, via || undefined),
    onSuccess: () => {
      setUrl('');
      setName('');
      setUa('');
      setVia('');
      setErr('');
      invalidate();
    },
    onError: onErr,
  });
  const [pasteName, setPasteName] = useState('');
  const [pasteContent, setPasteContent] = useState('');
  const importM = useMutation({
    mutationFn: () => tp.importNodes(pasteName, pasteContent),
    onSuccess: () => {
      setPasteName('');
      setPasteContent('');
      setErr('');
      invalidate();
    },
    onError: onErr,
  });

  const applyM = useMutation({ mutationFn: (id: string) => tp.applySub(id), onSuccess: invalidate, onError: onErr });
  const refreshM = useMutation({ mutationFn: (id: string) => tp.refreshSub(id), onSuccess: invalidate, onError: onErr });
  const delM = useMutation({ mutationFn: (id: string) => tp.delSub(id), onSuccess: invalidate, onError: onErr });
  const busy = addM.isPending || importM.isPending || applyM.isPending || refreshM.isPending || delM.isPending;

  return (
    <div className={s.page}>
      <h1 className={s.title}>{t('Subscriptions')}</h1>

      <form
        className={s.addForm}
        onSubmit={(e) => {
          e.preventDefault();
          if (url) addM.mutate();
        }}
      >
        <input
          className={s.input}
          style={{ flex: 3 }}
          placeholder={t('sub_url_ph')}
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />
        <input className={s.input} placeholder={t('sub_name_ph')} value={name} onChange={(e) => setName(e.target.value)} />
        <input className={s.input} placeholder={t('sub_ua_ph')} value={ua} onChange={(e) => setUa(e.target.value)} />
        <input className={s.input} placeholder={t('sub_via_ph')} value={via} onChange={(e) => setVia(e.target.value)} />
        <Button disabled={busy || !url}>{t('sub_add')}</Button>
      </form>

      <details className={s.paste}>
        <summary>{t('sub_paste_title')}</summary>
        <textarea
          className={s.textarea}
          placeholder={t('sub_paste_ph')}
          value={pasteContent}
          onChange={(e) => setPasteContent(e.target.value)}
          rows={5}
        />
        <div className={s.pasteRow}>
          <input
            className={s.input}
            placeholder={t('sub_name_ph')}
            value={pasteName}
            onChange={(e) => setPasteName(e.target.value)}
          />
          <Button disabled={busy || !pasteContent.trim()} onClick={() => importM.mutate()}>
            {t('sub_import')}
          </Button>
        </div>
      </details>

      {err && <div className={s.error}>⚠ {err}</div>}

      <div className={s.tableWrap}>
        <table className={s.table}>
          <thead>
            <tr>
              <th>{t('sub_name')}</th>
              <th>{t('sub_nodes')}</th>
              <th>{t('sub_status')}</th>
              <th>{t('sub_updated')}</th>
              <th className={s.right}>{t('sub_actions')}</th>
            </tr>
          </thead>
          <tbody>
            {subs.length === 0 && (
              <tr>
                <td colSpan={5} className={s.empty}>
                  {isLoading ? t('sub_loading') : t('sub_empty')}
                </td>
              </tr>
            )}
            {subs.map((sub) => (
              <tr key={sub.id}>
                <td>
                  <div className={s.name}>{sub.name || t('sub_unnamed')}</div>
                  <div className={s.url}>{sub.url}</div>
                  {sub.last_error && <div className={s.errInline}>⚠ {sub.last_error}</div>}
                </td>
                <td>{sub.node_count}</td>
                <td>
                  {sub.applied ? (
                    <span className={`${s.badge} ${s.applied}`}>{t('sub_applied')}</span>
                  ) : (
                    <span className={s.badge}>{t('sub_not_applied')}</span>
                  )}
                </td>
                <td className={s.muted}>{sub.updated_at ? new Date(sub.updated_at).toLocaleString() : '-'}</td>
                <td>
                  <div className={s.actions}>
                    <Button kind="minimal" disabled={busy || sub.node_count === 0} onClick={() => applyM.mutate(sub.id)}>
                      {t('sub_apply')}
                    </Button>
                    <Button kind="minimal" disabled={busy} onClick={() => refreshM.mutate(sub.id)}>
                      {t('sub_refresh')}
                    </Button>
                    <Button kind="minimal" disabled={busy} onClick={() => delM.mutate(sub.id)}>
                      {t('sub_delete')}
                    </Button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
