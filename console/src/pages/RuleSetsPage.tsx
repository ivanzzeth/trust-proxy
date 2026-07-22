import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { tp, TPRuleSetCatalogEntry } from '~/api/trustproxy';
import Button from '~/components/Button';

import s from './SubscriptionsPage.module.scss';

const KEY = ['tp', 'rulesets'];
const CATALOG_KEY = ['tp', 'rulesets', 'catalog'];
const ROLES = ['block', 'allow-direct', 'allow-proxy'];

export default function RuleSetsPage() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: KEY });
  const [err, setErr] = useState('');
  const onErr = (e: unknown) => setErr(String((e as Error).message));

  const { data: sets } = useQuery({ queryKey: KEY, queryFn: tp.listRuleSets });
  const { data: catalog } = useQuery({ queryKey: CATALOG_KEY, queryFn: tp.ruleSetCatalog });

  const addM = useMutation({
    mutationFn: (body: Record<string, unknown>) => tp.addRuleSet(body),
    onSuccess: () => {
      setErr('');
      invalidate();
    },
    onError: onErr,
  });
  const patchM = useMutation({
    mutationFn: (v: { tag: string; patch: { enabled?: boolean; role?: string } }) => tp.patchRuleSet(v.tag, v.patch),
    onSuccess: invalidate,
    onError: onErr,
  });
  const delM = useMutation({
    mutationFn: (tag: string) => tp.delRuleSet(tag),
    onSuccess: invalidate,
    onError: onErr,
  });
  const busy = addM.isPending || patchM.isPending || delM.isPending;

  const importCatalog = (e: TPRuleSetCatalogEntry, mirror: boolean) =>
    addM.mutate({ catalog_tag: e.tag, mirror });

  // manual add form
  const [mTag, setMTag] = useState('');
  const [mUrl, setMUrl] = useState('');
  const [mRole, setMRole] = useState('allow-proxy');

  return (
    <div className={s.page}>
      <h1 className={s.title}>{t('rs_title')}</h1>
      {err && <div className={s.errInline}>{err}</div>}

      <h2>{t('rs_catalog')}</h2>
      <div className={s.tableWrap}>
        <table className={s.table}>
          <tbody>
            {(catalog || []).map((e) => (
              <tr key={e.tag}>
                <td className={s.name}>{e.name}</td>
                <td className={s.muted}>{e.tag}</td>
                <td>
                  <span className={s.badge}>{e.suggested_role}</span>
                </td>
                <td className={s.actions}>
                  <Button disabled={busy} onClick={() => importCatalog(e, false)}>
                    {t('rs_import')}
                  </Button>
                  <Button disabled={busy} onClick={() => importCatalog(e, true)}>
                    {t('rs_import_mirror')}
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h2>{t('rs_manual')}</h2>
      <form
        className={s.pasteRow}
        onSubmit={(ev) => {
          ev.preventDefault();
          if (!mTag.trim() || !mUrl.trim()) return;
          addM.mutate({ tag: mTag.trim(), url: mUrl.trim(), role: mRole, type: 'remote' });
          setMTag('');
          setMUrl('');
        }}
      >
        <input className={s.input} placeholder={t('rs_tag')} value={mTag} onChange={(e) => setMTag(e.target.value)} />
        <input className={s.input} placeholder="https://…/xxx.srs" value={mUrl} onChange={(e) => setMUrl(e.target.value)} />
        <select className={s.input} value={mRole} onChange={(e) => setMRole(e.target.value)}>
          {ROLES.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
        <Button disabled={busy || !mTag.trim() || !mUrl.trim()}>{t('rs_add')}</Button>
      </form>

      <h2>{t('rs_imported')}</h2>
      <div className={s.tableWrap}>
        <table className={s.table}>
          <tbody>
            {(!sets || sets.sets.length === 0) && (
              <tr>
                <td className={s.empty}>{t('rs_empty')}</td>
              </tr>
            )}
            {(sets?.sets || []).map((rs) => (
              <tr key={rs.tag}>
                <td>
                  <input
                    type="checkbox"
                    checked={rs.enabled}
                    disabled={busy}
                    onChange={(e) => patchM.mutate({ tag: rs.tag, patch: { enabled: e.target.checked } })}
                  />
                </td>
                <td className={s.name}>{rs.name}</td>
                <td>
                  <select
                    className={s.input}
                    value={rs.role}
                    disabled={busy}
                    onChange={(e) => patchM.mutate({ tag: rs.tag, patch: { role: e.target.value } })}
                  >
                    {ROLES.map((r) => (
                      <option key={r} value={r}>
                        {r}
                      </option>
                    ))}
                  </select>
                </td>
                <td className={s.url}>{rs.url || rs.path}</td>
                <td className={s.actions}>
                  <Button disabled={busy} onClick={() => delM.mutate(rs.tag)}>
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
