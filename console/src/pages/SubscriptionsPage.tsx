import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { tp } from '~/api/trustproxy';
import Button from '~/components/Button';

import s from './SubscriptionsPage.module.scss';

const KEY = ['tp', 'subscriptions'];
const PROTOCOLS = ['anytls', 'vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'tuic'];
const SS_CIPHERS = ['aes-256-gcm', 'aes-128-gcm', 'chacha20-ietf-poly1305', '2022-blake3-aes-256-gcm'];

type Manual = {
  protocol: string;
  name: string;
  server: string;
  port: string;
  uuid: string;
  password: string;
  cipher: string;
  alterId: string;
  tls: boolean;
  sni: string;
  fingerprint: string;
  skipCertVerify: boolean;
  flow: string;
  pubkey: string;
  shortid: string;
  network: string;
  wsPath: string;
  wsHost: string;
};

const emptyManual: Manual = {
  protocol: 'anytls',
  name: '',
  server: '',
  port: '',
  uuid: '',
  password: '',
  cipher: 'aes-256-gcm',
  alterId: '0',
  tls: true,
  sni: '',
  fingerprint: 'chrome',
  skipCertVerify: false,
  flow: '',
  pubkey: '',
  shortid: '',
  network: 'tcp',
  wsPath: '',
  wsHost: '',
};

// build a Clash-style proxy dict from the form; the backend parser turns it
// into a sing-box outbound (handles all these protocols).
function buildClashDict(m: Manual): Record<string, unknown> {
  const d: Record<string, unknown> = {
    name: m.name || `${m.protocol}-${m.server}`,
    type: m.protocol,
    server: m.server,
    port: Number(m.port) || 0,
  };
  if (['vless', 'vmess', 'tuic'].includes(m.protocol)) d.uuid = m.uuid;
  if (['trojan', 'shadowsocks', 'hysteria2', 'anytls', 'tuic'].includes(m.protocol)) d.password = m.password;
  if (m.protocol === 'shadowsocks') d.cipher = m.cipher;
  if (m.protocol === 'vmess') d.alterId = Number(m.alterId) || 0;

  const tlsProto = m.protocol !== 'shadowsocks';
  if (tlsProto && (m.tls || m.protocol === 'anytls' || m.protocol === 'trojan' || m.protocol === 'hysteria2' || m.protocol === 'tuic')) {
    if (m.protocol === 'vless' || m.protocol === 'vmess') d.tls = true;
    if (m.sni) d.sni = m.sni;
    if (m.fingerprint) d['client-fingerprint'] = m.fingerprint;
    if (m.skipCertVerify) d['skip-cert-verify'] = true;
  }
  if (m.protocol === 'vless') {
    if (m.flow) d.flow = m.flow;
    if (m.pubkey) d['reality-opts'] = { 'public-key': m.pubkey, 'short-id': m.shortid };
  }
  if ((m.protocol === 'vless' || m.protocol === 'vmess' || m.protocol === 'trojan') && m.network && m.network !== 'tcp') {
    d.network = m.network;
    if (m.network === 'ws') d['ws-opts'] = { path: m.wsPath || '/', headers: m.wsHost ? { Host: m.wsHost } : undefined };
  }
  return d;
}

export default function SubscriptionsPage() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: KEY });
  const [err, setErr] = useState('');
  const onErr = (e: unknown) => setErr(String((e as Error).message));

  const { data: subs = [], isLoading } = useQuery({ queryKey: KEY, queryFn: tp.listSubs, refetchInterval: 5000 });

  const [mode, setMode] = useState<'manual' | 'paste' | 'url'>('manual');

  // manual form
  const [m, setM] = useState<Manual>(emptyManual);
  const setField = (k: keyof Manual, v: string | boolean) => setM((p) => ({ ...p, [k]: v }));
  const manualM = useMutation({
    mutationFn: () => tp.importNodes(m.name, JSON.stringify(buildClashDict(m))),
    onSuccess: () => {
      setM(emptyManual);
      setErr('');
      invalidate();
    },
    onError: onErr,
  });

  // paste
  const [pasteName, setPasteName] = useState('');
  const [pasteContent, setPasteContent] = useState('');
  const pasteM = useMutation({
    mutationFn: () => tp.importNodes(pasteName, pasteContent),
    onSuccess: () => {
      setPasteName('');
      setPasteContent('');
      setErr('');
      invalidate();
    },
    onError: onErr,
  });

  // subscription url
  const [url, setUrl] = useState('');
  const [urlName, setUrlName] = useState('');
  const [via, setVia] = useState('');
  const addM = useMutation({
    mutationFn: () => tp.addSub(urlName, url, undefined, via || undefined),
    onSuccess: () => {
      setUrl('');
      setUrlName('');
      setVia('');
      setErr('');
      invalidate();
    },
    onError: onErr,
  });

  const applyM = useMutation({ mutationFn: (id: string) => tp.applySub(id), onSuccess: invalidate, onError: onErr });
  const refreshM = useMutation({ mutationFn: (id: string) => tp.refreshSub(id), onSuccess: invalidate, onError: onErr });
  const delM = useMutation({ mutationFn: (id: string) => tp.delSub(id), onSuccess: invalidate, onError: onErr });
  const busy =
    manualM.isPending || pasteM.isPending || addM.isPending || applyM.isPending || refreshM.isPending || delM.isPending;

  const has = (protos: string[]) => protos.includes(m.protocol);

  return (
    <div className={s.page}>
      <h1 className={s.title}>{t('Subscriptions')}</h1>

      <div className={s.addCard}>
        <div className={s.tabs}>
          <button className={mode === 'manual' ? s.tabOn : s.tab} onClick={() => setMode('manual')}>
            {t('add_mode_manual')}
          </button>
          <button className={mode === 'paste' ? s.tabOn : s.tab} onClick={() => setMode('paste')}>
            {t('add_mode_paste')}
          </button>
          <button className={mode === 'url' ? s.tabOn : s.tab} onClick={() => setMode('url')}>
            {t('add_mode_url')}
          </button>
        </div>

        {mode === 'manual' && (
          <div className={s.form}>
            <div className={s.grid}>
              <label className={s.field}>
                <span>{t('f_protocol')}</span>
                <select className={s.input} value={m.protocol} onChange={(e) => setField('protocol', e.target.value)}>
                  {PROTOCOLS.map((p) => (
                    <option key={p} value={p}>
                      {p}
                    </option>
                  ))}
                </select>
              </label>
              <label className={s.field}>
                <span>{t('f_name')}</span>
                <input className={s.input} value={m.name} onChange={(e) => setField('name', e.target.value)} />
              </label>
              <label className={s.field}>
                <span>{t('f_server')}</span>
                <input className={s.input} value={m.server} onChange={(e) => setField('server', e.target.value)} />
              </label>
              <label className={s.field}>
                <span>{t('f_port')}</span>
                <input className={s.input} value={m.port} onChange={(e) => setField('port', e.target.value)} />
              </label>

              {has(['vless', 'vmess', 'tuic']) && (
                <label className={s.field}>
                  <span>UUID</span>
                  <input className={s.input} value={m.uuid} onChange={(e) => setField('uuid', e.target.value)} />
                </label>
              )}
              {has(['trojan', 'shadowsocks', 'hysteria2', 'anytls', 'tuic']) && (
                <label className={s.field}>
                  <span>{t('f_password')}</span>
                  <input className={s.input} value={m.password} onChange={(e) => setField('password', e.target.value)} />
                </label>
              )}
              {has(['shadowsocks']) && (
                <label className={s.field}>
                  <span>{t('f_cipher')}</span>
                  <select className={s.input} value={m.cipher} onChange={(e) => setField('cipher', e.target.value)}>
                    {SS_CIPHERS.map((c) => (
                      <option key={c} value={c}>
                        {c}
                      </option>
                    ))}
                  </select>
                </label>
              )}
              {has(['vmess']) && (
                <label className={s.field}>
                  <span>alterId</span>
                  <input className={s.input} value={m.alterId} onChange={(e) => setField('alterId', e.target.value)} />
                </label>
              )}

              {m.protocol !== 'shadowsocks' && (
                <>
                  <label className={s.field}>
                    <span>{t('f_sni')}</span>
                    <input className={s.input} value={m.sni} onChange={(e) => setField('sni', e.target.value)} />
                  </label>
                  <label className={s.field}>
                    <span>{t('f_fingerprint')}</span>
                    <input
                      className={s.input}
                      value={m.fingerprint}
                      onChange={(e) => setField('fingerprint', e.target.value)}
                    />
                  </label>
                  <label className={`${s.field} ${s.check}`}>
                    <input
                      type="checkbox"
                      checked={m.skipCertVerify}
                      onChange={(e) => setField('skipCertVerify', e.target.checked)}
                    />
                    <span>{t('f_skip_cert')}</span>
                  </label>
                </>
              )}

              {has(['vless']) && (
                <>
                  <label className={s.field}>
                    <span>flow</span>
                    <input className={s.input} value={m.flow} onChange={(e) => setField('flow', e.target.value)} />
                  </label>
                  <label className={s.field}>
                    <span>reality public-key</span>
                    <input className={s.input} value={m.pubkey} onChange={(e) => setField('pubkey', e.target.value)} />
                  </label>
                  <label className={s.field}>
                    <span>reality short-id</span>
                    <input className={s.input} value={m.shortid} onChange={(e) => setField('shortid', e.target.value)} />
                  </label>
                </>
              )}

              {has(['vless', 'vmess', 'trojan']) && (
                <label className={s.field}>
                  <span>{t('f_network')}</span>
                  <select className={s.input} value={m.network} onChange={(e) => setField('network', e.target.value)}>
                    <option value="tcp">tcp</option>
                    <option value="ws">ws</option>
                    <option value="grpc">grpc</option>
                  </select>
                </label>
              )}
              {m.network === 'ws' && has(['vless', 'vmess', 'trojan']) && (
                <>
                  <label className={s.field}>
                    <span>ws path</span>
                    <input className={s.input} value={m.wsPath} onChange={(e) => setField('wsPath', e.target.value)} />
                  </label>
                  <label className={s.field}>
                    <span>ws host</span>
                    <input className={s.input} value={m.wsHost} onChange={(e) => setField('wsHost', e.target.value)} />
                  </label>
                </>
              )}
            </div>
            <Button disabled={busy || !m.server || !m.port} onClick={() => manualM.mutate()}>
              {t('btn_add_node')}
            </Button>
          </div>
        )}

        {mode === 'paste' && (
          <div className={s.form}>
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
              <Button disabled={busy || !pasteContent.trim()} onClick={() => pasteM.mutate()}>
                {t('sub_import')}
              </Button>
            </div>
          </div>
        )}

        {mode === 'url' && (
          <form
            className={s.form}
            onSubmit={(e) => {
              e.preventDefault();
              if (url) addM.mutate();
            }}
          >
            <div className={s.pasteRow}>
              <input
                className={s.input}
                style={{ flex: 3 }}
                placeholder={t('sub_url_ph')}
                value={url}
                onChange={(e) => setUrl(e.target.value)}
              />
              <input className={s.input} placeholder={t('sub_name_ph')} value={urlName} onChange={(e) => setUrlName(e.target.value)} />
            </div>
            <div className={s.pasteRow}>
              <input className={s.input} placeholder={t('sub_via_ph')} value={via} onChange={(e) => setVia(e.target.value)} />
              <Button disabled={busy || !url}>{t('sub_add')}</Button>
            </div>
          </form>
        )}
      </div>

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
                  <div className={s.url}>{sub.url || t('sub_manual_src')}</div>
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
