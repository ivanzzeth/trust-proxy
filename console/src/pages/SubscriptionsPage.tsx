import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';

import { tp } from '~/api/trustproxy';
import Button from '~/components/Button';

import s from './SubscriptionsPage.module.scss';

const KEY = ['tp', 'subscriptions'];

export default function SubscriptionsPage() {
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

  const addM = useMutation({
    mutationFn: () => tp.addSub(name, url, ua || undefined),
    onSuccess: () => {
      setUrl('');
      setName('');
      setUa('');
      setErr('');
      invalidate();
    },
    onError: onErr,
  });
  const applyM = useMutation({ mutationFn: (id: string) => tp.applySub(id), onSuccess: invalidate, onError: onErr });
  const refreshM = useMutation({ mutationFn: (id: string) => tp.refreshSub(id), onSuccess: invalidate, onError: onErr });
  const delM = useMutation({ mutationFn: (id: string) => tp.delSub(id), onSuccess: invalidate, onError: onErr });
  const busy = addM.isPending || applyM.isPending || refreshM.isPending || delM.isPending;

  return (
    <div className={s.page}>
      <h1 className={s.title}>订阅 / 节点</h1>

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
          placeholder="订阅链接 (https:// 或 file://)"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />
        <input className={s.input} placeholder="名称 (可选)" value={name} onChange={(e) => setName(e.target.value)} />
        <input className={s.input} placeholder="UA (可选)" value={ua} onChange={(e) => setUa(e.target.value)} />
        <Button disabled={busy || !url}>添加</Button>
      </form>

      {err && <div className={s.error}>⚠ {err}</div>}

      <div className={s.tableWrap}>
        <table className={s.table}>
          <thead>
            <tr>
              <th>名称</th>
              <th>节点</th>
              <th>状态</th>
              <th>更新时间</th>
              <th className={s.right}>操作</th>
            </tr>
          </thead>
          <tbody>
            {subs.length === 0 && (
              <tr>
                <td colSpan={5} className={s.empty}>
                  {isLoading ? '加载中…' : '暂无订阅'}
                </td>
              </tr>
            )}
            {subs.map((sub) => (
              <tr key={sub.id}>
                <td>
                  <div className={s.name}>{sub.name || '(未命名)'}</div>
                  <div className={s.url}>{sub.url}</div>
                  {sub.last_error && <div className={s.errInline}>⚠ {sub.last_error}</div>}
                </td>
                <td>{sub.node_count}</td>
                <td>
                  {sub.applied ? (
                    <span className={`${s.badge} ${s.applied}`}>已应用</span>
                  ) : (
                    <span className={s.badge}>未应用</span>
                  )}
                </td>
                <td className={s.muted}>{sub.updated_at ? new Date(sub.updated_at).toLocaleString() : '-'}</td>
                <td>
                  <div className={s.actions}>
                    <Button kind="minimal" disabled={busy || sub.node_count === 0} onClick={() => applyM.mutate(sub.id)}>
                      应用
                    </Button>
                    <Button kind="minimal" disabled={busy} onClick={() => refreshM.mutate(sub.id)}>
                      刷新
                    </Button>
                    <Button kind="minimal" disabled={busy} onClick={() => delM.mutate(sub.id)}>
                      删除
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
