import { useEffect, useState } from 'react'
import { api, type Subscription } from '../api'

export default function Subscriptions() {
  const [subs, setSubs] = useState<Subscription[]>([])
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [url, setUrl] = useState('')
  const [name, setName] = useState('')
  const [ua, setUa] = useState('')

  const load = () =>
    api
      .listSubs()
      .then(setSubs)
      .catch((e) => setErr(String(e.message)))

  useEffect(() => {
    load()
  }, [])

  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true)
    setErr('')
    try {
      await fn()
      await load()
    } catch (e) {
      setErr(String((e as Error).message))
    } finally {
      setBusy(false)
    }
  }

  const add = (e: React.FormEvent) => {
    e.preventDefault()
    if (!url) return
    run(async () => {
      await api.addSub(name, url, ua || undefined)
      setUrl('')
      setName('')
      setUa('')
    })
  }

  return (
    <section>
      <h2>订阅</h2>
      <form className="card add-form" onSubmit={add}>
        <input placeholder="订阅链接 (https:// 或 file://)" value={url} onChange={(e) => setUrl(e.target.value)} />
        <input placeholder="名称 (可选)" value={name} onChange={(e) => setName(e.target.value)} />
        <input placeholder="User-Agent (可选)" value={ua} onChange={(e) => setUa(e.target.value)} />
        <button type="submit" disabled={busy || !url}>
          添加
        </button>
      </form>

      {err && <div className="error">⚠ {err}</div>}

      <table className="grid">
        <thead>
          <tr>
            <th>名称</th>
            <th>节点</th>
            <th>状态</th>
            <th>更新时间</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          {subs.length === 0 && (
            <tr>
              <td colSpan={5} className="empty">
                暂无订阅
              </td>
            </tr>
          )}
          {subs.map((s) => (
            <tr key={s.id}>
              <td>
                <div className="name">{s.name || '(未命名)'}</div>
                <div className="muted url">{s.url}</div>
                {s.last_error && <div className="error-inline">⚠ {s.last_error}</div>}
              </td>
              <td>{s.node_count}</td>
              <td>{s.applied ? <span className="badge applied">已应用</span> : <span className="badge">未应用</span>}</td>
              <td className="muted">{s.updated_at ? new Date(s.updated_at).toLocaleString() : '-'}</td>
              <td className="actions">
                <button disabled={busy || s.node_count === 0} onClick={() => run(() => api.applySub(s.id))}>
                  应用
                </button>
                <button disabled={busy} onClick={() => run(() => api.refreshSub(s.id))}>
                  刷新
                </button>
                <button className="danger" disabled={busy} onClick={() => run(() => api.delSub(s.id))}>
                  删除
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}
