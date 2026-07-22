import { useEffect, useRef, useState } from 'react'
import { api, fmtBytes, type Conn } from '../api'

export default function Connections() {
  const [conns, setConns] = useState<Conn[]>([])
  const [totals, setTotals] = useState({ up: 0, down: 0 })
  const [err, setErr] = useState('')
  const [paused, setPaused] = useState(false)
  const pausedRef = useRef(paused)
  pausedRef.current = paused

  const load = async () => {
    if (pausedRef.current) return
    try {
      const snap = await api.connections()
      setConns(snap.connections ?? [])
      setTotals({ up: snap.uploadTotal, down: snap.downloadTotal })
      setErr('')
    } catch (e) {
      setErr(String((e as Error).message))
    }
  }

  useEffect(() => {
    load()
    const t = setInterval(load, 2000)
    return () => clearInterval(t)
  }, [])

  const kill = async (id: string) => {
    try {
      await api.killConn(id)
      await load()
    } catch (e) {
      setErr(String((e as Error).message))
    }
  }

  return (
    <section>
      <div className="row-between">
        <h2>连接 ({conns.length})</h2>
        <div className="conn-tools">
          <span className="muted">
            ↑ {fmtBytes(totals.up)} · ↓ {fmtBytes(totals.down)}
          </span>
          <button onClick={() => setPaused((p) => !p)}>{paused ? '继续' : '暂停'}</button>
          <button className="danger" onClick={() => api.killAll().then(load)}>
            全部断开
          </button>
        </div>
      </div>

      {err && <div className="error">⚠ {err}</div>}

      <table className="grid">
        <thead>
          <tr>
            <th>目标</th>
            <th>网络</th>
            <th>进程</th>
            <th>↑</th>
            <th>↓</th>
            <th>出站链</th>
            <th>规则</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {conns.length === 0 && (
            <tr>
              <td colSpan={8} className="empty">
                无活动连接
              </td>
            </tr>
          )}
          {conns.map((c) => {
            const host = c.metadata.host || `${c.metadata.destinationIP}:${c.metadata.destinationPort}`
            const proc = c.metadata.processPath || c.metadata.process || '-'
            return (
              <tr key={c.id}>
                <td>{host}</td>
                <td className="muted">{c.metadata.network}</td>
                <td className="muted proc">{proc}</td>
                <td>{fmtBytes(c.upload)}</td>
                <td>{fmtBytes(c.download)}</td>
                <td className="muted">{(c.chains ?? []).join(' → ')}</td>
                <td className="muted">{c.rule}</td>
                <td>
                  <button className="danger" onClick={() => kill(c.id)}>
                    断开
                  </button>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </section>
  )
}
