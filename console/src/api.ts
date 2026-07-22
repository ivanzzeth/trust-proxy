// SDK-lite: the console only ever talks to the trust-proxy backend (single
// origin). Connection data is proxied by the backend from the Clash API.

export interface Node {
  tag: string
  protocol: string
  server: string
  port: number
}

export interface Subscription {
  id: string
  name: string
  url: string
  user_agent?: string
  node_count: number
  nodes?: Node[]
  updated_at?: string
  last_error?: string
  applied?: boolean
}

export interface ConnMeta {
  network: string
  type: string
  sourceIP: string
  destinationIP: string
  sourcePort: string
  destinationPort: string
  host: string
  process: string
  processPath: string
}

export interface Conn {
  id: string
  metadata: ConnMeta
  upload: number
  download: number
  start: string
  chains: string[]
  rule: string
}

export interface ConnSnapshot {
  downloadTotal: number
  uploadTotal: number
  connections: Conn[] | null
}

async function unwrap<T>(r: Response): Promise<T> {
  if (!r.ok) {
    let msg = `HTTP ${r.status}`
    try {
      msg = (await r.json()).error || msg
    } catch {
      /* ignore */
    }
    throw new Error(msg)
  }
  if (r.status === 204) return undefined as T
  return r.json() as Promise<T>
}

const json = { 'Content-Type': 'application/json' }

export const api = {
  listSubs: () => fetch('/api/subscriptions').then(unwrap<Subscription[]>),
  addSub: (name: string, url: string, user_agent?: string) =>
    fetch('/api/subscriptions', { method: 'POST', headers: json, body: JSON.stringify({ name, url, user_agent }) }).then(
      unwrap<Subscription>,
    ),
  applySub: (id: string) => fetch(`/api/subscriptions/${id}/apply`, { method: 'POST' }).then(unwrap<Subscription>),
  refreshSub: (id: string) => fetch(`/api/subscriptions/${id}/refresh`, { method: 'POST' }).then(unwrap<Subscription>),
  delSub: (id: string) => fetch(`/api/subscriptions/${id}`, { method: 'DELETE' }).then(unwrap<void>),
  connections: () => fetch('/api/connections').then(unwrap<ConnSnapshot>),
  killConn: (id: string) => fetch(`/api/connections/${encodeURIComponent(id)}`, { method: 'DELETE' }).then(unwrap<void>),
  killAll: () => fetch('/api/connections', { method: 'DELETE' }).then(unwrap<void>),
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`
  const u = ['KB', 'MB', 'GB', 'TB']
  let v = n / 1024
  let i = 0
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(1)} ${u[i]}`
}
