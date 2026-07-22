// trust-proxy backend API (our own /api, same-origin with the served console).
// Distinct from src/api/* which target the Clash controller.

export interface TPNode {
  tag: string;
  protocol: string;
  server: string;
  port: number;
}

export interface TPSubscription {
  id: string;
  name: string;
  url: string;
  user_agent?: string;
  via?: string;
  node_count: number;
  nodes?: TPNode[];
  updated_at?: string;
  last_error?: string;
  applied?: boolean;
}

async function unwrap<T>(r: Response): Promise<T> {
  if (!r.ok) {
    let msg = `HTTP ${r.status}`;
    try {
      msg = (await r.json()).error || msg;
    } catch {
      /* ignore */
    }
    throw new Error(msg);
  }
  if (r.status === 204) return undefined as T;
  return (await r.json()) as T;
}

const jsonHeaders = { 'Content-Type': 'application/json' };

export interface Whitelist {
  domains: string[];
  ips: string[];
}

export const tp = {
  listSubs: () => fetch('/api/subscriptions').then(unwrap<TPSubscription[]>),
  getWhitelist: () => fetch('/api/whitelist').then(unwrap<Whitelist>),
  addWhitelist: (type: 'domain' | 'ip', value: string) =>
    fetch('/api/whitelist', { method: 'POST', headers: jsonHeaders, body: JSON.stringify({ type, value }) }).then(
      unwrap<Whitelist>,
    ),
  delWhitelist: (type: 'domain' | 'ip', value: string) =>
    fetch('/api/whitelist', { method: 'DELETE', headers: jsonHeaders, body: JSON.stringify({ type, value }) }).then(
      unwrap<Whitelist>,
    ),
  addSub: (name: string, url: string, userAgent?: string, via?: string) =>
    fetch('/api/subscriptions', {
      method: 'POST',
      headers: jsonHeaders,
      body: JSON.stringify({ name, url, user_agent: userAgent, via }),
    }).then(unwrap<TPSubscription>),
  importNodes: (name: string, content: string) =>
    fetch('/api/subscriptions', {
      method: 'POST',
      headers: jsonHeaders,
      body: JSON.stringify({ name, content }),
    }).then(unwrap<TPSubscription>),
  applySub: (id: string) => fetch(`/api/subscriptions/${id}/apply`, { method: 'POST' }).then(unwrap<TPSubscription>),
  refreshSub: (id: string) =>
    fetch(`/api/subscriptions/${id}/refresh`, { method: 'POST' }).then(unwrap<TPSubscription>),
  delSub: (id: string) => fetch(`/api/subscriptions/${id}`, { method: 'DELETE' }).then(unwrap<void>),
};
