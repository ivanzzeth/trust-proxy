// trust-proxy backend client. Single origin (:9096); dev server proxies /api.
//
// Multi-node: setNode(id) repoints every call to /api/nodes/{id}/* which the
// brain reverse-proxies to that gateway. Node-registry calls always target the
// local brain (fixed /api/nodes). Subscribe(cb) fires when the node changes so
// the UI can reset queries.

let nodePrefix = ''; // '' = local; '/nodes/{id}' = a remote gateway
const listeners = new Set<() => void>();

export function setNode(id: string | null) {
  nodePrefix = id ? `/nodes/${id}` : '';
  listeners.forEach((l) => l());
}
export function currentNode(): string | null {
  return nodePrefix ? nodePrefix.slice('/nodes/'.length) : null;
}
export function onNodeChange(cb: () => void): () => void {
  listeners.add(cb);
  return () => listeners.delete(cb);
}
// A builds a node-scoped /api URL; L builds a brain-local one (node registry).
const A = (p: string) => `/api${nodePrefix}${p}`;
export const logsURL = (level: string) => A(`/logs?level=${encodeURIComponent(level)}`);

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
const J = { 'Content-Type': 'application/json' };
const get = <T>(p: string) => fetch(A(p)).then(unwrap<T>);
const post = <T>(p: string, body?: unknown) =>
  fetch(A(p), { method: 'POST', headers: J, body: body ? JSON.stringify(body) : undefined }).then(unwrap<T>);
const put = <T>(p: string, body?: unknown) =>
  fetch(A(p), { method: 'PUT', headers: J, body: body ? JSON.stringify(body) : undefined }).then(unwrap<T>);
const del = <T>(p: string, body?: unknown) =>
  fetch(A(p), { method: 'DELETE', headers: J, body: body ? JSON.stringify(body) : undefined }).then(unwrap<T>);

// ---- types ----
export interface Status {
  mode: string;
  modes: string[];
  autoBlock: boolean;
  root: boolean;
  threats: { domains: number; ips: number };
}
export interface Whitelist {
  domains: string[];
  ips: string[];
  processes: string[];
  devices: string[];
}
export type WLType = 'domain' | 'ip' | 'process' | 'device';
export interface TPNode {
  tag: string;
  protocol: string;
  server: string;
  port: number;
}
export interface Subscription {
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
export interface DetectEvent {
  id: number;
  time: string;
  network: string;
  host: string;
  destination: string;
  source: string;
  process: string;
  rule: string;
  outbound: string;
  upload: number;
  download: number;
  level: 'info' | 'alert';
  denied?: boolean;
  reasons?: string[];
}
export interface LiveConn {
  id: string;
  upload: number;
  download: number;
  start: string;
  chains: string[];
  rule: string;
  metadata: {
    network: string;
    type: string;
    host: string;
    destinationIP: string;
    destinationPort: string;
    sourceIP: string;
    sourcePort: string;
    process?: string;
  };
}
export interface ConnSnapshot {
  downloadTotal: number;
  uploadTotal: number;
  connections: LiveConn[] | null;
}
export interface RuleSet {
  tag: string;
  name: string;
  type: string;
  format: string;
  url?: string;
  path?: string;
  download_detour: string;
  update_interval: string;
  role: 'block' | 'allow-direct' | 'allow-proxy';
  enabled: boolean;
}
export interface CatalogEntry {
  tag: string;
  name: string;
  url: string;
  mirror: string;
  format: string;
  suggested_role: string;
}
export interface ProxyNode {
  type: string;
  now?: string;
  all?: string[];
  udp?: boolean;
  history?: { delay: number }[];
}
export interface Profile {
  id: string;
  name: string;
  subscription_id?: string;
  whitelist: Whitelist;
  ruleset_tags?: string[];
  mode?: string;
  active?: boolean;
}
export interface DNSServer {
  tag: string;
  type: string;
  server?: string;
  port?: number;
  detour?: string;
}
export interface DNSRule {
  domain_suffix?: string[];
  rule_set?: string[];
  server: string;
}
export interface DNSConfig {
  servers: DNSServer[];
  rules: DNSRule[];
  final?: string;
  strategy?: string;
}
export interface Talker {
  host: string;
  up: number;
  down: number;
  count: number;
}
export interface HourBucket {
  hour: number;
  up: number;
  down: number;
  count: number;
}
export interface HistoryStats {
  total_up: number;
  total_down: number;
  connections: number;
  blocked: number;
  alerts: number;
  top_talkers: Talker[];
  hourly: HourBucket[];
}
export interface HistoryRecord {
  t: string;
  h: string;
  d?: string;
  p?: string;
  o?: string;
  u: number;
  dn: number;
  x?: boolean;
  l?: string;
}
export interface Gateway {
  id: string;
  name: string;
  url: string;
}

export const api = {
  status: () => get<Status>('/status'),
  setMode: (mode: string) => post<{ mode: string }>('/mode', { mode }),
  setAutoBlock: (enabled: boolean) => post<{ autoBlock: boolean }>('/autoblock', { enabled }),

  connections: () => get<ConnSnapshot>('/connections'),
  killConn: (id: string) => del<void>(`/connections/${id}`),
  killAll: () => del<void>('/connections'),
  events: (alertsOnly?: boolean) => get<DetectEvent[]>('/events' + (alertsOnly ? '?level=alert' : '')),

  whitelist: () =>
    get<Whitelist>('/whitelist').then((w) => ({
      domains: w.domains ?? [],
      ips: w.ips ?? [],
      processes: w.processes ?? [],
      devices: w.devices ?? [],
    })),
  addWL: (type: WLType, value: string) => post<Whitelist>('/whitelist', { type, value }),
  delWL: (type: WLType, value: string) => del<Whitelist>('/whitelist', { type, value }),

  subs: () => get<Subscription[]>('/subscriptions'),
  addSub: (name: string, url: string, userAgent?: string, via?: string) =>
    post<Subscription>('/subscriptions', { name, url, user_agent: userAgent, via }),
  importNodes: (name: string, content: string) => post<Subscription>('/subscriptions', { name, content }),
  applySub: (id: string) => post<Subscription>(`/subscriptions/${id}/apply`),
  refreshSub: (id: string) => post<Subscription>(`/subscriptions/${id}/refresh`),
  delSub: (id: string) => del<void>(`/subscriptions/${id}`),

  rulesets: () => get<{ sets: RuleSet[] }>('/rulesets'),
  ruleCatalog: () => get<CatalogEntry[]>('/rulesets/catalog'),
  addRuleSet: (body: Record<string, unknown>) => post<{ sets: RuleSet[] }>('/rulesets', body),
  patchRuleSet: (tag: string, patch: { enabled?: boolean; role?: string }) =>
    put<{ sets: RuleSet[] }>(`/rulesets/${encodeURIComponent(tag)}`, patch),
  delRuleSet: (tag: string) => del<{ sets: RuleSet[] }>(`/rulesets/${encodeURIComponent(tag)}`),

  proxies: () => get<{ proxies: Record<string, ProxyNode> }>('/proxies'),
  selectProxy: (group: string, name: string) => put<void>('/proxies/select', { group, name }),
  delay: (name: string) => get<{ delay: number; error?: string }>(`/proxies/${encodeURIComponent(name)}/delay?timeout=3000`),

  profiles: () => get<Profile[]>('/profiles'),
  addProfile: (name: string) => post<Profile>('/profiles', { name }),
  activateProfile: (id: string) => post<Profile>(`/profiles/${id}/activate`),
  delProfile: (id: string) => del<void>(`/profiles/${id}`),

  dns: () => get<DNSConfig>('/dns'),
  setDNS: (c: DNSConfig) => put<DNSConfig>('/dns', c),

  historyStats: () => get<HistoryStats>('/history/stats'),
  history: (limit = 200, host = '') => get<HistoryRecord[]>(`/history?limit=${limit}&host=${encodeURIComponent(host)}`),

  // Node registry — always the local brain (never node-scoped).
  gateways: () => fetch('/api/nodes').then(unwrap<Gateway[]>),
  addGateway: (name: string, url: string, token: string) =>
    fetch('/api/nodes', { method: 'POST', headers: J, body: JSON.stringify({ name, url, token }) }).then(unwrap<Gateway>),
  delGateway: (id: string) => fetch(`/api/nodes/${id}`, { method: 'DELETE' }).then(unwrap<void>),
};

// ---- host/ip helpers (one-click add-to-whitelist) ----
export const splitHost = (hp: string) => {
  if (!hp) return '';
  if (hp.startsWith('[')) {
    const i = hp.indexOf(']');
    return i > 0 ? hp.slice(1, i) : hp;
  }
  const i = hp.lastIndexOf(':');
  return i > 0 && hp.indexOf(':') === i ? hp.slice(0, i) : hp;
};
export const isIPv4 = (s: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s);
export const isIPv6 = (s: string) => s.includes(':') && /^[0-9a-fA-F:]+$/.test(s);
export const isIP = (s: string) => isIPv4(s) || isIPv6(s);
export const toCIDR = (ip: string) => (ip.includes('/') ? ip : isIPv6(ip) ? `${ip}/128` : `${ip}/32`);
