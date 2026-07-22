// trust-proxy backend client. Single origin (:9096); the dev server proxies /api.

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
const post = (u: string, body?: unknown) =>
  fetch(u, { method: 'POST', headers: J, body: body ? JSON.stringify(body) : undefined });
const del = (u: string, body?: unknown) =>
  fetch(u, { method: 'DELETE', headers: J, body: body ? JSON.stringify(body) : undefined });

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

export const api = {
  status: () => fetch('/api/status').then(unwrap<Status>),
  dns: () => fetch('/api/dns').then(unwrap<DNSConfig>),
  historyStats: () => fetch('/api/history/stats').then(unwrap<HistoryStats>),
  history: (limit = 200, host = '') =>
    fetch(`/api/history?limit=${limit}&host=${encodeURIComponent(host)}`).then(unwrap<HistoryRecord[]>),
  setDNS: (c: DNSConfig) => fetch('/api/dns', { method: 'PUT', headers: J, body: JSON.stringify(c) }).then(unwrap<DNSConfig>),
  setMode: (mode: string) => post('/api/mode', { mode }).then(unwrap<{ mode: string }>),
  setAutoBlock: (enabled: boolean) => post('/api/autoblock', { enabled }).then(unwrap<{ autoBlock: boolean }>),

  connections: () => fetch('/api/connections').then(unwrap<ConnSnapshot>),
  killConn: (id: string) => del(`/api/connections/${id}`).then(unwrap<void>),
  killAll: () => del('/api/connections').then(unwrap<void>),
  events: (alertsOnly?: boolean) =>
    fetch('/api/events' + (alertsOnly ? '?level=alert' : '')).then(unwrap<DetectEvent[]>),

  whitelist: () =>
    fetch('/api/whitelist')
      .then(unwrap<Whitelist>)
      .then((w) => ({
        domains: w.domains ?? [],
        ips: w.ips ?? [],
        processes: w.processes ?? [],
        devices: w.devices ?? [],
      })),
  addWL: (type: WLType, value: string) => post('/api/whitelist', { type, value }).then(unwrap<Whitelist>),
  delWL: (type: WLType, value: string) => del('/api/whitelist', { type, value }).then(unwrap<Whitelist>),

  subs: () => fetch('/api/subscriptions').then(unwrap<Subscription[]>),
  addSub: (name: string, url: string, userAgent?: string, via?: string) =>
    post('/api/subscriptions', { name, url, user_agent: userAgent, via }).then(unwrap<Subscription>),
  importNodes: (name: string, content: string) =>
    post('/api/subscriptions', { name, content }).then(unwrap<Subscription>),
  applySub: (id: string) => post(`/api/subscriptions/${id}/apply`).then(unwrap<Subscription>),
  refreshSub: (id: string) => post(`/api/subscriptions/${id}/refresh`).then(unwrap<Subscription>),
  delSub: (id: string) => del(`/api/subscriptions/${id}`).then(unwrap<void>),

  rulesets: () => fetch('/api/rulesets').then(unwrap<{ sets: RuleSet[] }>),
  ruleCatalog: () => fetch('/api/rulesets/catalog').then(unwrap<CatalogEntry[]>),
  addRuleSet: (body: Record<string, unknown>) => post('/api/rulesets', body).then(unwrap<{ sets: RuleSet[] }>),
  patchRuleSet: (tag: string, patch: { enabled?: boolean; role?: string }) =>
    fetch(`/api/rulesets/${encodeURIComponent(tag)}`, { method: 'PATCH', headers: J, body: JSON.stringify(patch) }).then(
      unwrap<{ sets: RuleSet[] }>,
    ),
  delRuleSet: (tag: string) => del(`/api/rulesets/${encodeURIComponent(tag)}`).then(unwrap<{ sets: RuleSet[] }>),

  proxies: () => fetch('/api/proxies').then(unwrap<{ proxies: Record<string, ProxyNode> }>),
  selectProxy: (group: string, name: string) => fetch('/api/proxies/select', { method: 'PUT', headers: J, body: JSON.stringify({ group, name }) }).then(unwrap<void>),
  delay: (name: string) =>
    fetch(`/api/proxies/${encodeURIComponent(name)}/delay?timeout=3000`).then(unwrap<{ delay: number; error?: string }>),

  profiles: () => fetch('/api/profiles').then(unwrap<Profile[]>),
  addProfile: (name: string) => post('/api/profiles', { name }).then(unwrap<Profile>),
  activateProfile: (id: string) => post(`/api/profiles/${id}/activate`).then(unwrap<Profile>),
  delProfile: (id: string) => del(`/api/profiles/${id}`).then(unwrap<void>),
};

// ---- host/ip helpers (for one-click add-to-whitelist) ----
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
