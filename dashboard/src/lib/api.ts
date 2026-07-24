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
const patch = <T>(p: string, body?: unknown) =>
  fetch(A(p), { method: 'PATCH', headers: J, body: body ? JSON.stringify(body) : undefined }).then(unwrap<T>);
const del = <T>(p: string, body?: unknown) =>
  fetch(A(p), { method: 'DELETE', headers: J, body: body ? JSON.stringify(body) : undefined }).then(unwrap<T>);

// ---- types ----
export interface Status {
  mode: string;
  modes: string[];
  autoBlock: boolean;
  root: boolean;
  os?: string; // runtime.GOOS: darwin | linux | windows
  threats: { domains: number; ips: number };
  revert?: { to: string; in_seconds: number };
}
export interface Whitelist {
  domains: string[];
  ips: string[];
  processes: string[];
  devices: string[];
}
export type WLType = 'domain' | 'ip' | 'process' | 'device';
export interface Blacklist {
  domains: string[];
  keywords: string[];
  regexes: string[];
  ips: string[];
}
export type BLType = 'domain' | 'keyword' | 'regex' | 'ip';
export interface Directlist {
  domains: string[];
  ips: string[];
  builtin: string[];
}
export type DLType = 'domain' | 'ip';
export type CRMatch = 'domain' | 'domain_suffix' | 'keyword' | 'regex' | 'ip_cidr';
export type CRAction = 'direct' | 'proxy' | 'block' | 'node';
export interface CustomRule {
  id: string;
  match: CRMatch;
  value: string;
  action: CRAction;
  node?: string;
  pack?: string;
  enabled: boolean;
}
export interface PackPreset {
  name: string;
  description: string;
  exit?: 'overseas' | 'auto' | 'direct'; // how the pack egresses (display hint)
  rules: CustomRule[];
}
export interface RuleSetEntry {
  kind: string;
  value: string;
}
export interface RuleSetContent {
  tag: string;
  count: number;
  total: number;
  offset: number;
  limit: number;
  entries: RuleSetEntry[];
}
export interface RuleView {
  layer: string;
  source: string;
  action: string;
  matcher?: string;
  values?: string[];
  note?: string;
}
export type PGType = 'select' | 'urltest';
export type PGFilter = 'country' | 'regex' | 'manual';
export interface ProxyGroup {
  name: string;
  type: PGType;
  filter: PGFilter;
  value?: string;
  nodes?: string[];
}
export interface ProxyGroupsConfig {
  auto_country: boolean;
  exclude_countries: string[]; // ISO2 regions kept out of the shared Overseas group
  groups: ProxyGroup[];
}
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
export interface ClashRule {
  type: string;
  payload: string;
  proxy: string;
}
export interface ClashMode {
  mode: string;
  modes: string[];
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
  inet4_range?: string;
  inet6_range?: string;
  records?: Record<string, string[]>;
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
export interface Endpoint {
  tag: string;
  type: string; // wireguard | tailscale
  enabled: boolean;
  address?: string[];
  mtu?: number;
  peer_endpoint?: string;
  allowed_ips?: string[];
  hostname?: string;
  exit_node?: string;
  accept_routes?: boolean;
}
export interface InboundAuth {
  username: string;
  password: string;
}
export interface TUNConfig {
  stack: string; // system | gvisor | mixed
  mtu: number; // 0 = auto
  strict_route: boolean;
  exclude_package?: string[];
  include_package?: string[];
  exclude_process?: string[];
}

export const api = {
  status: () => get<Status>('/status'),
  setMode: (mode: string, guardSeconds?: number) =>
    post<{ mode: string }>('/mode', { mode, guard_seconds: guardSeconds }),
  confirmMode: () => post<{ ok: boolean }>('/mode/confirm'),
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

  blacklist: () =>
    get<Blacklist>('/blacklist').then((b) => ({
      domains: b.domains ?? [],
      keywords: b.keywords ?? [],
      regexes: b.regexes ?? [],
      ips: b.ips ?? [],
    })),
  addBL: (type: BLType, value: string) => post<Blacklist>('/blacklist', { type, value }),
  delBL: (type: BLType, value: string) => del<Blacklist>('/blacklist', { type, value }),

  directlist: () =>
    get<Directlist>('/directlist').then((d) => ({
      domains: d.domains ?? [],
      ips: d.ips ?? [],
      builtin: d.builtin ?? [],
    })),
  addDL: (type: DLType, value: string) => post<Directlist>('/directlist', { type, value }),
  delDL: (type: DLType, value: string) => del<Directlist>('/directlist', { type, value }),

  customRules: () => get<{ rules: CustomRule[] }>('/customrules').then((r) => r.rules ?? []),
  addCR: (body: Omit<CustomRule, 'id'>) => post<{ rules: CustomRule[] }>('/customrules', body),
  patchCR: (id: string, patchBody: Partial<Omit<CustomRule, 'id'>>) =>
    patch<{ rules: CustomRule[] }>(`/customrules/${encodeURIComponent(id)}`, patchBody),
  delCR: (id: string) => del<{ rules: CustomRule[] }>(`/customrules/${encodeURIComponent(id)}`),
  moveCR: (id: string, dir: number) => post<{ rules: CustomRule[] }>(`/customrules/${encodeURIComponent(id)}/move`, { dir }),
  packsCatalog: () => get<PackPreset[]>('/customrules/packs/catalog'),
  applyPack: (catalog: string) => post<{ rules: CustomRule[] }>('/customrules/packs/apply', { catalog }),
  setPackEnabled: (name: string, enabled: boolean) =>
    patch<{ rules: CustomRule[] }>(`/customrules/packs/${encodeURIComponent(name)}`, { enabled }),
  delPack: (name: string) => del<{ rules: CustomRule[] }>(`/customrules/packs/${encodeURIComponent(name)}`),

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
  patchRuleSet: (tag: string, body: { enabled?: boolean; role?: string }) =>
    patch<{ sets: RuleSet[] }>(`/rulesets/${encodeURIComponent(tag)}`, body),
  delRuleSet: (tag: string) => del<{ sets: RuleSet[] }>(`/rulesets/${encodeURIComponent(tag)}`),
  rulesetRules: (tag: string, q = '', offset = 0, limit = 200) =>
    get<RuleSetContent>(
      `/rulesets/${encodeURIComponent(tag)}/rules?q=${encodeURIComponent(q)}&offset=${offset}&limit=${limit}`,
    ),
  effectiveRules: () => get<RuleView[]>('/effective-rules'),
  proxyGroups: () =>
    get<ProxyGroupsConfig>('/proxygroups').then((c) => ({
      auto_country: !!c.auto_country,
      exclude_countries: c.exclude_countries ?? [],
      groups: c.groups ?? [],
    })),
  setProxyGroups: (cfg: ProxyGroupsConfig) => put<ProxyGroupsConfig>('/proxygroups', cfg),

  proxies: () => get<{ proxies: Record<string, ProxyNode> }>('/proxies'),
  selectProxy: (group: string, name: string) => put<void>('/proxies/select', { group, name }),
  delay: (name: string) => get<{ delay: number; error?: string }>(`/proxies/${encodeURIComponent(name)}/delay?timeout=3000`),
  rules: () => get<{ rules: ClashRule[] }>('/rules'),

  clashMode: () => get<ClashMode>('/clash-mode'),
  setClashMode: (mode: string) => put<{ mode: string }>('/clash-mode', { mode }),

  profiles: () => get<Profile[]>('/profiles'),
  addProfile: (name: string) => post<Profile>('/profiles', { name }),
  activateProfile: (id: string) => post<Profile>(`/profiles/${id}/activate`),
  delProfile: (id: string) => del<void>(`/profiles/${id}`),

  dns: () => get<DNSConfig>('/dns'),
  setDNS: (c: DNSConfig) => put<DNSConfig>('/dns', c),

  inbound: () => get<InboundAuth>('/inbound'),
  setInbound: (a: InboundAuth) => put<InboundAuth>('/inbound', a),

  tun: () => get<TUNConfig>('/tun'),
  setTUN: (c: TUNConfig) => put<TUNConfig>('/tun', c),

  endpoints: () => get<Endpoint[]>('/endpoints'),
  addEndpoint: (body: Record<string, unknown>) => post<{ tag: string }>('/endpoints', body),
  patchEndpoint: (tag: string, enabled: boolean) => patch<Endpoint[]>(`/endpoints/${encodeURIComponent(tag)}`, { enabled }),
  delEndpoint: (tag: string) => del<void>(`/endpoints/${encodeURIComponent(tag)}`),

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
