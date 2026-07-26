// trust-proxy backend client. Single origin (:21585); dev server proxies /api.
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
export const trafficURL = () => A('/traffic');

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
  /** Explicit Permit override (L3). Omitted ⇒ derived from action (direct/
   *  proxy/node grant Permit, block/none don't). Set false to make a
   *  direct/proxy/node rule Route-only — it still picks the egress but never
   *  opens the allow-set; the destination must already be permitted
   *  elsewhere (whitelist, a permit pack, …). */
  permit?: boolean;
}
export interface PackRuleSet {
  catalog_tag: string;
  role?: string;
}
export interface PackPreset {
  name: string;
  description: string;
  warning?: string;
  exit?: 'overseas' | 'auto' | 'direct';
  rule_sets?: PackRuleSet[];
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
// A subscription as the backend is willing to show it. The URL, any pasted node
// text, the `via` proxy URL and each node's outbound are credentials and never
// leave the server — see internal/subscription/public.go. `source` is a masked
// origin for display only.
export interface Subscription {
  id: string;
  name: string;
  source: string;
  has_url: boolean;
  has_content: boolean;
  has_via: boolean;
  user_agent?: string;
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
  /** How long the connection was open, in ms — the key "was this slow" signal. */
  duration_ms?: number;
  /** Phase breakdown of duration_ms (all 0/absent when unavailable, e.g. UDP). */
  dns_ms?: number;
  connect_ms?: number;
  tls_ms?: number;
}
export type DetectionKind = 'intel' | 'exfil' | 'beacon' | 'dga';
export type DetectionAction = 'alert' | 'blocked' | 'banned';
export interface Detection {
  id: number;
  time: string;
  kind: DetectionKind;
  host: string;
  destination: string;
  process?: string;
  upload?: number;
  download?: number;
  action: DetectionAction;
  reasons?: string[];
  event_id?: number;
}
export interface DetectionsPage {
  items: Detection[];
  total: number;
  limit: number;
  offset: number;
}
export interface DetectionsStats {
  alerts_24h: number;
  blocked_24h: number;
  banned_24h: number;
  by_kind: Record<string, number>;
  intel_domains: number;
  intel_ips: number;
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
  role: string;
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
  blacklist?: { domains?: string[]; keywords?: string[]; regexes?: string[]; ips?: string[] };
  directlist?: { domains?: string[]; ips?: string[] };
  custom_rules?: CustomRule[];
  rule_sets?: RuleSet[];
  ruleset_tags?: string[];
  proxy_groups?: ProxyGroupsConfig;
  dns?: DNSConfig;
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
// Detection thresholds. Every one of these was a Go constant until it turned out
// nobody can tune an alert stream they'd have to rebuild the binary to change.
export interface DetectionConfig {
  beacon_enabled: boolean;
  beacon_min_sample?: number;
  beacon_cv?: number;
  beacon_min_interval_s?: number;
  beacon_max_interval_s?: number;
  beacon_realert_s?: number;
  beacon_realert_factor?: number;
  dga_enabled: boolean;
  dga_min_label_len?: number;
  dga_min_entropy?: number;
  tunnel_min_label_len?: number;
  tunnel_min_entropy?: number;
  subdomain_alert_at?: number;
  exfil_upload_bytes?: number;
  exfil_min_ratio?: number;
  exfil_new_dest_hours?: number;
  auto_block: boolean;
  require_warm_permit: boolean;
}

// What the gateway blocked by itself. Distinct from the deny list: policy lives
// in the posture slot and gets replaced wholesale, defensive blocks must not.
// Query-level DNS activity. A DGA sweep is mostly NXDOMAIN and a tunnel encodes
// payload into names, so neither appears in the connection list at all.
export interface DNSQueryStats {
  total: number;
  nxdomain: number;
  odd_type: number;
  tracked_windows: number;
  top_parents: { parent: string; queries: number; nxdomain: number }[];
}

// Host routing / interface state. Tunnel bypasses (a rogue DHCP route, a network
// claiming public space is "local") never reach the data plane, so they are only
// visible by looking at the machine itself.
export interface NetworkState {
  supported: boolean;
  tun_ifaces?: string[];
  local_nets?: string[];
  default_via?: string;
  host_routes?: number;
  routes?: { prefix: string; interface: string; gateway?: string }[];
}

// TLS client fingerprints. Describes the client stack rather than its
// destination, so it survives ECH hiding the name the Permit gate matches on.
export interface FingerprintList {
  learning: boolean;
  learning_until?: string;
  fingerprints: { ja4: string; count: number; first_seen: string; last_seen: string; processes?: string[] }[];
}

export interface QuarantineEntry {
  value: string;
  is_ip: boolean;
  reason: string;
  time: string;
}

export interface DNSConfig {
  servers: DNSServer[];
  rules: DNSRule[];
  final?: string;
  strategy?: string;
  // "DNS follows route": when the servers above are reached through the exit
  // node, direct-routed domains are resolved by this directly-dialed resolver
  // instead, so domestic destinations get domestic answers. "" = 223.5.5.5.
  direct_server?: string;
  disable_direct_split?: boolean;
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
  /** How long the connection was open, in ms — the key "was this slow" signal. */
  ms?: number;
  /** Phase breakdown of ms (all 0/absent when unavailable, e.g. UDP). */
  dns_ms?: number;
  connect_ms?: number;
  tls_ms?: number;
}
export interface HistoryPage {
  items: HistoryRecord[];
  total: number;
  limit: number;
  offset: number;
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
export interface TUNConfig {
  stack: string; // system | gvisor | mixed
  mtu: number; // 0 = auto
  strict_route: boolean;
  exclude_package?: string[];
  include_package?: string[];
  exclude_process?: string[];
}

export interface ProxyGenRequest {
  type: string;
  server: string;
  port?: number;
  sni?: string;
  name?: string;
}

export interface ProxyGenResult {
  server: Record<string, unknown>; // sing-box server config
  client: Record<string, unknown>; // Clash node dict, importable as-is
  share?: string;
  gen_command: string;
  install_script: string;
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
  detections: (opts?: { kind?: string; q?: string; offset?: number; limit?: number }) => {
    const p = new URLSearchParams();
    if (opts?.kind) p.set('kind', opts.kind);
    if (opts?.q) p.set('q', opts.q);
    if (opts?.offset != null) p.set('offset', String(opts.offset));
    if (opts?.limit != null) p.set('limit', String(opts.limit));
    const qs = p.toString();
    return get<DetectionsPage>('/detections' + (qs ? `?${qs}` : ''));
  },
  detectionsStats: () => get<DetectionsStats>('/detections/stats'),

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

  customRules: () => get<CustomRule[]>('/customrules'),
  addCR: (body: Omit<CustomRule, 'id'>) => post<CustomRule[]>('/customrules', body),
  patchCR: (id: string, patchBody: Partial<Omit<CustomRule, 'id'>>) =>
    patch<CustomRule[]>(`/customrules/${encodeURIComponent(id)}`, patchBody),
  delCR: (id: string) => del<CustomRule[]>(`/customrules/${encodeURIComponent(id)}`),
  moveCR: (id: string, dir: number) => post<CustomRule[]>(`/customrules/${encodeURIComponent(id)}/move`, { dir }),
  packsCatalog: () => get<PackPreset[]>('/customrules/packs/catalog'),
  // Applying a pack changes two things, so this one stays a result object.
  applyPack: (catalog: string) =>
    post<{ rules: CustomRule[]; rule_sets: PackRuleSet[] }>('/customrules/packs/apply', { catalog }),
  setPackEnabled: (name: string, enabled: boolean) =>
    patch<CustomRule[]>(`/customrules/packs/${encodeURIComponent(name)}`, { enabled }),
  delPack: (name: string) => del<CustomRule[]>(`/customrules/packs/${encodeURIComponent(name)}`),

  // Self-hosted exit: the gateway mints the server config and the matching
  // client node in one call, so the keys can't drift the way they do when you
  // run `proxy gen` on the exit host and paste half of it back.
  proxyProtocols: () => get<string[]>('/proxy-gen/protocols'),
  proxyGen: (req: ProxyGenRequest) => post<ProxyGenResult>('/proxy-gen', req),

  subs: () => get<Subscription[]>('/subscriptions'),
  addSub: (name: string, url: string, userAgent?: string, via?: string) =>
    post<Subscription>('/subscriptions', { name, url, user_agent: userAgent, via }),
  importNodes: (name: string, content: string) => post<Subscription>('/subscriptions', { name, content }),
  applySub: (id: string) => post<Subscription>(`/subscriptions/${id}/apply`),
  refreshSub: (id: string) => post<Subscription>(`/subscriptions/${id}/refresh`),
  delSub: (id: string) => del<void>(`/subscriptions/${id}`),

  rulesets: () => get<RuleSet[]>('/rulesets'),
  ruleCatalog: () => get<CatalogEntry[]>('/rulesets/catalog'),
  addRuleSet: (body: Record<string, unknown>) => post<RuleSet[]>('/rulesets', body),
  patchRuleSet: (tag: string, body: { enabled?: boolean; role?: string }) =>
    patch<RuleSet[]>(`/rulesets/${encodeURIComponent(tag)}`, body),
  delRuleSet: (tag: string) => del<RuleSet[]>(`/rulesets/${encodeURIComponent(tag)}`),
  rulesetRules: (tag: string, q = '', offset = 0, limit = 200) =>
    get<RuleSetContent>(
      `/rulesets/${encodeURIComponent(tag)}/rules?q=${encodeURIComponent(q)}&offset=${offset}&limit=${limit}`,
    ),
  effectiveRules: () => get<RuleView[]>('/effective-rules'),
  detectionConfig: () => get<DetectionConfig>('/detection-config'),
  setDetectionConfig: (c: DetectionConfig) => put<DetectionConfig>('/detection-config', c),
  dnsQueryStats: (top = 10) => get<DNSQueryStats>(`/dns-queries/stats?top=${top}`),
  netcheck: () => get<NetworkState>('/netcheck'),
  fingerprints: (limit = 50) => get<FingerprintList>(`/fingerprints?limit=${limit}`),
  quarantine: () => get<QuarantineEntry[]>('/quarantine'),
  releaseQuarantine: (value: string) => del<QuarantineEntry[]>('/quarantine', { value }),
  clearQuarantine: () => del<QuarantineEntry[]>('/quarantine', { all: true }),
  final: () => get<{ outbound: string }>('/final'),
  setFinal: (outbound: string) => put<{ outbound: string }>('/final', { outbound }),
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

  posture: () => get<{ active: string; seeded_split: boolean }>('/posture'),
  setPosture: (active: string) =>
    put<{ active: string; seeded_split: boolean; forced_clash_rule?: boolean }>('/posture', { active }),

  profiles: () => get<Profile[]>('/profiles'),
  addProfile: (name: string) => post<Profile>('/profiles', { name }),
  activateProfile: (id: string) => post<Profile>(`/profiles/${id}/activate`),
  delProfile: (id: string) => del<void>(`/profiles/${id}`),

  dns: () => get<DNSConfig>('/dns'),
  setDNS: (c: DNSConfig) => put<DNSConfig>('/dns', c),


  tun: () => get<TUNConfig>('/tun'),
  setTUN: (c: TUNConfig) => put<TUNConfig>('/tun', c),

  endpoints: () => get<Endpoint[]>('/endpoints'),
  addEndpoint: (body: Record<string, unknown>) => post<{ tag: string }>('/endpoints', body),
  patchEndpoint: (tag: string, enabled: boolean) => patch<Endpoint[]>(`/endpoints/${encodeURIComponent(tag)}`, { enabled }),
  delEndpoint: (tag: string) => del<void>(`/endpoints/${encodeURIComponent(tag)}`),

  historyStats: () => get<HistoryStats>('/history/stats'),
  history: (limit = 50, q = '', offset = 0) =>
    get<HistoryPage>(`/history?page=1&limit=${limit}&offset=${offset}&q=${encodeURIComponent(q)}`),

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
