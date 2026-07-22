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
  processes: string[];
  devices: string[];
}
export type WLType = 'domain' | 'ip' | 'process' | 'device';

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

export interface TPStatus {
  mode: string;
  modes: string[];
  autoBlock: boolean;
  root: boolean;
  threats: { domains: number; ips: number };
}

export interface TPRuleSet {
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
export interface TPRuleSets {
  sets: TPRuleSet[];
}
export interface TPRuleSetCatalogEntry {
  tag: string;
  name: string;
  url: string;
  mirror: string;
  format: string;
  suggested_role: string;
}
export interface TPProfile {
  id: string;
  name: string;
  subscription_id?: string;
  whitelist: { domains: string[]; ips: string[] };
  ruleset_tags?: string[];
  mode?: string;
  active?: boolean;
}

export interface TPLiveConn {
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
export interface TPConnSnapshot {
  downloadTotal: number;
  uploadTotal: number;
  connections: TPLiveConn[] | null;
}

export const tp = {
  status: () => fetch('/api/status').then(unwrap<TPStatus>),
  connections: () => fetch('/api/connections').then(unwrap<TPConnSnapshot>),

  listRuleSets: () => fetch('/api/rulesets').then(unwrap<TPRuleSets>),
  ruleSetCatalog: () => fetch('/api/rulesets/catalog').then(unwrap<TPRuleSetCatalogEntry[]>),
  addRuleSet: (body: Record<string, unknown>) =>
    fetch('/api/rulesets', { method: 'POST', headers: jsonHeaders, body: JSON.stringify(body) }).then(
      unwrap<TPRuleSets>,
    ),
  patchRuleSet: (tag: string, patch: { enabled?: boolean; role?: string }) =>
    fetch(`/api/rulesets/${encodeURIComponent(tag)}`, {
      method: 'PATCH',
      headers: jsonHeaders,
      body: JSON.stringify(patch),
    }).then(unwrap<TPRuleSets>),
  delRuleSet: (tag: string) =>
    fetch(`/api/rulesets/${encodeURIComponent(tag)}`, { method: 'DELETE' }).then(unwrap<TPRuleSets>),

  listProfiles: () => fetch('/api/profiles').then(unwrap<TPProfile[]>),
  addProfile: (name: string) =>
    fetch('/api/profiles', { method: 'POST', headers: jsonHeaders, body: JSON.stringify({ name }) }).then(
      unwrap<TPProfile>,
    ),
  activateProfile: (id: string) =>
    fetch(`/api/profiles/${id}/activate`, { method: 'POST' }).then(unwrap<TPProfile>),
  delProfile: (id: string) => fetch(`/api/profiles/${id}`, { method: 'DELETE' }).then(unwrap<void>),
  setMode: (mode: string) =>
    fetch('/api/mode', { method: 'POST', headers: jsonHeaders, body: JSON.stringify({ mode }) }).then(
      unwrap<{ mode: string }>,
    ),
  setAutoBlock: (enabled: boolean) =>
    fetch('/api/autoblock', { method: 'POST', headers: jsonHeaders, body: JSON.stringify({ enabled }) }).then(
      unwrap<{ autoBlock: boolean }>,
    ),
  listSubs: () => fetch('/api/subscriptions').then(unwrap<TPSubscription[]>),
  events: (alertsOnly?: boolean) =>
    fetch('/api/events' + (alertsOnly ? '?level=alert' : '')).then(unwrap<DetectEvent[]>),
  getWhitelist: () => fetch('/api/whitelist').then(unwrap<Whitelist>),
  addWhitelist: (type: WLType, value: string) =>
    fetch('/api/whitelist', { method: 'POST', headers: jsonHeaders, body: JSON.stringify({ type, value }) }).then(
      unwrap<Whitelist>,
    ),
  delWhitelist: (type: WLType, value: string) =>
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
