import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Plus, Save, Trash2 } from 'lucide-react';

import { api, DNSConfig, DNSServer } from '@/lib/api';
import { PageHeader } from '@/components/page-header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';

const TYPES = ['local', 'udp', 'tcp', 'tls', 'https', 'quic', 'fakeip', 'hosts'];
// fakeip/hosts synthesize answers locally — no server address / detour.
const SYNTH = new Set(['local', 'fakeip', 'hosts']);

// hosts records <-> textarea text ("host=ip1,ip2" per line).
const recordsToText = (r?: Record<string, string[]>) =>
  Object.entries(r ?? {})
    .map(([h, ips]) => `${h}=${ips.join(',')}`)
    .join('\n');
const textToRecords = (t: string): Record<string, string[]> => {
  const out: Record<string, string[]> = {};
  for (const line of t.split('\n')) {
    const [h, rest] = line.split('=');
    const host = (h ?? '').trim();
    if (!host) continue;
    out[host] = (rest ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  }
  return out;
};
// Radix SelectItem values must be non-empty, so "auto" is the sentinel for "".
const DETOURS = ['auto', 'direct', 'proxy'];
const STRATEGIES = ['auto', 'prefer_ipv4', 'prefer_ipv6', 'ipv4_only', 'ipv6_only'];

const PRESETS: Record<string, DNSConfig> = {
  System: { servers: [{ tag: 'local', type: 'local' }], rules: [], final: 'local' },
  'DoH over proxy': {
    servers: [
      { tag: 'local', type: 'local' },
      { tag: 'doh', type: 'https', server: '1.1.1.1', detour: 'proxy' },
    ],
    rules: [],
    final: 'doh',
  },
  'China-split': {
    servers: [
      { tag: 'direct', type: 'https', server: '223.5.5.5', detour: 'direct' },
      { tag: 'doh', type: 'https', server: '1.1.1.1', detour: 'proxy' },
    ],
    rules: [{ rule_set: ['geosite-cn'], server: 'direct' }],
    final: 'doh',
    strategy: 'prefer_ipv4',
  },
};

export default function DNS() {
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ['dns'], queryFn: api.dns });
  const [cfg, setCfg] = useState<DNSConfig | null>(null);
  useEffect(() => {
    if (data && !cfg) setCfg(structuredClone(data));
  }, [data, cfg]);

  const save = useMutation({
    mutationFn: (c: DNSConfig) => api.setDNS(c),
    onSuccess: (c) => {
      toast.success('DNS applied');
      setCfg(structuredClone(c));
      qc.invalidateQueries({ queryKey: ['dns'] });
    },
    onError: (e) => toast.error(String((e as Error).message)),
  });

  if (!cfg) return null;
  const patch = (p: Partial<DNSConfig>) => setCfg({ ...cfg, ...p });
  const tags = cfg.servers.map((s) => s.tag).filter(Boolean);

  const setServer = (i: number, p: Partial<DNSServer>) =>
    patch({ servers: cfg.servers.map((s, j) => (j === i ? { ...s, ...p } : s)) });

  return (
    <div>
      <PageHeader
        title="DNS"
        description="Resolver policy. Route DNS through the exit node (detour: proxy) to stop leaks — the prerequisite for DNS-tunnel / DGA detection."
        actions={
          <Button disabled={save.isPending} onClick={() => save.mutate(cfg)}>
            <Save className="size-4" /> Apply
          </Button>
        }
      />

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <span className="text-xs text-muted-foreground">Presets:</span>
        {Object.entries(PRESETS).map(([name, p]) => (
          <Button key={name} size="xs" variant="outline" onClick={() => setCfg(structuredClone(p))}>
            {name}
          </Button>
        ))}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="flex-row items-center justify-between pb-3">
            <CardTitle className="text-sm">Servers</CardTitle>
            <Button size="xs" variant="secondary" onClick={() => patch({ servers: [...cfg.servers, { tag: '', type: 'https', server: '', detour: 'proxy' }] })}>
              <Plus className="size-3.5" /> Add
            </Button>
          </CardHeader>
          <CardContent className="space-y-2">
            {cfg.servers.map((s, i) => (
              <div key={i} className="space-y-1.5">
                <div className="grid grid-cols-[1fr_5rem_1.2fr_5.5rem_auto] items-center gap-1.5">
                  <Input className="h-8" placeholder="tag" value={s.tag} onChange={(e) => setServer(i, { tag: e.target.value })} />
                  <Select value={s.type} onValueChange={(v) => setServer(i, { type: v })}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>{TYPES.map((t) => <SelectItem key={t} value={t}>{t}</SelectItem>)}</SelectContent>
                  </Select>
                  <Input className="h-8 disabled:opacity-40" placeholder={SYNTH.has(s.type) ? (s.type === 'local' ? '(system)' : `(${s.type})`) : 'server'} disabled={SYNTH.has(s.type)} value={s.server ?? ''} onChange={(e) => setServer(i, { server: e.target.value })} />
                  <Select value={s.detour ? s.detour : 'auto'} onValueChange={(v) => setServer(i, { detour: v === 'auto' ? '' : v })} disabled={SYNTH.has(s.type)}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>{DETOURS.map((d) => <SelectItem key={d} value={d}>{d}</SelectItem>)}</SelectContent>
                  </Select>
                  <Button size="icon" variant="ghost" className="size-7 text-destructive" onClick={() => patch({ servers: cfg.servers.filter((_, j) => j !== i) })}>
                    <Trash2 className="size-3.5" />
                  </Button>
                </div>
                {s.type === 'fakeip' && (
                  <div className="grid grid-cols-2 gap-1.5 pl-1">
                    <Input className="h-8" placeholder="inet4_range (198.18.0.0/15)" value={s.inet4_range ?? ''} onChange={(e) => setServer(i, { inet4_range: e.target.value })} />
                    <Input className="h-8" placeholder="inet6_range (fc00::/18)" value={s.inet6_range ?? ''} onChange={(e) => setServer(i, { inet6_range: e.target.value })} />
                  </div>
                )}
                {s.type === 'hosts' && (
                  <textarea
                    className="min-h-16 w-full rounded-md border border-input bg-transparent px-2 py-1.5 text-xs font-mono shadow-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                    placeholder="one per line: host=1.2.3.4,5.6.7.8"
                    value={recordsToText(s.records)}
                    onChange={(e) => setServer(i, { records: textToRecords(e.target.value) })}
                  />
                )}
              </div>
            ))}
            <p className="pt-1 text-xs text-muted-foreground">detour <code>proxy</code> = resolve via the exit node (no leak); <code>direct</code> = local network. <code>fakeip</code>/<code>hosts</code> answer locally (no address).</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex-row items-center justify-between pb-3">
            <CardTitle className="text-sm">Split rules</CardTitle>
            <Button size="xs" variant="secondary" onClick={() => patch({ rules: [...cfg.rules, { domain_suffix: [], server: tags[0] ?? '' }] })}>
              <Plus className="size-3.5" /> Add
            </Button>
          </CardHeader>
          <CardContent className="space-y-2">
            {cfg.rules.length === 0 && <p className="py-2 text-xs text-muted-foreground">No split rules — everything resolves via “final”.</p>}
            {cfg.rules.map((r, i) => (
              <div key={i} className="grid grid-cols-[1fr_1fr_6rem_auto] items-center gap-1.5">
                <Input className="h-8" placeholder="domain_suffix (csv)" value={(r.domain_suffix ?? []).join(',')} onChange={(e) => patch({ rules: cfg.rules.map((x, j) => (j === i ? { ...x, domain_suffix: e.target.value.split(',').map((s) => s.trim()).filter(Boolean) } : x)) })} />
                <Input className="h-8" placeholder="rule_set (csv)" value={(r.rule_set ?? []).join(',')} onChange={(e) => patch({ rules: cfg.rules.map((x, j) => (j === i ? { ...x, rule_set: e.target.value.split(',').map((s) => s.trim()).filter(Boolean) } : x)) })} />
                <Select value={r.server} onValueChange={(v) => patch({ rules: cfg.rules.map((x, j) => (j === i ? { ...x, server: v } : x)) })}>
                  <SelectTrigger><SelectValue placeholder="server" /></SelectTrigger>
                  <SelectContent>{tags.map((t) => <SelectItem key={t} value={t}>{t}</SelectItem>)}</SelectContent>
                </Select>
                <Button size="icon" variant="ghost" className="size-7 text-destructive" onClick={() => patch({ rules: cfg.rules.filter((_, j) => j !== i) })}>
                  <Trash2 className="size-3.5" />
                </Button>
              </div>
            ))}
            <div className="grid grid-cols-2 gap-2 pt-2">
              <label className="space-y-1 text-xs text-muted-foreground">
                Final (fallback) server
                <Select value={cfg.final ?? ''} onValueChange={(v) => patch({ final: v })}>
                  <SelectTrigger><SelectValue placeholder="—" /></SelectTrigger>
                  <SelectContent>{tags.map((t) => <SelectItem key={t} value={t}>{t}</SelectItem>)}</SelectContent>
                </Select>
              </label>
              <label className="space-y-1 text-xs text-muted-foreground">
                Strategy
                <Select value={cfg.strategy ? cfg.strategy : 'auto'} onValueChange={(v) => patch({ strategy: v === 'auto' ? '' : v })}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>{STRATEGIES.map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}</SelectContent>
                </Select>
              </label>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
