import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Check, Gauge, Loader2, Plus, Trash2, Zap } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { api, PGFilter, PGType, ProxyGroup, ProxyGroupsConfig, ProxyNode } from '@/lib/api';
import { cn } from '@/lib/utils';
import { PageHeader } from '@/components/page-header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';

function delayColor(ms?: number) {
  if (ms === undefined) return 'text-muted-foreground';
  if (ms <= 0) return 'text-destructive';
  if (ms < 200) return 'text-primary';
  if (ms < 800) return 'text-warning';
  return 'text-destructive';
}
function delayText(ms: number | undefined, timeoutLabel: string) {
  if (ms === undefined) return '—';
  if (ms <= 0) return timeoutLabel;
  return `${ms} ms`;
}

export default function Proxies() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ['proxies'], queryFn: api.proxies, refetchInterval: 5000 });
  const [delays, setDelays] = useState<Record<string, number>>({});
  const [testing, setTesting] = useState<string | null>(null);

  const select = useMutation({
    mutationFn: (v: { group: string; name: string }) => api.selectProxy(v.group, v.name),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['proxies'] }),
    onError: (e) => toast.error(String((e as Error).message)),
  });

  const proxies = data?.proxies ?? {};
  const groups = Object.entries(proxies).filter(([, p]) => Array.isArray(p.all) && p.all.length > 0);

  const lastDelay = (name: string): number | undefined => {
    if (name in delays) return delays[name];
    const h = proxies[name]?.history;
    return h && h.length ? h[h.length - 1].delay : undefined;
  };

  const testGroup = async (members: string[]) => {
    setTesting(members.join());
    const results = await Promise.all(
      members.map(async (m) => {
        try {
          const r = await api.delay(m);
          return [m, r.error ? 0 : r.delay] as const;
        } catch {
          return [m, 0] as const;
        }
      }),
    );
    setDelays((d) => ({ ...d, ...Object.fromEntries(results) }));
    setTesting(null);
  };

  return (
    <div>
      <PageHeader
        title={t('pages.proxies.title')}
        description={t('pages.proxies.description')}
      />
      <GroupSettings />
      {groups.length === 0 && (
        <Card>
          <CardContent className="py-16 text-center text-sm text-muted-foreground">
            {t('pages.proxies.emptyGroups')}
          </CardContent>
        </Card>
      )}
      <div className="space-y-4">
        {groups.map(([name, g]: [string, ProxyNode]) => {
          const selectable = g.type === 'Selector';
          const members = g.all ?? [];
          return (
            <Card key={name}>
              <CardHeader className="flex-row items-center justify-between pb-3">
                <CardTitle className="flex items-center gap-2 text-sm">
                  {name}
                  <Badge variant="outline">{g.type}</Badge>
                  {g.now && <span className="text-xs font-normal text-muted-foreground">{t('pages.proxies.nowLabel')} <span className="text-primary">{g.now}</span></span>}
                </CardTitle>
                <Button size="xs" variant="outline" disabled={!!testing} onClick={() => testGroup(members)}>
                  {testing === members.join() ? <Loader2 className="size-3.5 animate-spin" /> : <Zap className="size-3.5" />} {t('pages.proxies.test')}
                </Button>
              </CardHeader>
              <CardContent className="pt-0">
                <div className="grid gap-1.5 sm:grid-cols-2 lg:grid-cols-3">
                  {members.map((m) => {
                    const active = g.now === m;
                    const d = lastDelay(m);
                    return (
                      <button
                        key={m}
                        disabled={!selectable || select.isPending}
                        onClick={() => selectable && select.mutate({ group: name, name: m })}
                        className={cn(
                          'flex items-center justify-between gap-2 rounded-md border px-3 py-2 text-left text-sm transition-colors',
                          active ? 'border-primary/50 bg-primary/10' : 'hover:bg-muted/50',
                          selectable ? 'cursor-pointer' : 'cursor-default',
                        )}
                      >
                        <span className="flex min-w-0 items-center gap-1.5">
                          {active && <Check className="size-3.5 shrink-0 text-primary" />}
                          <span className="truncate">{m}</span>
                        </span>
                        <span className={cn('tnum shrink-0 text-xs', delayColor(d))}>{delayText(d, t('pages.proxies.delayTimeout'))}</span>
                      </button>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>
      <p className="mt-3 flex items-center gap-1.5 text-xs text-muted-foreground">
        <Gauge className="size-3.5" /> {t('pages.proxies.footerHint')}
      </p>
    </div>
  );
}

const PG_TYPES: PGType[] = ['urltest', 'select'];
const PG_FILTERS: PGFilter[] = ['country', 'regex', 'manual'];

// GroupSettings edits the proxy-group config (auto-country + custom groups) as a
// local draft, saved explicitly (each save rebuilds the data plane). The group
// list/selection itself is rendered by the Proxies list below, from the Clash API.
function GroupSettings() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ['proxygroups'], queryFn: api.proxyGroups });
  const [draft, setDraft] = useState<ProxyGroupsConfig | null>(null);
  useEffect(() => {
    if (data) setDraft((d) => d ?? structuredClone(data));
  }, [data]);

  const save = useMutation({
    mutationFn: (cfg: ProxyGroupsConfig) => api.setProxyGroups(cfg),
    onSuccess: (cfg) => {
      setDraft(structuredClone(cfg));
      qc.invalidateQueries({ queryKey: ['proxygroups'] });
      qc.invalidateQueries({ queryKey: ['proxies'] });
      toast.success(t('pages.proxies.groups.saved'));
    },
    onError: (e) => toast.error(String((e as Error).message)),
  });

  if (!draft) return null;
  const patchGroup = (i: number, p: Partial<ProxyGroup>) =>
    setDraft({ ...draft, groups: draft.groups.map((g, j) => (j === i ? { ...g, ...p } : g)) });
  const addGroup = () =>
    setDraft({ ...draft, groups: [...draft.groups, { name: '', type: 'urltest', filter: 'regex', value: '' }] });
  const delGroup = (i: number) => setDraft({ ...draft, groups: draft.groups.filter((_, j) => j !== i) });
  const dirty = JSON.stringify(draft) !== JSON.stringify(data);

  return (
    <Card className="mb-4">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm">{t('pages.proxies.groups.title')}</CardTitle>
        <p className="text-xs leading-relaxed text-muted-foreground">{t('pages.proxies.groups.hint')}</p>
      </CardHeader>
      <CardContent className="space-y-3">
        <label className="flex items-center gap-2 text-sm">
          <Switch checked={draft.auto_country} onCheckedChange={(v) => setDraft({ ...draft, auto_country: v })} />
          {t('pages.proxies.groups.autoCountry')}
        </label>

        <div className="space-y-2">
          {draft.groups.map((g, i) => (
            <div key={i} className="flex flex-wrap items-center gap-2 rounded-md border px-2 py-2">
              <Input
                className="w-36"
                placeholder={t('pages.proxies.groups.namePh')}
                value={g.name}
                onChange={(e) => patchGroup(i, { name: e.target.value })}
              />
              <Select value={g.type} onValueChange={(v) => patchGroup(i, { type: v as PGType })}>
                <SelectTrigger className="w-32"><SelectValue /></SelectTrigger>
                <SelectContent>{PG_TYPES.map((x) => <SelectItem key={x} value={x}>{t(`pages.proxies.groups.type.${x}`)}</SelectItem>)}</SelectContent>
              </Select>
              <Select value={g.filter} onValueChange={(v) => patchGroup(i, { filter: v as PGFilter })}>
                <SelectTrigger className="w-28"><SelectValue /></SelectTrigger>
                <SelectContent>{PG_FILTERS.map((x) => <SelectItem key={x} value={x}>{t(`pages.proxies.groups.filter.${x}`)}</SelectItem>)}</SelectContent>
              </Select>
              {g.filter === 'manual' ? (
                <Input
                  className="min-w-[180px] flex-1"
                  placeholder={t('pages.proxies.groups.nodesPh')}
                  value={(g.nodes ?? []).join(', ')}
                  onChange={(e) => patchGroup(i, { nodes: e.target.value.split(',').map((s) => s.trim()).filter(Boolean) })}
                />
              ) : (
                <Input
                  className="min-w-[140px] flex-1"
                  placeholder={g.filter === 'country' ? t('pages.proxies.groups.countryPh') : t('pages.proxies.groups.regexPh')}
                  value={g.value ?? ''}
                  onChange={(e) => patchGroup(i, { value: e.target.value })}
                />
              )}
              <Button size="icon" variant="ghost" className="size-7 text-destructive" onClick={() => delGroup(i)}>
                <Trash2 className="size-3.5" />
              </Button>
            </div>
          ))}
        </div>

        <div className="flex items-center gap-2">
          <Button size="sm" variant="secondary" onClick={addGroup}>
            <Plus className="size-4" /> {t('pages.proxies.groups.add')}
          </Button>
          <Button size="sm" disabled={!dirty || save.isPending} onClick={() => save.mutate(draft)}>
            {t('pages.proxies.groups.save')}
          </Button>
          {dirty && <span className="text-xs text-muted-foreground">{t('pages.proxies.groups.unsaved')}</span>}
        </div>
        <p className="text-xs text-muted-foreground">{t('pages.proxies.groups.lbNote')}</p>
      </CardContent>
    </Card>
  );
}
