import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Check, Gauge, Loader2, Zap } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { api, ProxyNode } from '@/lib/api';
import { cn } from '@/lib/utils';
import { PageHeader } from '@/components/page-header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';

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
