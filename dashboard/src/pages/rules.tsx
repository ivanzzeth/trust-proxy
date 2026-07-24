import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';

import { api, RuleView } from '@/lib/api';
import { matchesQuery, usePagedList } from '@/hooks/use-paged-list';
import { PageHeader } from '@/components/page-header';
import { ListSearch, PaginationBar } from '@/components/pagination-bar';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import RuleSets from '@/pages/rulesets';
import CustomRules from '@/pages/custom-rules';

const FINAL_BUILTINS = ['proxy', 'direct', 'blocked'] as const;

// Rules unifies the three policy views: Routing (the effective, layer-labeled
// policy — "why is this allowed/blocked"), Rule Sets, and Custom routing rules.
export default function Rules() {
  const { t } = useTranslation();
  const [tab, setTab] = useState<'routing' | 'sets' | 'custom'>('routing');
  return (
    <div>
      <PageHeader title={t('pages.rules.title')} description={t('pages.rules.description')} />
      <Tabs value={tab} onValueChange={(v) => setTab(v as typeof tab)} className="mb-5">
        <TabsList>
          <TabsTrigger value="routing">{t('pages.rules.tabRouting')}</TabsTrigger>
          <TabsTrigger value="sets">{t('pages.rules.tabSets')}</TabsTrigger>
          <TabsTrigger value="custom">{t('pages.rules.tabCustom')}</TabsTrigger>
        </TabsList>
      </Tabs>
      {tab === 'routing' && <Routing />}
      {tab === 'sets' && <RuleSets embedded />}
      {tab === 'custom' && <CustomRules embedded />}
    </div>
  );
}

const actionColor = (a: string): 'danger' | 'success' | 'muted' | 'warning' | 'default' => {
  if (a === 'reject' || a === 'route:blocked') return 'danger';
  if (a === 'route:direct') return 'muted';
  if (a === 'route:proxy') return 'success';
  return 'default';
};

const layerColor = (l: string): 'danger' | 'warning' | 'default' | 'muted' | 'success' => {
  switch (l) {
    case 'L1':
      return 'danger';
    case 'L2':
    case 'L3':
      return 'warning';
    case 'L0':
      return 'success';
    case 'catch-all':
      return 'default';
    default:
      return 'muted';
  }
};

function Routing() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [search, setSearch] = useState('');
  const { data: rules = [], isLoading } = useQuery({
    queryKey: ['effectiveRules'],
    queryFn: api.effectiveRules,
    refetchInterval: 5000,
  });
  const { data: finalCfg } = useQuery({
    queryKey: ['final'],
    queryFn: api.final,
  });
  const setFinal = useMutation({
    mutationFn: (outbound: string) => api.setFinal(outbound),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['final'] });
      qc.invalidateQueries({ queryKey: ['effectiveRules'] });
    },
  });

  const filtered = useMemo(
    () =>
      rules.filter((r: RuleView) =>
        matchesQuery(search, r.layer, r.source, r.action, r.matcher, r.note, ...(r.values ?? [])),
      ),
    [rules, search],
  );
  const page = usePagedList(filtered, search);

  return (
    <div>
      <div className="mb-4 flex flex-wrap items-end gap-4">
        <div className="space-y-1.5">
          <Label className="text-xs text-muted-foreground">{t('pages.rules.finalLabel')}</Label>
          <Select
            value={finalCfg?.outbound ?? 'proxy'}
            onValueChange={(v) => setFinal.mutate(v)}
            disabled={setFinal.isPending}
          >
            <SelectTrigger className="w-40">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {FINAL_BUILTINS.map((o) => (
                <SelectItem key={o} value={o}>
                  {t(`pages.rules.final.${o}`)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <p className="max-w-xl flex-1 text-sm text-muted-foreground">{t('pages.rules.finalHint')}</p>
        <ListSearch
          value={search}
          onChange={setSearch}
          placeholder={t('pages.rules.searchPlaceholder')}
          className="ml-auto"
        />
      </div>
      <p className="mb-3 text-sm text-muted-foreground">{t('pages.rules.routingHint')}</p>
      <Card>
        <CardContent className="space-y-1.5 py-3">
          {isLoading && <p className="py-6 text-center text-sm text-muted-foreground">{t('common.loading')}</p>}
          {!isLoading && page.total === 0 && (
            <p className="py-6 text-center text-sm text-muted-foreground">{t('pages.rules.empty')}</p>
          )}
          {page.pageItems.map((r: RuleView, i: number) => (
            <div
              key={`${page.page}-${i}`}
              className="flex flex-wrap items-center gap-2 rounded-md border px-3 py-2 text-sm"
            >
              <Badge variant={layerColor(r.layer)} className="w-14 justify-center tnum text-[10px]">
                {r.layer}
              </Badge>
              <span className="min-w-[120px] font-medium">
                {t(`pages.rules.source.${r.source.split(':')[0]}`, r.source)}
              </span>
              {r.source.startsWith('rule-set:') && (
                <Badge variant="outline" className="tnum text-[10px]">
                  {r.source.slice('rule-set:'.length)}
                </Badge>
              )}
              <Badge variant={actionColor(r.action)} className="font-mono text-[10px]">
                {r.action}
              </Badge>
              {r.matcher && <span className="font-mono text-xs text-muted-foreground">{r.matcher}</span>}
              {r.values && r.values.length > 0 && (
                <span className="tnum max-w-full truncate text-xs text-muted-foreground" title={r.values.join(', ')}>
                  {r.values.join(', ')}
                </span>
              )}
              {r.note && <span className="ml-auto text-xs italic text-muted-foreground">{r.note}</span>}
            </div>
          ))}
          <PaginationBar
            page={page.page}
            totalPages={page.totalPages}
            from={page.from}
            to={page.to}
            total={page.total}
            onPageChange={page.setPage}
          />
        </CardContent>
      </Card>
    </div>
  );
}
