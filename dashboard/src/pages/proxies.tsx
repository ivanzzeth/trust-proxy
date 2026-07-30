import { useDeferredValue, useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Check, ChevronDown, ChevronRight, Gauge, Loader2, Plus, RotateCcw, Trash2, Zap } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import {
  api,
  PGFilter,
  PGType,
  PROXY_FAILOVER_DEFAULTS,
  ProxyFailover,
  ProxyGroup,
  ProxyGroupsConfig,
  ProxyNode,
  ProxyScore,
  ProxyScores,
  ProxyScoring,
} from '@/lib/api';
import { cn } from '@/lib/utils';
import { matchesQuery, usePagedList } from '@/hooks/use-paged-list';
import { PageHeader } from '@/components/page-header';
import { ListSearch, PaginationBar } from '@/components/pagination-bar';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';

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

// A demoted node (breaker open) reads as the worst state regardless of the
// number it is carrying: the score describes how good it has been, the breaker
// describes whether it can be used right now, and those are different questions.
function scoreVariant(s: ProxyScore): 'muted' | 'danger' | 'warning' | 'success' {
  if (s.blackhole) return 'danger';
  if (!s.preferred) return 'danger';
  if (s.warming) return 'muted';
  if (s.score >= 75) return 'success';
  if (s.score >= 45) return 'warning';
  return 'danger';
}

// Warm-up must never render as a bare 100 — "measured and excellent" is the
// opposite of "not measured yet", and a user reading a fleet of fresh 100s
// would conclude every node is perfect.
function scoreLabel(s: ProxyScore) {
  if (s.warming) return `${Math.round(s.score)} · ${s.samples}/${s.min_samples}`;
  return String(Math.round(s.score));
}

export default function Proxies() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ['proxies'], queryFn: api.proxies, refetchInterval: 5000 });
  // Scores are advisory here: a gateway too old to serve them (or one with
  // scoring off) must still render the proxy list, so a failed query degrades
  // to "no badges" rather than an error page.
  const { data: scores } = useQuery({
    queryKey: ['proxyscores'],
    queryFn: api.proxyScores,
    refetchInterval: 5000,
    retry: false,
  });
  const [delays, setDelays] = useState<Record<string, number>>({});
  const [testing, setTesting] = useState<string | null>(null);
  const [nodeSearch, setNodeSearch] = useState('');
  const deferredNodeSearch = useDeferredValue(nodeSearch);

  const select = useMutation({
    mutationFn: (v: { group: string; name: string }) => api.selectProxy(v.group, v.name),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['proxies'] }),
    onError: (e) => toast.error(String((e as Error).message)),
  });

  const proxies = data?.proxies ?? {};
  const groups = Object.entries(proxies).filter(([, p]) => Array.isArray(p.all) && p.all.length > 0);
  const scoreOf = useMemo(() => {
    const m = new Map<string, ProxyScore>();
    if (scores?.enabled) for (const s of scores.scores) m.set(s.tag, s);
    return (tag: string) => m.get(tag);
  }, [scores]);

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
        actions={<ListSearch value={nodeSearch} onChange={setNodeSearch} placeholder={t('pages.proxies.searchPlaceholder')} />}
      />
      <GroupSettings />
      <ScoreBoard data={scores} />
      {groups.length === 0 && (
        <Card>
          <CardContent className="py-16 text-center text-sm text-muted-foreground">
            {t('pages.proxies.emptyGroups')}
          </CardContent>
        </Card>
      )}
      <div className="space-y-4">
        {groups.map(([name, g]: [string, ProxyNode]) => (
          <ProxyGroupCard
            key={name}
            name={name}
            g={g}
            search={deferredNodeSearch}
            lastDelay={lastDelay}
            scoreOf={scoreOf}
            testing={testing}
            selectPending={select.isPending}
            onSelect={(n) => select.mutate({ group: name, name: n })}
            onTest={testGroup}
            timeoutLabel={t('pages.proxies.delayTimeout')}
            nowLabel={t('pages.proxies.nowLabel')}
            testLabel={t('pages.proxies.test')}
          />
        ))}
      </div>
      <p className="mt-3 flex items-center gap-1.5 text-xs text-muted-foreground">
        <Gauge className="size-3.5" /> {t('pages.proxies.footerHint')}
      </p>
    </div>
  );
}

function ProxyGroupCard({
  name,
  g,
  search,
  lastDelay,
  scoreOf,
  testing,
  selectPending,
  onSelect,
  onTest,
  timeoutLabel,
  nowLabel,
  testLabel,
}: {
  name: string;
  g: ProxyNode;
  search: string;
  lastDelay: (n: string) => number | undefined;
  scoreOf: (tag: string) => ProxyScore | undefined;
  testing: string | null;
  selectPending: boolean;
  onSelect: (n: string) => void;
  onTest: (members: string[]) => void;
  timeoutLabel: string;
  nowLabel: string;
  testLabel: string;
}) {
  const selectable = g.type === 'Selector';
  const members = g.all ?? [];
  const filtered = useMemo(() => members.filter((m) => matchesQuery(search, m)), [members, search]);
  const page = usePagedList(filtered, search.trim().toLowerCase(), 60);

  return (
    <TooltipProvider delayDuration={150}>
    <Card className="overflow-hidden">
      <CardHeader className="flex-row items-center justify-between pb-3">
        <CardTitle className="flex items-center gap-2 text-sm">
          {name}
          <Badge variant="outline">{g.type}</Badge>
          {g.now && (
            <span className="text-xs font-normal text-muted-foreground">
              {nowLabel} <span className="text-primary">{g.now}</span>
            </span>
          )}
          <Badge variant="muted" className="tnum">
            {page.total}/{members.length}
          </Badge>
        </CardTitle>
        <Button size="xs" variant="outline" disabled={!!testing} onClick={() => onTest(members)}>
          {testing === members.join() ? <Loader2 className="size-3.5 animate-spin" /> : <Zap className="size-3.5" />} {testLabel}
        </Button>
      </CardHeader>
      <CardContent className="pt-0">
        <div className="grid gap-1.5 sm:grid-cols-2 lg:grid-cols-3">
          {page.pageItems.map((m) => {
            const active = g.now === m;
            const d = lastDelay(m);
            const s = scoreOf(m);
            return (
              <button
                key={m}
                disabled={!selectable || selectPending}
                onClick={() => selectable && onSelect(m)}
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
                <span className="flex shrink-0 items-center gap-1.5">
                  {s && <ScoreBadge s={s} />}
                  <span className={cn('tnum text-xs', delayColor(d))}>{delayText(d, timeoutLabel)}</span>
                </span>
              </button>
            );
          })}
        </div>
      </CardContent>
      <PaginationBar
        page={page.page}
        totalPages={page.totalPages}
        total={page.total}
        from={page.from}
        to={page.to}
        onPageChange={page.setPage}
      />
    </Card>
    </TooltipProvider>
  );
}

// ScoreBadge is the score plus, on hover, every input that produced it. A bare
// number would be one more opaque auto-switch: the point of the feature is that
// "why is this node at 62" has an answer the user can read without a CLI.
function ScoreBadge({ s }: { s: ProxyScore }) {
  const { t } = useTranslation();
  const k = (x: string, o?: Record<string, unknown>) => t(`pages.proxies.score.${x}`, o) as string;
  const row = (label: string, value: string) => (
    <div className="flex justify-between gap-4">
      <span className="text-muted-foreground">{label}</span>
      <span className="tnum">{value}</span>
    </div>
  );
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Badge variant={scoreVariant(s)} className="tnum cursor-help">
          {scoreLabel(s)}
        </Badge>
      </TooltipTrigger>
      <TooltipContent className="w-60 space-y-1">
        <div className="font-medium">
          {s.tag} · {Math.round(s.score)}
        </div>
        {s.blackhole && (
          <div className="text-destructive">{k('blackhole', { n: s.blackhole_streak ?? 0 })}</div>
        )}
        {s.warming && !s.blackhole && (
          <div className="text-warning">{k('warming', { n: s.samples, min: s.min_samples })}</div>
        )}
        {!s.preferred && !s.blackhole && (
          <div className="text-destructive">
            {k('demoted')}
            {s.breaker_remaining_seconds ? ` (${s.breaker_remaining_seconds}s)` : ''}
          </div>
        )}
        {row(k('reliability'), String(Math.round(s.reliability)))}
        {row(k('latency'), `${Math.round(s.latency_score)}${s.latency_ms ? ` (${s.latency_ms} ms)` : ''}`)}
        {row(
          k('throughput'),
          `${Math.round(s.throughput_score)}${s.throughput_kbps ? ` (${Math.round(s.throughput_kbps)} KB/s)` : ''}`,
        )}
        {row(k('samples'), String(s.samples))}
        {row(
          k('streak'),
          s.fail_streak > 0
            ? k('failStreak', { n: s.fail_streak })
            : s.ok_streak > 0
              ? k('okStreak', { n: s.ok_streak })
              : '—',
        )}
        {row(k('breaker'), s.breaker || '—')}
        {s.last_err && <div className="truncate text-destructive">{s.last_err}</div>}
      </TooltipContent>
    </Tooltip>
  );
}

// ScoreBoard is the whole ranking in one table, in the same order the data
// plane picks in, with the formula printed above it and rendered with the
// weights actually in force. The formula is not decoration: the weights are
// adjustable below, and a user changing them needs to see what they multiply.
function ScoreBoard({ data }: { data?: ProxyScores }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const k = (x: string, o?: Record<string, unknown>) => t(`pages.proxies.score.${x}`, o) as string;
  const [open, setOpen] = useState(false);
  const reset = useMutation({
    mutationFn: () => api.resetProxyScores(),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['proxyscores'] });
      toast.success(k('resetDone'));
    },
    onError: (e) => toast.error(String((e as Error).message)),
  });

  if (!data) return null;
  const rows = data.scores;
  return (
    <Card className="mb-4">
      <CardHeader className="flex-row items-center justify-between pb-3">
        <div>
          <CardTitle className="text-sm">{k('title')}</CardTitle>
          <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">{k('hint')}</p>
          <p className="mt-1 font-mono text-[11px] text-muted-foreground">{data.formula}</p>
        </div>
        <div className="flex items-center gap-2">
          {!data.enabled && <Badge variant="muted">{k('disabled')}</Badge>}
          <Button size="xs" variant="outline" disabled={reset.isPending} onClick={() => reset.mutate()}>
            <RotateCcw className="size-3.5" /> {k('reset')}
          </Button>
          <Button size="xs" variant="ghost" onClick={() => setOpen((v) => !v)}>
            {open ? <ChevronDown className="size-3.5" /> : <ChevronRight className="size-3.5" />} {k('table')}
          </Button>
        </div>
      </CardHeader>
      {open && (
        <CardContent className="pt-0">
          {rows.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted-foreground">{k('empty')}</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{k('node')}</TableHead>
                  <TableHead className="text-right">{k('scoreCol')}</TableHead>
                  <TableHead className="text-right">{k('reliability')}</TableHead>
                  <TableHead className="text-right">{k('latency')}</TableHead>
                  <TableHead className="text-right">{k('throughput')}</TableHead>
                  <TableHead className="text-right">{k('samples')}</TableHead>
                  <TableHead>{k('state')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((s) => (
                  <TableRow key={s.tag}>
                    <TableCell className="max-w-[220px] truncate font-medium">{s.tag}</TableCell>
                    <TableCell className="text-right">
                      <Badge variant={scoreVariant(s)} className="tnum">
                        {scoreLabel(s)}
                      </Badge>
                    </TableCell>
                    <TableCell className="tnum text-right">{Math.round(s.reliability)}</TableCell>
                    <TableCell className="tnum text-right">
                      {Math.round(s.latency_score)}
                      {s.latency_ms ? <span className="text-muted-foreground"> · {s.latency_ms}ms</span> : null}
                    </TableCell>
                    <TableCell className="tnum text-right">{Math.round(s.throughput_score)}</TableCell>
                    <TableCell className="tnum text-right">{s.samples}</TableCell>
                    <TableCell className="text-xs">
                      {s.blackhole ? (
                        <span className="font-medium text-destructive">
                          {k('blackholeShort', { n: s.blackhole_streak ?? 0 })}
                        </span>
                      ) : !s.preferred ? (
                        <span className="text-destructive">
                          {k('demoted')}
                          {s.breaker_remaining_seconds ? ` · ${s.breaker_remaining_seconds}s` : ''}
                        </span>
                      ) : s.warming ? (
                        <span className="text-warning">{k('warmingShort')}</span>
                      ) : s.fail_streak > 0 ? (
                        <span className="text-warning">{k('failStreak', { n: s.fail_streak })}</span>
                      ) : (
                        <span className="text-muted-foreground">{k('okStreak', { n: s.ok_streak })}</span>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
          <p className="mt-2 text-[11px] leading-relaxed text-muted-foreground">{k('demotedNote')}</p>
        </CardContent>
      )}
    </Card>
  );
}

const PG_TYPES: PGType[] = ['urltest', 'select'];
const PG_FILTERS: PGFilter[] = ['country', 'regex', 'manual'];

// FailoverSettings surfaces the URLTest knobs that used to be hard-coded. They
// are here rather than buried in a JSON blob because the one that matters —
// interrupting live connections — is the difference between a working login and
// a page that dies halfway through, and there was no way to see or change it.
function FailoverSettings({
  value,
  onChange,
}: {
  value: ProxyFailover;
  onChange: (v: ProxyFailover) => void;
}) {
  const { t } = useTranslation();
  const k = (s: string) => t(`pages.proxies.groups.failover.${s}`);
  // An empty field means "unset" => the gateway default. Show the default as the
  // placeholder so the box is never a mystery blank.
  const num = (
    label: string,
    hint: string,
    field: 'probe_interval_seconds' | 'tolerance_ms' | 'idle_timeout_seconds',
  ) => (
    <div>
      <label className="text-xs text-muted-foreground">{label}</label>
      <Input
        className="mt-1 font-mono"
        type="number"
        min={0}
        placeholder={`${PROXY_FAILOVER_DEFAULTS[field]} (${k('defaultSuffix')})`}
        value={value[field] ?? ''}
        onChange={(e) => {
          const n = e.target.value.trim() === '' ? undefined : Number(e.target.value);
          onChange({ ...value, [field]: Number.isFinite(n as number) ? n : undefined });
        }}
      />
      <p className="mt-1 text-[11px] leading-relaxed text-muted-foreground">{hint}</p>
    </div>
  );

  return (
    <div className="rounded-md border px-3 py-2.5">
      <div className="text-sm font-medium">{k('title')}</div>
      <p className="mt-0.5 mb-3 text-xs leading-relaxed text-muted-foreground">{k('hint')}</p>
      <div className="grid gap-3 sm:grid-cols-3">
        {num(k('intervalLabel'), k('intervalHint'), 'probe_interval_seconds')}
        {num(k('toleranceLabel'), k('toleranceHint'), 'tolerance_ms')}
        {num(k('idleLabel'), k('idleHint'), 'idle_timeout_seconds')}
      </div>
      <label className="mt-3 flex items-start gap-2 text-sm">
        <Switch
          className="mt-0.5"
          checked={value.interrupt_existing_connections}
          onCheckedChange={(v) => onChange({ ...value, interrupt_existing_connections: v })}
        />
        <span>
          {k('interruptLabel')}
          <p className="text-[11px] leading-relaxed font-normal text-muted-foreground">{k('interruptHint')}</p>
        </span>
      </label>
      {value.interrupt_existing_connections && (
        <p className="mt-2 rounded-md border border-amber-500/40 bg-amber-500/10 px-2 py-1.5 text-[11px] leading-relaxed text-amber-700 dark:text-amber-400">
          {k('interruptWarn')}
        </p>
      )}
    </div>
  );
}

// ScoringSettings is the "advanced" half of the transparency requirement: the
// weights are adjustable, but they are shown next to the formula they feed and
// next to what each term currently measures across the fleet — so a number here
// is never a knob whose effect you have to guess at.
//
// Every input is "unset => gateway default", and the placeholder is the value
// actually in force (resolved by the backend, not re-derived here — a second
// copy of the defaults in the console is exactly how the two drift apart).
function ScoringSettings({
  value,
  onChange,
  live,
}: {
  value: ProxyScoring;
  onChange: (v: ProxyScoring) => void;
  live?: ProxyScores;
}) {
  const { t } = useTranslation();
  const k = (s: string, o?: Record<string, unknown>) => t(`pages.proxies.groups.scoring.${s}`, o) as string;
  const [open, setOpen] = useState(false);
  const cfg = live?.config ?? {};

  // Fleet average per term: what the weights are currently multiplying. Only
  // measured nodes count — averaging in the warm-up 100s would report a healthy
  // fleet the moment a subscription is applied.
  const measured = (live?.scores ?? []).filter((s) => !s.warming);
  const avg = (pick: (s: ProxyScore) => number) =>
    measured.length ? Math.round(measured.reduce((a, s) => a + pick(s), 0) / measured.length) : undefined;
  const now = {
    reliability: avg((s) => s.reliability),
    latency: avg((s) => s.latency_score),
    throughput: avg((s) => s.throughput_score),
  };

  type NumField = Exclude<keyof ProxyScoring, 'disabled'>;
  const num = (label: string, hint: string, field: NumField, nowValue?: number) => (
    <div>
      <label className="flex items-center justify-between gap-2 text-xs text-muted-foreground">
        <span>{label}</span>
        {nowValue !== undefined && <span className="tnum text-[11px]">{k('nowIs', { v: nowValue })}</span>}
      </label>
      <Input
        className="mt-1 font-mono"
        type="number"
        min={0}
        placeholder={cfg[field] !== undefined ? `${cfg[field]} (${k('defaultSuffix')})` : ''}
        value={value[field] ?? ''}
        onChange={(e) => {
          const n = e.target.value.trim() === '' ? undefined : Number(e.target.value);
          onChange({ ...value, [field]: Number.isFinite(n as number) ? n : undefined });
        }}
      />
      <p className="mt-1 text-[11px] leading-relaxed text-muted-foreground">{hint}</p>
    </div>
  );

  return (
    <div className="rounded-md border px-3 py-2.5">
      <button type="button" className="flex w-full items-center gap-1.5 text-left" onClick={() => setOpen((v) => !v)}>
        {open ? <ChevronDown className="size-3.5" /> : <ChevronRight className="size-3.5" />}
        <span className="text-sm font-medium">{k('title')}</span>
        {value.disabled && <Badge variant="muted">{k('off')}</Badge>}
      </button>
      <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">{k('hint')}</p>
      {live && <p className="mt-1 font-mono text-[11px] text-muted-foreground">{live.formula}</p>}

      {open && (
        <div className="mt-3 space-y-3">
          <label className="flex items-start gap-2 text-sm">
            <Switch
              className="mt-0.5"
              checked={!value.disabled}
              onCheckedChange={(v) => onChange({ ...value, disabled: !v })}
            />
            <span>
              {k('enableLabel')}
              <p className="text-[11px] leading-relaxed font-normal text-muted-foreground">{k('enableHint')}</p>
            </span>
          </label>

          <div>
            <div className="mb-1.5 text-xs font-medium">{k('weightsTitle')}</div>
            <p className="mb-2 text-[11px] leading-relaxed text-muted-foreground">{k('weightsHint')}</p>
            <div className="grid gap-3 sm:grid-cols-3">
              {num(k('wRel'), k('wRelHint'), 'weight_reliability', now.reliability)}
              {num(k('wLat'), k('wLatHint'), 'weight_latency', now.latency)}
              {num(k('wTp'), k('wTpHint'), 'weight_throughput', now.throughput)}
            </div>
          </div>

          <div className="grid gap-3 sm:grid-cols-3">
            {num(k('minSamples'), k('minSamplesHint'), 'min_samples')}
            {num(k('tieMargin'), k('tieMarginHint'), 'tie_margin_points')}
            {num(k('staleHours'), k('staleHoursHint'), 'stale_hours')}
            {num(k('blackholeStreak'), k('blackholeStreakHint'), 'blackhole_streak')}
          </div>

          <div className="grid gap-3 sm:grid-cols-3">
            {num(k('reward'), k('rewardHint'), 'reward_per_success')}
            {num(k('penalty'), k('penaltyHint'), 'penalty_per_failure')}
            {num(k('maxStreak'), k('maxStreakHint'), 'max_streak')}
          </div>

          <div className="grid gap-3 sm:grid-cols-3">
            {num(k('latGood'), k('latGoodHint'), 'latency_good_ms')}
            {num(k('latBad'), k('latBadHint'), 'latency_bad_ms')}
            {num(k('tpGood'), k('tpGoodHint'), 'throughput_good_kbps')}
          </div>

          <div>
            <div className="mb-1.5 text-xs font-medium">{k('breakerTitle')}</div>
            <p className="mb-2 text-[11px] leading-relaxed text-muted-foreground">{k('breakerHint')}</p>
            <div className="grid gap-3 sm:grid-cols-3">
              {num(k('brFailures'), k('brFailuresHint'), 'breaker_failures')}
              {num(k('brDelay'), k('brDelayHint'), 'breaker_delay_seconds')}
              {num(k('brSuccesses'), k('brSuccessesHint'), 'breaker_successes')}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// GroupSettings edits the proxy-group config (auto-country + custom groups) as a
// local draft, saved explicitly (each save rebuilds the data plane). The group
// list/selection itself is rendered by the Proxies list below, from the Clash API.
function GroupSettings() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ['proxygroups'], queryFn: api.proxyGroups });
  // The resolved policy + live measurements shown next to the weight inputs.
  // Advisory: an old gateway that 503s here still gets the editor.
  const { data: liveScores } = useQuery({ queryKey: ['proxyscores'], queryFn: api.proxyScores, retry: false });
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
      qc.invalidateQueries({ queryKey: ['proxyscores'] });
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

        <div className="rounded-md border px-3 py-2.5">
          <div className="text-sm font-medium">🌏 {t('pages.proxies.groups.overseasTitle')}</div>
          <p className="mt-0.5 mb-2 text-xs leading-relaxed text-muted-foreground">{t('pages.proxies.groups.overseasHint')}</p>
          <label className="text-xs text-muted-foreground">{t('pages.proxies.groups.excludeLabel')}</label>
          <Input
            className="mt-1 font-mono"
            placeholder="HK, MO, CN"
            value={(draft.exclude_countries ?? []).join(', ')}
            onChange={(e) =>
              setDraft({
                ...draft,
                exclude_countries: e.target.value
                  .split(',')
                  .map((s) => s.trim().toUpperCase())
                  .filter(Boolean),
              })
            }
          />
        </div>

        <FailoverSettings
          value={draft.failover}
          onChange={(failover) => setDraft({ ...draft, failover })}
        />

        <ScoringSettings
          value={draft.scoring}
          onChange={(scoring) => setDraft({ ...draft, scoring })}
          live={liveScores}
        />

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
