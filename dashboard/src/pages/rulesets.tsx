import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { ChevronLeft, ChevronRight, Download, Eye, Plus, Trash2, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { api, CatalogEntry } from '@/lib/api';
import { PageHeader } from '@/components/page-header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';

const ROLES = ['block', 'allow-direct', 'allow-proxy'];
const roleBadge = (r: string) =>
  r === 'block' ? 'danger' : r === 'allow-direct' ? 'muted' : 'success';

export default function RuleSets({ embedded }: { embedded?: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [viewTag, setViewTag] = useState<string | null>(null);
  const invalidate = () => qc.invalidateQueries({ queryKey: ['rulesets'] });
  const { data: sets } = useQuery({ queryKey: ['rulesets'], queryFn: api.rulesets });
  const { data: catalog = [] } = useQuery({ queryKey: ['ruleCatalog'], queryFn: api.ruleCatalog });

  const err = (e: unknown) => toast.error(String((e as Error).message));
  const add = useMutation({ mutationFn: api.addRuleSet, onSuccess: () => { toast.success(t('pages.rulesets.importSuccessToast')); invalidate(); }, onError: err });
  const patch = useMutation({ mutationFn: (v: { tag: string; patch: { enabled?: boolean; role?: string } }) => api.patchRuleSet(v.tag, v.patch), onSuccess: invalidate, onError: err });
  const del = useMutation({ mutationFn: api.delRuleSet, onSuccess: invalidate, onError: err });

  const [tag, setTag] = useState('');
  const [url, setUrl] = useState('');
  const [role, setRole] = useState('allow-proxy');

  const imported = new Set((sets?.sets ?? []).map((s) => s.tag));

  return (
    <div>
      {!embedded && <PageHeader title={t('pages.rulesets.title')} description={t('pages.rulesets.description')} />}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="pb-3"><CardTitle className="text-sm">{t('pages.rulesets.catalogTitle')}</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {catalog.map((e: CatalogEntry) => (
              <div key={e.tag} className="flex items-center gap-3 rounded-md border px-3 py-2">
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm font-medium">{e.name}</div>
                  <div className="tnum truncate text-xs text-muted-foreground">{e.tag}</div>
                </div>
                <Badge variant={roleBadge(e.suggested_role)}>{e.suggested_role}</Badge>
                {imported.has(e.tag) ? (
                  <Badge variant="muted">{t('pages.rulesets.importedBadge')}</Badge>
                ) : (
                  <div className="flex gap-1">
                    <Button size="xs" variant="secondary" disabled={add.isPending} onClick={() => add.mutate({ catalog_tag: e.tag })}>
                      <Download className="size-3.5" /> {t('pages.rulesets.importButton')}
                    </Button>
                    <Button size="xs" variant="ghost" disabled={add.isPending} onClick={() => add.mutate({ catalog_tag: e.tag, mirror: true })}>
                      {t('pages.rulesets.mirrorButton')}
                    </Button>
                  </div>
                )}
              </div>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3"><CardTitle className="text-sm">{t('pages.rulesets.addUrlTitle')}</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            <Input placeholder={t('pages.rulesets.tagPlaceholder')} value={tag} onChange={(e) => setTag(e.target.value)} />
            <Input placeholder={t('pages.rulesets.urlPlaceholder')} value={url} onChange={(e) => setUrl(e.target.value)} />
            <div className="flex gap-2">
              <Select value={role} onValueChange={setRole}>
                <SelectTrigger className="flex-1"><SelectValue /></SelectTrigger>
                <SelectContent>{ROLES.map((r) => <SelectItem key={r} value={r}>{r}</SelectItem>)}</SelectContent>
              </Select>
              <Button disabled={!tag.trim() || !url.trim() || add.isPending} onClick={() => { add.mutate({ tag: tag.trim(), url: url.trim(), role, type: 'remote' }); setTag(''); setUrl(''); }}>
                <Plus className="size-4" /> {t('pages.rulesets.addButton')}
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">{t('pages.rulesets.roleHint')}</p>
          </CardContent>
        </Card>
      </div>

      <Card className="mt-4 overflow-hidden">
        <CardHeader className="pb-2"><CardTitle className="text-sm">{t('pages.rulesets.importedTableTitle')}</CardTitle></CardHeader>
        <CardContent className="px-0 pb-0">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="w-16">{t('pages.rulesets.columnOn')}</TableHead>
                <TableHead>{t('pages.rulesets.columnName')}</TableHead>
                <TableHead className="w-40">{t('pages.rulesets.columnRole')}</TableHead>
                <TableHead>{t('pages.rulesets.columnSource')}</TableHead>
                <TableHead></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(!sets || sets.sets.length === 0) && (
                <TableRow className="hover:bg-transparent">
                  <TableCell colSpan={5} className="py-10 text-center text-muted-foreground">{t('pages.rulesets.emptyImported')}</TableCell>
                </TableRow>
              )}
              {(sets?.sets ?? []).map((rs) => (
                <TableRow key={rs.tag}>
                  <TableCell>
                    <Switch checked={rs.enabled} onCheckedChange={(v) => patch.mutate({ tag: rs.tag, patch: { enabled: v } })} />
                  </TableCell>
                  <TableCell className="font-medium">{rs.name}</TableCell>
                  <TableCell>
                    <Select value={rs.role} onValueChange={(v) => patch.mutate({ tag: rs.tag, patch: { role: v } })}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>{ROLES.map((r) => <SelectItem key={r} value={r}>{r}</SelectItem>)}</SelectContent>
                    </Select>
                  </TableCell>
                  <TableCell className="tnum max-w-[280px] truncate text-xs text-muted-foreground">{rs.url || rs.path}</TableCell>
                  <TableCell className="text-right">
                    <Button size="icon" variant="ghost" className="size-7" title={t('pages.rulesets.viewButton')} onClick={() => setViewTag(rs.tag)}>
                      <Eye className="size-3.5" />
                    </Button>
                    <Button size="icon" variant="ghost" className="size-7 text-destructive" onClick={() => del.mutate(rs.tag)}>
                      <Trash2 className="size-3.5" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {viewTag && <RuleSetViewer tag={viewTag} onClose={() => setViewTag(null)} />}
    </div>
  );
}

function RuleSetViewer({ tag, onClose }: { tag: string; onClose: () => void }) {
  const { t } = useTranslation();
  const [q, setQ] = useState('');
  const [offset, setOffset] = useState(0);
  const limit = 200;
  const { data, isLoading, isError } = useQuery({
    queryKey: ['rulesetRules', tag, q, offset],
    queryFn: () => api.rulesetRules(tag, q, offset, limit),
  });
  const total = data?.total ?? 0;

  return (
    <Card className="mt-4 overflow-hidden">
      <CardHeader className="flex-row items-center gap-2 pb-3">
        <CardTitle className="text-sm">
          {t('pages.rulesets.viewerTitle')} <span className="tnum text-muted-foreground">{tag}</span>
        </CardTitle>
        {data && (
          <Badge variant="muted" className="tnum">
            {data.count}
          </Badge>
        )}
        <Button size="icon" variant="ghost" className="ml-auto size-7" onClick={onClose}>
          <X className="size-4" />
        </Button>
      </CardHeader>
      <CardContent className="space-y-3">
        <Input
          placeholder={t('pages.rulesets.viewerSearch')}
          value={q}
          onChange={(e) => {
            setQ(e.target.value);
            setOffset(0);
          }}
        />
        {isError && <p className="text-sm text-destructive">{t('pages.rulesets.viewerError')}</p>}
        {isLoading && <p className="py-6 text-center text-sm text-muted-foreground">{t('common.loading')}</p>}
        {data && (
          <>
            <div className="max-h-[420px] overflow-auto rounded-md border">
              {data.entries.length === 0 ? (
                <p className="py-8 text-center text-sm text-muted-foreground">{t('pages.rulesets.viewerEmpty')}</p>
              ) : (
                data.entries.map((e, i) => (
                  <div key={i} className="flex items-center gap-2 border-b px-3 py-1 last:border-0">
                    <Badge variant="outline" className="w-32 shrink-0 justify-center font-mono text-[10px]">
                      {e.kind}
                    </Badge>
                    <span className="tnum truncate text-xs">{e.value}</span>
                  </div>
                ))
              )}
            </div>
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <span className="tnum">
                {total === 0 ? 0 : offset + 1}–{Math.min(offset + limit, total)} / {total}
              </span>
              <div className="flex gap-1">
                <Button size="icon" variant="ghost" className="size-7" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))}>
                  <ChevronLeft className="size-4" />
                </Button>
                <Button size="icon" variant="ghost" className="size-7" disabled={offset + limit >= total} onClick={() => setOffset(offset + limit)}>
                  <ChevronRight className="size-4" />
                </Button>
              </div>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}
