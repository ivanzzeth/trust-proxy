import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { ArrowDown, ArrowUp, Download, Package, Plus, Trash2 } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { api, CRAction, CRMatch, CustomRule, PackPreset } from '@/lib/api';
import { PageHeader } from '@/components/page-header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';

const MATCHES: CRMatch[] = ['domain', 'domain_suffix', 'keyword', 'regex', 'ip_cidr'];
const ACTIONS: CRAction[] = ['direct', 'proxy', 'block', 'node'];
const actionBadge = (a: CRAction) =>
  a === 'block' ? 'danger' : a === 'proxy' ? 'success' : a === 'node' ? 'default' : 'muted';

export default function CustomRules({ embedded }: { embedded?: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['customrules'] });
    qc.invalidateQueries({ queryKey: ['status'] });
  };
  const err = (e: unknown) => toast.error(String((e as Error).message));

  const { data: rules = [] } = useQuery({ queryKey: ['customrules'], queryFn: api.customRules });
  const { data: proxyData } = useQuery({ queryKey: ['proxies'], queryFn: api.proxies });
  const { data: catalog = [] } = useQuery({ queryKey: ['packsCatalog'], queryFn: api.packsCatalog });
  const nodes = proxyData?.proxies?.['proxy']?.all ?? [];

  const add = useMutation({ mutationFn: api.addCR, onSuccess: invalidate, onError: err });
  const patch = useMutation({ mutationFn: (v: { id: string; patch: Partial<Omit<CustomRule, 'id'>> }) => api.patchCR(v.id, v.patch), onSuccess: invalidate, onError: err });
  const del = useMutation({ mutationFn: api.delCR, onSuccess: invalidate, onError: err });
  const move = useMutation({ mutationFn: (v: { id: string; dir: number }) => api.moveCR(v.id, v.dir), onSuccess: invalidate, onError: err });
  const applyPack = useMutation({ mutationFn: api.applyPack, onSuccess: invalidate, onError: err });
  const packEnable = useMutation({ mutationFn: (v: { name: string; enabled: boolean }) => api.setPackEnabled(v.name, v.enabled), onSuccess: invalidate, onError: err });
  const packDel = useMutation({ mutationFn: api.delPack, onSuccess: invalidate, onError: err });

  // Distinct packs present, with their all-enabled state (for the manage strip).
  const packs = Array.from(new Set(rules.map((r) => r.pack).filter((p): p is string => !!p)));
  const packAllOn = (name: string) => rules.filter((r) => r.pack === name).every((r) => r.enabled);
  const importedPacks = new Set(packs);

  const [match, setMatch] = useState<CRMatch>('domain_suffix');
  const [value, setValue] = useState('');
  const [action, setAction] = useState<CRAction>('proxy');
  const [node, setNode] = useState('');

  const submit = () => {
    const v = value.trim();
    if (!v) return;
    if (action === 'node' && !node) {
      toast.error(t('pages.customRules.nodeRequired'));
      return;
    }
    add.mutate({ match, value: v, action, node: action === 'node' ? node : undefined, enabled: true });
    setValue('');
  };

  // Switching a rule's action to "node" needs a node; default to the first live one.
  const changeAction = (r: CustomRule, a: CRAction) => {
    if (a === 'node') {
      const n = r.node && nodes.includes(r.node) ? r.node : nodes[0];
      if (!n) {
        toast.error(t('pages.customRules.noNodes'));
        return;
      }
      patch.mutate({ id: r.id, patch: { action: a, node: n } });
    } else {
      patch.mutate({ id: r.id, patch: { action: a } });
    }
  };

  return (
    <div>
      {!embedded && <PageHeader title={t('pages.customRules.title')} description={t('pages.customRules.desc')} />}

      <Card>
        <CardHeader className="pb-3"><CardTitle className="text-sm">{t('pages.customRules.addTitle')}</CardTitle></CardHeader>
        <CardContent>
          <div className="flex flex-wrap items-center gap-2">
            <Select value={match} onValueChange={(v) => setMatch(v as CRMatch)}>
              <SelectTrigger className="w-40"><SelectValue /></SelectTrigger>
              <SelectContent>{MATCHES.map((m) => <SelectItem key={m} value={m}>{t(`pages.customRules.match.${m}`)}</SelectItem>)}</SelectContent>
            </Select>
            <Input
              className="min-w-[200px] flex-1"
              placeholder={t('pages.customRules.valuePlaceholder')}
              value={value}
              onChange={(e) => setValue(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && submit()}
            />
            <Select value={action} onValueChange={(v) => setAction(v as CRAction)}>
              <SelectTrigger className="w-32"><SelectValue /></SelectTrigger>
              <SelectContent>{ACTIONS.map((a) => <SelectItem key={a} value={a}>{t(`pages.customRules.action.${a}`)}</SelectItem>)}</SelectContent>
            </Select>
            {action === 'node' && (
              <Select value={node} onValueChange={setNode}>
                <SelectTrigger className="w-40"><SelectValue placeholder={t('pages.customRules.pickNode')} /></SelectTrigger>
                <SelectContent>{nodes.map((n) => <SelectItem key={n} value={n}>{n}</SelectItem>)}</SelectContent>
              </Select>
            )}
            <Button disabled={!value.trim() || add.isPending} onClick={submit}>
              <Plus className="size-4" /> {t('pages.customRules.addButton')}
            </Button>
          </div>
          <p className="mt-2 text-xs text-muted-foreground">{t('pages.customRules.hint')}</p>
        </CardContent>
      </Card>

      <Card className="mt-4">
        <CardHeader className="pb-3"><CardTitle className="text-sm">{t('pages.customRules.presetsTitle')}</CardTitle></CardHeader>
        <CardContent className="space-y-2">
          {catalog.map((p: PackPreset) => (
            <div key={p.name} className="flex items-center gap-3 rounded-md border px-3 py-2">
              <Package className="size-4 shrink-0 text-muted-foreground" />
              <div className="min-w-0 flex-1">
                <div className="text-sm font-medium">{p.name}</div>
                <div className="truncate text-xs text-muted-foreground">{p.description}</div>
              </div>
              <Badge variant="muted" className="tnum">{p.rules.length}</Badge>
              {importedPacks.has(p.name) ? (
                <Badge variant="muted">{t('pages.customRules.importedBadge')}</Badge>
              ) : (
                <Button size="xs" variant="secondary" disabled={applyPack.isPending} onClick={() => applyPack.mutate(p.name)}>
                  <Download className="size-3.5" /> {t('pages.customRules.importButton')}
                </Button>
              )}
            </div>
          ))}
        </CardContent>
      </Card>

      {packs.length > 0 && (
        <Card className="mt-4">
          <CardHeader className="pb-3"><CardTitle className="text-sm">{t('pages.customRules.packsTitle')}</CardTitle></CardHeader>
          <CardContent className="flex flex-wrap gap-2">
            {packs.map((name) => (
              <div key={name} className="flex items-center gap-2 rounded-md border px-3 py-1.5">
                <span className="text-sm font-medium">{name}</span>
                <Badge variant="muted" className="tnum">{rules.filter((r) => r.pack === name).length}</Badge>
                <Switch checked={packAllOn(name)} onCheckedChange={(v) => packEnable.mutate({ name, enabled: v })} title={t('pages.customRules.packToggle')} />
                <Button size="icon" variant="ghost" className="size-6 text-destructive" onClick={() => packDel.mutate(name)} title={t('pages.customRules.packDelete')}>
                  <Trash2 className="size-3.5" />
                </Button>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      <Card className="mt-4 overflow-hidden">
        <CardHeader className="pb-2"><CardTitle className="text-sm">{t('pages.customRules.tableTitle')}</CardTitle></CardHeader>
        <CardContent className="px-0 pb-0">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="w-16">{t('pages.customRules.columnOrder')}</TableHead>
                <TableHead className="w-14">{t('pages.customRules.columnOn')}</TableHead>
                <TableHead className="w-40">{t('pages.customRules.columnMatch')}</TableHead>
                <TableHead>{t('pages.customRules.columnValue')}</TableHead>
                <TableHead className="w-56">{t('pages.customRules.columnAction')}</TableHead>
                <TableHead></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rules.length === 0 && (
                <TableRow className="hover:bg-transparent">
                  <TableCell colSpan={6} className="py-10 text-center text-muted-foreground">{t('pages.customRules.empty')}</TableCell>
                </TableRow>
              )}
              {rules.map((r, i) => {
                const stale = r.action === 'node' && !nodes.includes(r.node ?? '');
                return (
                  <TableRow key={r.id}>
                    <TableCell>
                      <div className="flex">
                        <Button size="icon" variant="ghost" className="size-6" disabled={i === 0} onClick={() => move.mutate({ id: r.id, dir: -1 })}>
                          <ArrowUp className="size-3.5" />
                        </Button>
                        <Button size="icon" variant="ghost" className="size-6" disabled={i === rules.length - 1} onClick={() => move.mutate({ id: r.id, dir: 1 })}>
                          <ArrowDown className="size-3.5" />
                        </Button>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Switch checked={r.enabled} onCheckedChange={(v) => patch.mutate({ id: r.id, patch: { enabled: v } })} />
                    </TableCell>
                    <TableCell><Badge variant="muted">{t(`pages.customRules.match.${r.match}`)}</Badge></TableCell>
                    <TableCell className="max-w-[260px]">
                      <div className="flex items-center gap-2">
                        <span className="tnum truncate">{r.value}</span>
                        {r.pack && <Badge variant="outline" className="shrink-0 text-[10px]">{r.pack}</Badge>}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Select value={r.action} onValueChange={(v) => changeAction(r, v as CRAction)}>
                          <SelectTrigger className="w-28"><SelectValue><Badge variant={actionBadge(r.action)}>{t(`pages.customRules.action.${r.action}`)}</Badge></SelectValue></SelectTrigger>
                          <SelectContent>{ACTIONS.map((a) => <SelectItem key={a} value={a}>{t(`pages.customRules.action.${a}`)}</SelectItem>)}</SelectContent>
                        </Select>
                        {r.action === 'node' && (
                          <Select value={r.node ?? ''} onValueChange={(v) => patch.mutate({ id: r.id, patch: { node: v } })}>
                            <SelectTrigger className="w-32"><SelectValue placeholder={t('pages.customRules.pickNode')} /></SelectTrigger>
                            <SelectContent>
                              {nodes.map((n) => <SelectItem key={n} value={n}>{n}</SelectItem>)}
                              {stale && r.node && <SelectItem value={r.node}>{r.node}</SelectItem>}
                            </SelectContent>
                          </Select>
                        )}
                        {stale && <Badge variant="danger">{t('pages.customRules.stale')}</Badge>}
                      </div>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button size="icon" variant="ghost" className="size-7 text-destructive" onClick={() => del.mutate(r.id)}>
                        <Trash2 className="size-3.5" />
                      </Button>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
