import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Check, Download, Loader2, Plus, RefreshCw, Trash2 } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { api } from '@/lib/api';
import { PageHeader } from '@/components/page-header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';

export default function Subscriptions() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: ['subs'] });
  const { data: subs = [] } = useQuery({ queryKey: ['subs'], queryFn: api.subs });

  const err = (e: unknown) => toast.error(String((e as Error).message));
  const addUrl = useMutation({ mutationFn: (v: { name: string; url: string; via?: string }) => api.addSub(v.name, v.url, undefined, v.via), onSuccess: invalidate, onError: err });
  const paste = useMutation({ mutationFn: (v: { name: string; content: string }) => api.importNodes(v.name, v.content), onSuccess: invalidate, onError: err });
  const apply = useMutation({ mutationFn: api.applySub, onSuccess: () => { toast.success(t('pages.subscriptions.applySuccess')); invalidate(); }, onError: err });
  const refresh = useMutation({ mutationFn: api.refreshSub, onSuccess: invalidate, onError: err });
  const del = useMutation({ mutationFn: api.delSub, onSuccess: invalidate, onError: err });

  const [uName, setUName] = useState('');
  const [uUrl, setUUrl] = useState('');
  const [uVia, setUVia] = useState('');
  const [pName, setPName] = useState('');
  const [pContent, setPContent] = useState('');

  return (
    <div>
      <PageHeader title={t('pages.subscriptions.title')} description={t('pages.subscriptions.desc')} />

      <div className="grid gap-4 lg:grid-cols-5">
        <Card className="lg:col-span-2">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm">{t('pages.subscriptions.addNodes')}</CardTitle>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="url">
              <TabsList className="w-full">
                <TabsTrigger value="url" className="flex-1">{t('pages.subscriptions.tabUrl')}</TabsTrigger>
                <TabsTrigger value="paste" className="flex-1">{t('pages.subscriptions.tabPaste')}</TabsTrigger>
              </TabsList>
              <TabsContent value="url" className="space-y-2">
                <Input placeholder={t('pages.subscriptions.namePh')} value={uName} onChange={(e) => setUName(e.target.value)} />
                <Input placeholder={t('pages.subscriptions.urlPh')} value={uUrl} onChange={(e) => setUUrl(e.target.value)} />
                <Input placeholder={t('pages.subscriptions.viaPh')} value={uVia} onChange={(e) => setUVia(e.target.value)} />
                <Button
                  className="w-full"
                  disabled={!uUrl.trim() || addUrl.isPending}
                  onClick={() => { addUrl.mutate({ name: uName.trim() || 'sub', url: uUrl.trim(), via: uVia.trim() || undefined }); setUName(''); setUUrl(''); setUVia(''); }}
                >
                  {addUrl.isPending ? <Loader2 className="size-4 animate-spin" /> : <Plus className="size-4" />} {t('pages.subscriptions.fetchAndAdd')}
                </Button>
              </TabsContent>
              <TabsContent value="paste" className="space-y-2">
                <Input placeholder={t('pages.subscriptions.namePh')} value={pName} onChange={(e) => setPName(e.target.value)} />
                <textarea
                  className="min-h-28 w-full resize-y rounded-md border bg-background/40 p-2.5 font-mono text-xs shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/60"
                  placeholder={t('pages.subscriptions.contentPh')}
                  value={pContent}
                  onChange={(e) => setPContent(e.target.value)}
                />
                <Button
                  className="w-full"
                  disabled={!pContent.trim() || paste.isPending}
                  onClick={() => { paste.mutate({ name: pName.trim() || 'pasted', content: pContent.trim() }); setPName(''); setPContent(''); }}
                >
                  <Plus className="size-4" /> {t('pages.subscriptions.import')}
                </Button>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>

        <Card className="lg:col-span-3 overflow-hidden">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">{t('pages.subscriptions.subscriptions')}</CardTitle>
          </CardHeader>
          <CardContent className="px-0 pb-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead>{t('pages.subscriptions.colName')}</TableHead>
                  <TableHead className="text-right">{t('pages.subscriptions.colNodes')}</TableHead>
                  <TableHead></TableHead>
                  <TableHead className="text-right">{t('pages.subscriptions.colActions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {subs.length === 0 && (
                  <TableRow className="hover:bg-transparent">
                    <TableCell colSpan={4} className="py-10 text-center text-muted-foreground">{t('pages.subscriptions.empty')}</TableCell>
                  </TableRow>
                )}
                {subs.map((s) => (
                  <TableRow key={s.id}>
                    <TableCell>
                      <div className="flex items-center gap-2 font-medium">
                        {s.name}
                        {s.applied && <Badge variant="success"><Check className="size-3" /> {t('pages.subscriptions.active')}</Badge>}
                      </div>
                      <div className="max-w-[260px] truncate text-xs text-muted-foreground">{s.url || t('pages.subscriptions.pasted')}</div>
                      {s.last_error && <div className="max-w-[260px] truncate text-xs text-destructive">{s.last_error}</div>}
                    </TableCell>
                    <TableCell className="tnum text-right">{s.node_count}</TableCell>
                    <TableCell></TableCell>
                    <TableCell>
                      <div className="flex items-center justify-end gap-1">
                        <Button size="xs" variant={s.applied ? 'secondary' : 'default'} disabled={apply.isPending} onClick={() => apply.mutate(s.id)}>
                          {t('pages.subscriptions.apply')}
                        </Button>
                        <Button size="icon" variant="ghost" className="size-7" disabled={refresh.isPending} onClick={() => refresh.mutate(s.id)}>
                          <RefreshCw className="size-3.5" />
                        </Button>
                        <Button size="icon" variant="ghost" className="size-7 text-destructive" onClick={() => del.mutate(s.id)}>
                          <Trash2 className="size-3.5" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>
      <p className="mt-3 flex items-center gap-1.5 text-xs text-muted-foreground">
        <Download className="size-3.5" /> {t('pages.subscriptions.tipPrefix')} <code className="tnum">trust-proxy proxy gen</code>{t('pages.subscriptions.tipSuffix')}
      </p>
    </div>
  );
}
