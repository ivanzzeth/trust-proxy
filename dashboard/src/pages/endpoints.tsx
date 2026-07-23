import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Network, Plus, Trash2 } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { api } from '@/lib/api';
import { PageHeader } from '@/components/page-header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

export default function Endpoints() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { data: eps = [] } = useQuery({ queryKey: ['endpoints'], queryFn: api.endpoints });
  const invalidate = () => qc.invalidateQueries({ queryKey: ['endpoints'] });
  const err = (e: unknown) => toast.error(String((e as Error).message));
  const add = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.addEndpoint(body),
    onSuccess: () => {
      toast.success(t('pages.endpoints.toastAdded'));
      invalidate();
    },
    onError: err,
  });
  const toggle = useMutation({ mutationFn: (v: { tag: string; on: boolean }) => api.patchEndpoint(v.tag, v.on), onSuccess: invalidate, onError: err });
  const del = useMutation({ mutationFn: api.delEndpoint, onSuccess: invalidate, onError: err });

  // wireguard paste
  const [wgName, setWgName] = useState('');
  const [wgConf, setWgConf] = useState('');
  // tailscale
  const [tsName, setTsName] = useState('');
  const [tsKey, setTsKey] = useState('');
  const [tsHost, setTsHost] = useState('');
  const [tsExit, setTsExit] = useState('');

  return (
    <div>
      <PageHeader
        title={t('pages.endpoints.title')}
        description={t('pages.endpoints.description')}
      />

      <div className="grid gap-4 lg:grid-cols-5">
        <Card className="lg:col-span-2">
          <CardHeader className="pb-3"><CardTitle className="text-sm">{t('pages.endpoints.addEndpointTitle')}</CardTitle></CardHeader>
          <CardContent>
            <Tabs defaultValue="wg">
              <TabsList className="w-full">
                <TabsTrigger value="wg" className="flex-1">WireGuard</TabsTrigger>
                <TabsTrigger value="ts" className="flex-1">Tailscale</TabsTrigger>
              </TabsList>
              <TabsContent value="wg" className="space-y-2">
                <Input placeholder={t('pages.endpoints.tagPlaceholder')} value={wgName} onChange={(e) => setWgName(e.target.value)} />
                <textarea
                  className="min-h-40 w-full resize-y rounded-md border bg-background/40 p-2.5 font-mono text-xs shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/60"
                  placeholder={'[Interface]\nPrivateKey = ...\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = ...\nEndpoint = host:51820\nAllowedIPs = 0.0.0.0/0, ::/0'}
                  value={wgConf}
                  onChange={(e) => setWgConf(e.target.value)}
                />
                <Button
                  className="w-full"
                  disabled={!wgName.trim() || !wgConf.trim() || add.isPending}
                  onClick={() => { add.mutate({ type: 'wireguard', tag: wgName.trim(), conf: wgConf }); setWgName(''); setWgConf(''); }}
                >
                  <Plus className="size-4" /> {t('pages.endpoints.addFromWgButton')}
                </Button>
                <p className="text-xs text-muted-foreground">{t('pages.endpoints.wgHint')}</p>
              </TabsContent>
              <TabsContent value="ts" className="space-y-2">
                <Input placeholder={t('pages.endpoints.tagPlaceholder')} value={tsName} onChange={(e) => setTsName(e.target.value)} />
                <Input placeholder={t('pages.endpoints.authKeyPlaceholder')} value={tsKey} onChange={(e) => setTsKey(e.target.value)} />
                <Input placeholder={t('pages.endpoints.hostnamePlaceholder')} value={tsHost} onChange={(e) => setTsHost(e.target.value)} />
                <Input placeholder={t('pages.endpoints.exitNodePlaceholder')} value={tsExit} onChange={(e) => setTsExit(e.target.value)} />
                <Button
                  className="w-full"
                  disabled={!tsName.trim() || !tsKey.trim() || add.isPending}
                  onClick={() => { add.mutate({ type: 'tailscale', tag: tsName.trim(), auth_key: tsKey.trim(), hostname: tsHost.trim(), exit_node: tsExit.trim(), accept_routes: true }); setTsName(''); setTsKey(''); setTsHost(''); setTsExit(''); }}
                >
                  <Plus className="size-4" /> {t('pages.endpoints.joinTailnetButton')}
                </Button>
                <p className="text-xs text-muted-foreground">{t('pages.endpoints.tsHint')}</p>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>

        <Card className="lg:col-span-3">
          <CardHeader className="pb-3"><CardTitle className="text-sm">{t('pages.endpoints.endpointsListTitle')}</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {eps.length === 0 ? (
              <div className="flex flex-col items-center gap-2 py-12 text-center">
                <Network className="size-8 text-muted-foreground/50" />
                <p className="text-sm text-muted-foreground">{t('pages.endpoints.emptyState')}</p>
              </div>
            ) : (
              eps.map((e) => (
                <div key={e.tag} className="flex items-center gap-3 rounded-md border px-3 py-2.5">
                  <Switch checked={e.enabled} onCheckedChange={(on) => toggle.mutate({ tag: e.tag, on })} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 text-sm font-medium">
                      {e.tag}
                      <Badge variant={e.type === 'wireguard' ? 'default' : 'secondary'}>{e.type}</Badge>
                    </div>
                    <div className="tnum truncate text-xs text-muted-foreground">
                      {e.type === 'wireguard'
                        ? t('pages.endpoints.wgRowInfo', {
                            address: (e.address ?? []).join(', '),
                            peer: e.peer_endpoint,
                            allowed: (e.allowed_ips ?? []).join(', '),
                          })
                        : `${e.hostname || 'tailnet'}${e.exit_node ? t('pages.endpoints.exitSuffix', { exit: e.exit_node }) : ''}`}
                    </div>
                  </div>
                  <Button size="icon" variant="ghost" className="size-7 text-destructive" onClick={() => del.mutate(e.tag)}>
                    <Trash2 className="size-3.5" />
                  </Button>
                </div>
              ))
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
