import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Network, Plus, Trash2 } from 'lucide-react';

import { api } from '@/lib/api';
import { PageHeader } from '@/components/page-header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

export default function Endpoints() {
  const qc = useQueryClient();
  const { data: eps = [] } = useQuery({ queryKey: ['endpoints'], queryFn: api.endpoints });
  const invalidate = () => qc.invalidateQueries({ queryKey: ['endpoints'] });
  const err = (e: unknown) => toast.error(String((e as Error).message));
  const add = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.addEndpoint(body),
    onSuccess: () => {
      toast.success('Endpoint added — enabled ones join the proxy group');
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
        title="Endpoints"
        description="WireGuard / Tailscale exits. Enabled endpoints join the “proxy” group, so whitelisted egress can exit through them alongside subscription nodes."
      />

      <div className="grid gap-4 lg:grid-cols-5">
        <Card className="lg:col-span-2">
          <CardHeader className="pb-3"><CardTitle className="text-sm">Add endpoint</CardTitle></CardHeader>
          <CardContent>
            <Tabs defaultValue="wg">
              <TabsList className="w-full">
                <TabsTrigger value="wg" className="flex-1">WireGuard</TabsTrigger>
                <TabsTrigger value="ts" className="flex-1">Tailscale</TabsTrigger>
              </TabsList>
              <TabsContent value="wg" className="space-y-2">
                <Input placeholder="tag (name)" value={wgName} onChange={(e) => setWgName(e.target.value)} />
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
                  <Plus className="size-4" /> Add from wg-quick config
                </Button>
                <p className="text-xs text-muted-foreground">Paste your wg-quick .conf (e.g. the one on your k8s cluster). AllowedIPs default to full-tunnel if omitted.</p>
              </TabsContent>
              <TabsContent value="ts" className="space-y-2">
                <Input placeholder="tag (name)" value={tsName} onChange={(e) => setTsName(e.target.value)} />
                <Input placeholder="auth key (tskey-...)" value={tsKey} onChange={(e) => setTsKey(e.target.value)} />
                <Input placeholder="hostname (optional)" value={tsHost} onChange={(e) => setTsHost(e.target.value)} />
                <Input placeholder="exit node (optional, e.g. 100.x.y.z)" value={tsExit} onChange={(e) => setTsExit(e.target.value)} />
                <Button
                  className="w-full"
                  disabled={!tsName.trim() || !tsKey.trim() || add.isPending}
                  onClick={() => { add.mutate({ type: 'tailscale', tag: tsName.trim(), auth_key: tsKey.trim(), hostname: tsHost.trim(), exit_node: tsExit.trim(), accept_routes: true }); setTsName(''); setTsKey(''); setTsHost(''); setTsExit(''); }}
                >
                  <Plus className="size-4" /> Join tailnet
                </Button>
                <p className="text-xs text-muted-foreground">Joins your tailnet with the auth key. Set an exit node to egress via Tailscale.</p>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>

        <Card className="lg:col-span-3">
          <CardHeader className="pb-3"><CardTitle className="text-sm">Endpoints</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {eps.length === 0 ? (
              <div className="flex flex-col items-center gap-2 py-12 text-center">
                <Network className="size-8 text-muted-foreground/50" />
                <p className="text-sm text-muted-foreground">No endpoints. Add a WireGuard or Tailscale exit.</p>
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
                        ? `${(e.address ?? []).join(', ')} → ${e.peer_endpoint} · allowed ${(e.allowed_ips ?? []).join(', ')}`
                        : `${e.hostname || 'tailnet'}${e.exit_node ? ' · exit ' + e.exit_node : ''}`}
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
