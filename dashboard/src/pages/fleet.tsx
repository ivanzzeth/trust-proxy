import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Plus, Server, Trash2 } from 'lucide-react';

import { api, Gateway, setNode } from '@/lib/api';
import { PageHeader } from '@/components/page-header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

// Reachability probe — hits the brain's reverse proxy for this gateway.
function useHealth(id: string) {
  return useQuery({
    queryKey: ['gw-health', id],
    queryFn: async () => {
      const r = await fetch(`/api/nodes/${id}/status`);
      if (!r.ok) throw new Error(String(r.status));
      return (await r.json()) as { mode: string };
    },
    retry: false,
    refetchInterval: 10000,
  });
}

function GatewayRow({ g, onDel }: { g: Gateway; onDel: () => void }) {
  const h = useHealth(g.id);
  const qc = useQueryClient();
  return (
    <div className="flex items-center gap-3 rounded-md border px-3 py-2.5">
      <span
        className={
          'size-2 shrink-0 rounded-full ' +
          (h.isLoading ? 'bg-muted-foreground/40' : h.isError ? 'bg-destructive' : 'bg-primary')
        }
      />
      <div className="min-w-0 flex-1">
        <div className="truncate text-sm font-medium">{g.name}</div>
        <div className="tnum truncate text-xs text-muted-foreground">{g.url}</div>
      </div>
      {h.data && <Badge variant="muted">mode: {h.data.mode}</Badge>}
      {h.isError && <Badge variant="danger">unreachable</Badge>}
      <Button
        size="xs"
        variant="outline"
        onClick={() => {
          setNode(g.id);
          qc.clear();
          toast.success(`Viewing ${g.name} — switch back from the top bar`);
        }}
      >
        View
      </Button>
      <Button size="icon" variant="ghost" className="size-7 text-destructive" onClick={onDel}>
        <Trash2 className="size-3.5" />
      </Button>
    </div>
  );
}

export default function Fleet() {
  const qc = useQueryClient();
  const { data: gws = [] } = useQuery({ queryKey: ['gateways'], queryFn: api.gateways });
  const invalidate = () => qc.invalidateQueries({ queryKey: ['gateways'] });
  const err = (e: unknown) => toast.error(String((e as Error).message));

  const add = useMutation({
    mutationFn: (v: { name: string; url: string; token: string }) => api.addGateway(v.name, v.url, v.token),
    onSuccess: invalidate,
    onError: err,
  });
  const del = useMutation({ mutationFn: api.delGateway, onSuccess: invalidate, onError: err });

  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [token, setToken] = useState('');

  return (
    <div>
      <PageHeader
        title="Fleet"
        description="Manage remote trust-proxy gateways. The brain reverse-proxies to each (token stays server-side); switch which one you're viewing from the top bar."
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm">Add gateway</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <Input placeholder="name" value={name} onChange={(e) => setName(e.target.value)} />
            <Input placeholder="http://host:9096" value={url} onChange={(e) => setUrl(e.target.value)} />
            <Input placeholder="api token (--api-token on the probe)" value={token} onChange={(e) => setToken(e.target.value)} />
            <Button
              className="w-full"
              disabled={!url.trim() || add.isPending}
              onClick={() => {
                add.mutate({ name: name.trim(), url: url.trim(), token: token.trim() });
                setName('');
                setUrl('');
                setToken('');
              }}
            >
              <Plus className="size-4" /> Register
            </Button>
            <p className="text-xs leading-relaxed text-muted-foreground">
              On the remote gateway run <code className="tnum">serve --api-addr 0.0.0.0:9096 --api-token &lt;secret&gt;</code>.
            </p>
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm">Gateways</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {gws.length === 0 ? (
              <div className="flex flex-col items-center gap-2 py-12 text-center">
                <Server className="size-8 text-muted-foreground/50" />
                <p className="text-sm text-muted-foreground">No remote gateways. This console controls the local one.</p>
              </div>
            ) : (
              gws.map((g) => <GatewayRow key={g.id} g={g} onDel={() => del.mutate(g.id)} />)
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
