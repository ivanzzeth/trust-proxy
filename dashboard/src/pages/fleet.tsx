import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Plus, Server, Trash2 } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { api, Gateway, setNode } from '@/lib/api';
import { Switch } from '@/components/ui/switch';
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
  const { t } = useTranslation();
  const h = useHealth(g.id);
  const qc = useQueryClient();
  const err = (e: unknown) => toast.error(String((e as Error).message));
  const [exitUser, setExitUser] = useState(g.proxy_user ?? '');
  const [exitPass, setExitPass] = useState('');
  const [exitPort, setExitPort] = useState(String(g.proxy_port || 21584));
  const patch = useMutation({
    mutationFn: (p: Parameters<typeof api.patchGateway>[1]) => api.patchGateway(g.id, p),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['gateways'] }),
    onError: err,
  });

  // The local entry is this machine. Its switch is not "delete the process" — the
  // console is served by this very gateway — but whether it runs a data plane at
  // all: in client mode it captures nothing and the gateway it exits through
  // decides everything.
  if (g.local) {
    return (
      <div className="space-y-2 rounded-md border border-primary/40 bg-primary/5 px-3 py-2.5">
        <div className="flex items-center gap-3">
          <Badge variant="secondary">{t('pages.fleet.thisMachine')}</Badge>
          <div className="min-w-0 flex-1 truncate text-sm font-medium">{g.name}</div>
          <span className="text-xs text-muted-foreground">{t('pages.fleet.mode')}</span>
          <Button
            size="xs"
            variant={g.mode !== 'client' ? 'default' : 'ghost'}
            onClick={() => patch.mutate({ mode: 'gateway' })}
          >
            {t('pages.fleet.modeGateway')}
          </Button>
          <Button
            size="xs"
            variant={g.mode === 'client' ? 'default' : 'ghost'}
            onClick={() => patch.mutate({ mode: 'client' })}
          >
            {t('pages.fleet.modeClient')}
          </Button>
        </div>
        <p className="text-xs text-muted-foreground">
          {g.mode === 'client' ? t('pages.fleet.clientModeHint') : t('pages.fleet.gatewayModeHint')}
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-2 rounded-md border px-3 py-2.5">
    <div className="flex items-center gap-3">
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
      {h.data && <Badge variant="muted">{t('pages.fleet.modeLabel', { mode: h.data.mode })}</Badge>}
      {h.isError && <Badge variant="danger">{t('pages.fleet.unreachableBadge')}</Badge>}
      <Button
        size="xs"
        variant="outline"
        onClick={() => {
          setNode(g.id);
          qc.clear();
          toast.success(t('pages.fleet.viewingToast', { name: g.name }));
        }}
      >
        {t('pages.fleet.viewButton')}
      </Button>
      <Button size="icon" variant="ghost" className="size-7 text-destructive" onClick={onDel}>
        <Trash2 className="size-3.5" />
      </Button>
    </div>

    {/* Using it as an exit is a separate axis from administering it: one needs an
        account on that gateway, the other its admin token. */}
    <div className="flex flex-wrap items-center gap-2 border-t pt-2">
      <span className="text-xs text-muted-foreground">{t('pages.fleet.useAsExit')}</span>
      <Switch checked={g.as_exit} onCheckedChange={(v) => patch.mutate({ as_exit: v })} disabled={!g.as_exit && !g.has_proxy_pass && !exitPass} />
      <Input className="h-7 w-24 text-xs" placeholder={t('pages.fleet.portPh')} value={exitPort} onChange={(e) => setExitPort(e.target.value.replace(/\D/g, ''))} />
      <Input className="h-7 w-28 text-xs" placeholder={t('pages.fleet.userPh')} value={exitUser} onChange={(e) => setExitUser(e.target.value)} />
      <Input className="h-7 w-32 text-xs" type="password" placeholder={g.has_proxy_pass ? '••••••••' : t('pages.fleet.passPh')} value={exitPass} onChange={(e) => setExitPass(e.target.value)} />
      <Button
        size="xs"
        disabled={!exitUser.trim() || (!exitPass && !g.has_proxy_pass)}
        onClick={() =>
          patch.mutate({
            as_exit: true,
            proxy_port: Number(exitPort) || 21584,
            proxy_user: exitUser.trim(),
            ...(exitPass ? { proxy_pass: exitPass } : {}),
          })
        }
      >
        {t('pages.fleet.saveExit')}
      </Button>
      <span className="text-xs text-muted-foreground">{t('pages.fleet.enabled')}</span>
      <Switch checked={g.enabled} onCheckedChange={(v) => patch.mutate({ enabled: v })} />
    </div>
    </div>
  );
}

export default function Fleet() {
  const { t } = useTranslation();
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
      <PageHeader title={t('pages.fleet.title')} description={t('pages.fleet.description')} />

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm">{t('pages.fleet.addGatewayTitle')}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <Input placeholder={t('pages.fleet.namePlaceholder')} value={name} onChange={(e) => setName(e.target.value)} />
            <Input placeholder="http://host:21585" value={url} onChange={(e) => setUrl(e.target.value)} />
            <Input
              placeholder={t('pages.fleet.tokenPlaceholder')}
              value={token}
              onChange={(e) => setToken(e.target.value)}
            />
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
              <Plus className="size-4" /> {t('pages.fleet.registerButton')}
            </Button>
            <p className="text-xs leading-relaxed text-muted-foreground">
              {t('pages.fleet.remoteHintPre')}
              <code className="tnum">serve --api-addr 0.0.0.0:21585 --api-token &lt;secret&gt;</code>
              {t('pages.fleet.remoteHintPost')}
            </p>
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm">{t('pages.fleet.gatewaysTitle')}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {gws.length === 0 ? (
              <div className="flex flex-col items-center gap-2 py-12 text-center">
                <Server className="size-8 text-muted-foreground/50" />
                <p className="text-sm text-muted-foreground">{t('pages.fleet.emptyText')}</p>
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
