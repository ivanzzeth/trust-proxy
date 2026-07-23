import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Save } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { api, InboundAuth, TUNConfig } from '@/lib/api';
import { LANGS } from '@/i18n';
import { PageHeader } from '@/components/page-header';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';

const STACKS = ['gvisor', 'system', 'mixed'];

// list <-> textarea text (one entry per line).
const listToText = (l?: string[]) => (l ?? []).join('\n');
const textToList = (t: string) =>
  t
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean);

function InboundCard() {
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ['inbound'], queryFn: api.inbound });
  const [auth, setAuth] = useState<InboundAuth | null>(null);
  useEffect(() => {
    if (data && !auth) setAuth({ username: data.username ?? '', password: data.password ?? '' });
  }, [data, auth]);

  const save = useMutation({
    mutationFn: (a: InboundAuth) => api.setInbound(a),
    onSuccess: (a) => {
      toast.success(a.username ? 'Proxy inbound auth enabled' : 'Proxy inbound auth disabled (open)');
      setAuth({ username: a.username ?? '', password: a.password ?? '' });
      qc.invalidateQueries({ queryKey: ['inbound'] });
    },
    onError: (e) => toast.error(String((e as Error).message)),
  });

  if (!auth) return null;
  const enabled = auth.username !== '' || auth.password !== '';

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">Proxy inbound auth</CardTitle>
        <CardDescription>
          Require a username/password on the mixed proxy inbound (:17070). Leave both empty to keep it open.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-1.5">
          <Label htmlFor="inbound-user">Username</Label>
          <Input
            id="inbound-user"
            autoComplete="off"
            placeholder="(empty = open)"
            value={auth.username}
            onChange={(e) => setAuth({ ...auth, username: e.target.value })}
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="inbound-pass">Password</Label>
          <Input
            id="inbound-pass"
            type="password"
            autoComplete="new-password"
            placeholder="(empty = open)"
            value={auth.password}
            onChange={(e) => setAuth({ ...auth, password: e.target.value })}
          />
        </div>
        <div className="flex items-center justify-between">
          <p className="text-xs text-muted-foreground">
            {enabled ? 'Auth required for clients on :17070.' : 'Inbound is open — no auth required.'}
          </p>
          <Button disabled={save.isPending} onClick={() => save.mutate(auth)}>
            <Save className="size-4" /> Save
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function TUNCard() {
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ['tun'], queryFn: api.tun });
  const [cfg, setCfg] = useState<TUNConfig | null>(null);
  useEffect(() => {
    if (data && !cfg) setCfg({ ...data, stack: data.stack || 'gvisor' });
  }, [data, cfg]);

  const save = useMutation({
    mutationFn: (c: TUNConfig) => api.setTUN(c),
    onSuccess: (c) => {
      toast.success('TUN options saved');
      setCfg({ ...c, stack: c.stack || 'gvisor' });
      qc.invalidateQueries({ queryKey: ['tun'] });
    },
    onError: (e) => toast.error(String((e as Error).message)),
  });

  if (!cfg) return null;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">TUN options</CardTitle>
        <CardDescription>
          Advanced tuning for the TUN inbound. Only takes effect in <code>tun</code> capture mode.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1.5">
            <Label>Stack</Label>
            <Select value={cfg.stack || 'gvisor'} onValueChange={(v) => setCfg({ ...cfg, stack: v })}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>{STACKS.map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}</SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="tun-mtu">MTU</Label>
            <Input
              id="tun-mtu"
              type="number"
              min={0}
              placeholder="0 = auto"
              value={cfg.mtu || 0}
              onChange={(e) => setCfg({ ...cfg, mtu: Number(e.target.value) || 0 })}
            />
          </div>
        </div>
        <div className="flex items-center justify-between">
          <div>
            <Label htmlFor="tun-strict">Strict route</Label>
            <p className="text-xs text-muted-foreground">Enforce that all traffic goes through the tun (recommended).</p>
          </div>
          <Switch id="tun-strict" checked={cfg.strict_route} onCheckedChange={(v) => setCfg({ ...cfg, strict_route: v })} />
        </div>
        <div className="space-y-1.5">
          <Label>Exclude packages / processes</Label>
          <textarea
            className="min-h-16 w-full rounded-md border border-input bg-transparent px-2 py-1.5 text-xs font-mono shadow-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            placeholder="one per line — routed AROUND the tun (Android package names)"
            value={listToText(cfg.exclude_package)}
            onChange={(e) => setCfg({ ...cfg, exclude_package: textToList(e.target.value) })}
          />
        </div>
        <div className="space-y-1.5">
          <Label>Include packages</Label>
          <textarea
            className="min-h-16 w-full rounded-md border border-input bg-transparent px-2 py-1.5 text-xs font-mono shadow-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            placeholder="one per line — ONLY these are routed INTO the tun (mutually exclusive with exclude)"
            value={listToText(cfg.include_package)}
            onChange={(e) => setCfg({ ...cfg, include_package: textToList(e.target.value) })}
          />
        </div>
        <div className="flex items-center justify-end">
          <Button disabled={save.isPending} onClick={() => save.mutate(cfg)}>
            <Save className="size-4" /> Save
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function LanguageCard() {
  const { t, i18n } = useTranslation();
  const cur = (i18n.resolvedLanguage ?? 'en').startsWith('zh') ? 'zh' : 'en';
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">{t('settings.language')}</CardTitle>
        <CardDescription>{t('settings.languageDesc')}</CardDescription>
      </CardHeader>
      <CardContent>
        <Select value={cur} onValueChange={(v) => void i18n.changeLanguage(v)}>
          <SelectTrigger className="w-48"><SelectValue /></SelectTrigger>
          <SelectContent>
            {LANGS.map((l) => (
              <SelectItem key={l.code} value={l.code}>
                {l.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </CardContent>
    </Card>
  );
}

export default function Settings() {
  const { t } = useTranslation();
  return (
    <div>
      <PageHeader title={t('nav.settings')} description={t('settings.pageDesc')} />
      <div className="grid gap-4 lg:grid-cols-2">
        <LanguageCard />
        <InboundCard />
        <TUNCard />
      </div>
    </div>
  );
}
