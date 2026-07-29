import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Save } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { api, TUNConfig } from '@/lib/api';
import { LANGS } from '@/i18n';
import { PageHeader } from '@/components/page-header';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Textarea } from '@/components/ui/textarea';
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

function TUNCard() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ['tun'], queryFn: api.tun });
  const { data: st } = useQuery({ queryKey: ['status'], queryFn: api.status });
  const [cfg, setCfg] = useState<TUNConfig | null>(null);
  useEffect(() => {
    if (data && !cfg) {
      setCfg({
        ...data,
        stack: data.stack || 'gvisor',
        // Missing/undefined must not save as false — that would silently disable
        // Docker capture on the next Settings save after an older gateway reply.
        auto_redirect: data.auto_redirect !== false,
      });
    }
  }, [data, cfg]);

  const save = useMutation({
    mutationFn: (c: TUNConfig) => api.setTUN(c),
    onSuccess: (c) => {
      toast.success(t('settings.tun.toast'));
      setCfg({ ...c, stack: c.stack || 'gvisor' });
      qc.invalidateQueries({ queryKey: ['tun'] });
    },
    onError: (e) => toast.error(String((e as Error).message)),
  });

  const installNft = useMutation({
    mutationFn: () => api.installNftables(true),
    onSuccess: () => {
      toast.success(t('settings.tun.redirectNftInstalled'));
      qc.invalidateQueries({ queryKey: ['status'] });
    },
    onError: (e) => toast.error(String((e as Error).message)),
  });

  const wantsRedirect = cfg ? cfg.auto_redirect !== false : false;
  const nft = st?.nftables;
  const nftMissing = wantsRedirect && nft && (!nft.supported || !nft.usable);

  if (!cfg) return null;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">{t('settings.tun.title')}</CardTitle>
        <CardDescription>{t('settings.tun.desc')}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1.5">
            <Label>{t('settings.tun.stack')}</Label>
            <Select value={cfg.stack || 'gvisor'} onValueChange={(v) => setCfg({ ...cfg, stack: v })}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>{STACKS.map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}</SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="tun-mtu">{t('settings.tun.mtu')}</Label>
            <Input
              id="tun-mtu"
              type="number"
              min={0}
              placeholder={t('settings.tun.mtuPh')}
              value={cfg.mtu || 0}
              onChange={(e) => setCfg({ ...cfg, mtu: Number(e.target.value) || 0 })}
            />
          </div>
        </div>
        <p className="text-xs text-muted-foreground">{t('settings.tun.stackDesc')}</p>
        <div className="flex items-center justify-between">
          <div>
            <Label htmlFor="tun-strict">{t('settings.tun.strict')}</Label>
            <p className="text-xs text-muted-foreground">{t('settings.tun.strictDesc')}</p>
          </div>
          <Switch id="tun-strict" checked={cfg.strict_route} onCheckedChange={(v) => setCfg({ ...cfg, strict_route: v })} />
        </div>
        <div className="flex items-center justify-between">
          <div>
            <Label htmlFor="tun-redirect">{t('settings.tun.redirect')}</Label>
            <p className="text-xs text-muted-foreground">{t('settings.tun.redirectDesc')}</p>
          </div>
          <Switch
            id="tun-redirect"
            checked={cfg.auto_redirect !== false}
            onCheckedChange={(v) => setCfg({ ...cfg, auto_redirect: v })}
          />
        </div>
        {nftMissing && (
          <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive space-y-1">
            <div className="font-medium">{t('settings.tun.redirectNftMissingTitle')}</div>
            <div className="text-xs leading-relaxed">
              {t('settings.tun.redirectNftMissingBody', { cmd: nft?.suggested_install_cmd ?? '' })}
            </div>
            {nft?.auto_install_supported && (
              <div className="flex items-center justify-end">
                <Button variant="secondary" size="sm" disabled={installNft.isPending} onClick={() => installNft.mutate()}>
                  {t('settings.tun.redirectNftInstall')}
                </Button>
              </div>
            )}
          </div>
        )}
        <div className="space-y-1.5">
          <Label>{t('settings.tun.address')}</Label>
          <p className="text-xs text-muted-foreground">{t('settings.tun.addressDesc')}</p>
          <Textarea
            className="min-h-16 w-full rounded-md border border-input bg-transparent px-2 py-1.5 text-xs font-mono shadow-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            placeholder={t('settings.tun.addressPh')}
            value={listToText(cfg.address)}
            onChange={(e) => setCfg({ ...cfg, address: textToList(e.target.value) })}
          />
        </div>
        <div className="space-y-1.5">
          <Label>{t('settings.tun.exclude')}</Label>
          <p className="text-xs text-muted-foreground">{t('settings.tun.excludeDesc')}</p>
          <Textarea
            className="min-h-16 w-full rounded-md border border-input bg-transparent px-2 py-1.5 text-xs font-mono shadow-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            placeholder={t('settings.tun.excludePh')}
            value={listToText(cfg.exclude_package)}
            onChange={(e) => setCfg({ ...cfg, exclude_package: textToList(e.target.value) })}
          />
        </div>
        <div className="space-y-1.5">
          <Label>{t('settings.tun.include')}</Label>
          <p className="text-xs text-muted-foreground">{t('settings.tun.includeDesc')}</p>
          <Textarea
            className="min-h-16 w-full rounded-md border border-input bg-transparent px-2 py-1.5 text-xs font-mono shadow-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            placeholder={t('settings.tun.includePh')}
            value={listToText(cfg.include_package)}
            onChange={(e) => setCfg({ ...cfg, include_package: textToList(e.target.value) })}
          />
        </div>
        <div className="flex items-center justify-end">
          <Button disabled={save.isPending} onClick={() => save.mutate(cfg)}>
            <Save className="size-4" /> {t('settings.tun.save')}
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
        <TUNCard />
      </div>
    </div>
  );
}
