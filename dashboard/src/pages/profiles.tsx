import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Check, Layers, Play, Plus, Trash2 } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { api, Profile } from '@/lib/api';
import { PageHeader } from '@/components/page-header';
import { Card, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

export default function Profiles() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { data: profiles = [] } = useQuery({ queryKey: ['profiles'], queryFn: api.profiles });
  const invalidate = () => {
    for (const k of [
      'profiles', 'whitelist', 'blacklist', 'directlist', 'customrules',
      'rulesets', 'dns', 'proxygroups', 'status', 'subs', 'conns', 'events', 'effectiveRules',
    ]) {
      qc.invalidateQueries({ queryKey: [k] });
    }
  };
  const err = (e: unknown) => toast.error(String((e as Error).message));
  const add = useMutation({
    mutationFn: api.addProfile,
    onSuccess: () => {
      toast.success(t('pages.profiles.profileSaved'));
      invalidate();
    },
    onError: err,
  });
  const activate = useMutation({
    mutationFn: api.activateProfile,
    onSuccess: () => {
      toast.success(t('pages.profiles.profileActivated'));
      invalidate();
    },
    onError: err,
  });
  const del = useMutation({ mutationFn: api.delProfile, onSuccess: invalidate, onError: err });

  const [name, setName] = useState('');

  return (
    <div>
      <PageHeader
        title={t('pages.profiles.title')}
        description={t('pages.profiles.description')}
        actions={
          <div className="flex gap-2">
            <Input
              className="w-48"
              placeholder={t('pages.profiles.namePlaceholder')}
              value={name}
              onChange={(e) => setName(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && name.trim() && (add.mutate(name.trim()), setName(''))}
            />
            <Button disabled={!name.trim() || add.isPending} onClick={() => { add.mutate(name.trim()); setName(''); }}>
              <Plus className="size-4" /> {t('pages.profiles.saveCurrent')}
            </Button>
          </div>
        }
      />

      {profiles.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center gap-2 py-16 text-center">
            <Layers className="size-8 text-muted-foreground/50" />
            <p className="text-sm text-muted-foreground">{t('pages.profiles.empty')}</p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {profiles.map((p) => (
            <Card key={p.id} className={p.active ? 'ring-1 ring-primary/50' : ''}>
              <CardContent className="p-5">
                <div className="mb-3 flex items-center justify-between">
                  <div className="flex items-center gap-2 font-semibold">
                    <Layers className="size-4 text-primary" />
                    {p.name}
                  </div>
                  {p.active && (
                    <Badge variant="success">
                      <Check className="size-3" /> {t('pages.profiles.active')}
                    </Badge>
                  )}
                </div>
                <dl className="space-y-1.5 text-sm">
                  <Stat
                    k={t('pages.profiles.statWhitelist')}
                    v={t('pages.profiles.whitelistStat', {
                      domains: p.whitelist?.domains?.length ?? 0,
                      ips: p.whitelist?.ips?.length ?? 0,
                    })}
                  />
                  <Stat k={t('pages.profiles.statBlacklist')} v={String(blCount(p))} />
                  <Stat k={t('pages.profiles.statDirectlist')} v={String(dlCount(p))} />
                  <Stat k={t('pages.profiles.statCustomRules')} v={String(p.custom_rules?.length ?? 0)} />
                  <Stat k={t('pages.profiles.statRuleSets')} v={String(rsCount(p))} />
                  <Stat k={t('pages.profiles.statProxyGroups')} v={String(p.proxy_groups?.groups?.length ?? 0)} />
                  <Stat k={t('pages.profiles.statDNS')} v={p.dns ? String(p.dns.servers?.length ?? 0) : '—'} />
                  <Stat k={t('pages.profiles.statMode')} v={p.mode || '—'} />
                  <Stat k={t('pages.profiles.statSub')} v={p.subscription_id ? p.subscription_id.slice(0, 8) : '—'} />
                </dl>
                <div className="mt-4 flex gap-2">
                  <Button size="sm" className="flex-1" disabled={p.active || activate.isPending} onClick={() => activate.mutate(p.id)}>
                    <Play className="size-3.5" /> {t('pages.profiles.activate')}
                  </Button>
                  <Button size="icon" variant="ghost" className="text-destructive" onClick={() => del.mutate(p.id)}>
                    <Trash2 className="size-4" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

function blCount(p: Profile) {
  const b = p.blacklist;
  if (!b) return 0;
  return (b.domains?.length ?? 0) + (b.keywords?.length ?? 0) + (b.regexes?.length ?? 0) + (b.ips?.length ?? 0);
}
function dlCount(p: Profile) {
  const d = p.directlist;
  if (!d) return 0;
  return (d.domains?.length ?? 0) + (d.ips?.length ?? 0);
}
function rsCount(p: Profile) {
  if (p.rule_sets?.length) return p.rule_sets.length;
  return p.ruleset_tags?.length ?? 0;
}

function Stat({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <dt className="text-muted-foreground">{k}</dt>
      <dd className="tnum truncate capitalize">{v}</dd>
    </div>
  );
}
