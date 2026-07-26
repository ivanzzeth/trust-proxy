import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Check, Layers, Play, Plus, Save, Trash2 } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { api, Profile } from '@/lib/api';
import { PageHeader } from '@/components/page-header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

// A profile is a snapshot of the whole policy, and the page used to show nothing
// but "no profiles yet — configure your policy, then save": it never said what a
// snapshot contains, so an empty list looked like the page was broken even for
// someone whose policy was fully configured. The current policy is therefore
// rendered right here, in the same shape as a saved profile, so "Save current
// policy" has something visible to point at — and both destructive steps
// (overwrite, activate) now say what they are about to replace.

export default function Profiles() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { data: profiles = [] } = useQuery({ queryKey: ['profiles'], queryFn: api.profiles });
  const invalidate = () => {
    for (const k of [
      'profiles', 'whitelist', 'blacklist', 'directlist', 'customrules',
      'rulesets', 'dns', 'proxygroups', 'status', 'subs', 'conns', 'events', 'effectiveRules', 'posture',
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
  const current = useCurrentPolicy();

  const save = () => {
    const n = name.trim();
    if (!n) return;
    if (profiles.some((p) => p.name === n) && !window.confirm(t('pages.profiles.overwriteConfirm', { name: n }))) return;
    add.mutate(n);
    setName('');
  };

  const tryActivate = (p: Profile) => {
    // Activating replaces every policy axis at once. When no profile is marked
    // active, nothing holds the policy that is running — say so before replacing
    // it, because there is no undo.
    if (!profiles.some((o) => o.active)) {
      if (!window.confirm(t('pages.profiles.activateNoBackup') + '\n\n' + t('pages.profiles.activateConfirm', { name: p.name }))) return;
    } else if (!window.confirm(t('pages.profiles.activateConfirm', { name: p.name }))) {
      return;
    }
    activate.mutate(p.id);
  };

  return (
    <div>
      <PageHeader title={t('pages.profiles.title')} description={t('pages.profiles.description')} />

      <div className="grid gap-4 lg:grid-cols-3">
        {/* What "save" would capture, so the button is never pointing at nothing. */}
        <Card className="lg:col-span-1">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">
              <Save className="size-4 text-primary" /> {t('pages.profiles.currentTitle')}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-xs text-muted-foreground">{t('pages.profiles.currentHint')}</p>
            <dl className="space-y-1.5 text-sm">
              <Stat k={t('pages.profiles.statPermit')} v={t('pages.profiles.permitStat', { domains: current.permitDomains, ips: current.permitIPs })} />
              <Stat k={t('pages.profiles.statDeny')} v={String(current.deny)} />
              <Stat k={t('pages.profiles.statDirectlist')} v={String(current.noProxy)} />
              <Stat k={t('pages.profiles.statCustomRules')} v={String(current.customRules)} />
              <Stat k={t('pages.profiles.statRuleSets')} v={String(current.ruleSets)} />
              <Stat k={t('pages.profiles.statProxyGroups')} v={String(current.groups)} />
              <Stat k={t('pages.profiles.statDNS')} v={String(current.dnsServers)} />
              <Stat k={t('pages.profiles.statPosture')} v={current.posture} />
              <Stat k={t('pages.profiles.statMode')} v={current.mode} />
              <Stat k={t('pages.profiles.statSub')} v={current.sub} />
            </dl>
            <div className="flex gap-2">
              <Input
                placeholder={t('pages.profiles.namePlaceholder')}
                value={name}
                onChange={(e) => setName(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && save()}
              />
              <Button disabled={!name.trim() || add.isPending} onClick={save}>
                <Plus className="size-4" /> {t('pages.profiles.saveCurrent')}
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">{t('pages.profiles.saveHint')}</p>
          </CardContent>
        </Card>

        <div className="lg:col-span-2">
          {profiles.length === 0 ? (
            <Card className="h-full">
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-2 text-sm">
                  <Layers className="size-4 text-muted-foreground" /> {t('pages.profiles.howTitle')}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ol className="space-y-3 text-sm text-muted-foreground">
                  {[t('pages.profiles.how1'), t('pages.profiles.how2'), t('pages.profiles.how3')].map((s, i) => (
                    <li key={i} className="flex gap-3">
                      <span className="grid size-5 shrink-0 place-items-center rounded-full bg-primary/15 text-[11px] font-semibold text-primary">
                        {i + 1}
                      </span>
                      <span>{s}</span>
                    </li>
                  ))}
                </ol>
              </CardContent>
            </Card>
          ) : (
            <div className="grid gap-3 md:grid-cols-2">
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
                        k={t('pages.profiles.statPermit')}
                        v={t('pages.profiles.permitStat', {
                          domains: p.whitelist?.domains?.length ?? 0,
                          ips: p.whitelist?.ips?.length ?? 0,
                        })}
                      />
                      <Stat k={t('pages.profiles.statDeny')} v={String(blCount(p))} />
                      <Stat k={t('pages.profiles.statDirectlist')} v={String(dlCount(p))} />
                      <Stat k={t('pages.profiles.statCustomRules')} v={String(p.custom_rules?.length ?? 0)} />
                      <Stat k={t('pages.profiles.statRuleSets')} v={String(rsCount(p))} />
                      <Stat k={t('pages.profiles.statProxyGroups')} v={String(p.proxy_groups?.groups?.length ?? 0)} />
                      <Stat
                        k={t('pages.profiles.statDNS')}
                        v={p.dns ? String(p.dns.servers?.length ?? 0) : t('pages.profiles.notCaptured')}
                      />
                      <Stat k={t('pages.profiles.statMode')} v={p.mode || t('pages.profiles.notCaptured')} />
                      <Stat
                        k={t('pages.profiles.statSub')}
                        v={p.subscription_id ? p.subscription_id.slice(0, 8) : t('pages.profiles.notCaptured')}
                      />
                    </dl>
                    <div className="mt-4 flex gap-2">
                      <Button
                        size="sm"
                        className="flex-1"
                        disabled={p.active || activate.isPending}
                        onClick={() => tryActivate(p)}
                      >
                        <Play className="size-3.5" /> {t('pages.profiles.activate')}
                      </Button>
                      <Button
                        size="icon"
                        variant="ghost"
                        className="text-destructive"
                        onClick={() => window.confirm(t('pages.profiles.deleteConfirm', { name: p.name })) && del.mutate(p.id)}
                      >
                        <Trash2 className="size-4" />
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// useCurrentPolicy reads the live stores — the same axes a profile snapshots — so
// the page can show what saving would capture instead of an empty card.
function useCurrentPolicy() {
  const { t } = useTranslation();
  const wl = useQuery({ queryKey: ['whitelist'], queryFn: api.whitelist });
  const bl = useQuery({ queryKey: ['blacklist'], queryFn: api.blacklist });
  const dl = useQuery({ queryKey: ['directlist'], queryFn: api.directlist });
  const cr = useQuery({ queryKey: ['customrules'], queryFn: api.customRules });
  const rs = useQuery({ queryKey: ['rulesets'], queryFn: api.rulesets });
  const pg = useQuery({ queryKey: ['proxygroups'], queryFn: api.proxyGroups });
  const dns = useQuery({ queryKey: ['dns'], queryFn: api.dns });
  const st = useQuery({ queryKey: ['status'], queryFn: api.status });
  const po = useQuery({ queryKey: ['posture'], queryFn: api.posture });
  const subs = useQuery({ queryKey: ['subs'], queryFn: api.subs });
  const dash = t('pages.profiles.notCaptured');
  const applied = subs.data?.find((s) => s.applied);
  return {
    permitDomains: wl.data?.domains?.length ?? 0,
    permitIPs: wl.data?.ips?.length ?? 0,
    deny: (bl.data?.domains?.length ?? 0) + (bl.data?.keywords?.length ?? 0) + (bl.data?.regexes?.length ?? 0) + (bl.data?.ips?.length ?? 0),
    noProxy: (dl.data?.domains?.length ?? 0) + (dl.data?.ips?.length ?? 0),
    customRules: cr.data?.length ?? 0,
    ruleSets: rs.data?.length ?? 0,
    groups: pg.data?.groups?.length ?? 0,
    dnsServers: dns.data?.servers?.length ?? 0,
    mode: st.data?.mode ?? dash,
    posture: po.data?.active ?? dash,
    sub: applied ? applied.name : dash,
  };
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
      <dd className="tnum truncate">{v}</dd>
    </div>
  );
}
