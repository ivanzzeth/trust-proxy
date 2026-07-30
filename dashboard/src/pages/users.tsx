import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Check, Copy, KeyRound, Plus, ShieldCheck, Trash2, UserX, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { api, PermitRequest, Role, User } from '@/lib/api';
import { PageHeader } from '@/components/page-header';
import { OpenRegistrationSwitch } from '@/components/policy-rows';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';

// User administration, admin-only (the API enforces that; this page just would not
// load otherwise).
//
// Two passwords per person, and the page has to make the difference obvious or
// people will set one and wonder why the other does not work:
//
//   account password  signs in to this console (stored as a hash, never shown)
//   proxy password    lets their client use the proxy port (sing-box checks it
//                     itself, so it is stored where it can be read)

export default function Users() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['users'] });
    qc.invalidateQueries({ queryKey: ['authState'] });
  };
  const err = (e: unknown) => toast.error(String((e as Error).message));

  const { data: users = [] } = useQuery({ queryKey: ['users'], queryFn: api.users });
  const { data: requests = [] } = useQuery({ queryKey: ['permitRequests'], queryFn: api.permitRequests });
  // Which of these rows is the person looking at the page: only that one is asked
  // for its current password.
  const { data: authState } = useQuery({ queryKey: ['authState'], queryFn: api.authState });
  const me = authState?.user;

  const create = useMutation({
    mutationFn: (v: { username: string; password: string; role: Role }) =>
      api.createUser(v.username, v.password, v.role),
    onSuccess: () => {
      toast.success(t('pages.users.created'));
      invalidate();
    },
    onError: err,
  });

  const [name, setName] = useState('');
  const [pw, setPw] = useState('');
  const [role, setRole] = useState<Role>('client');

  return (
    <div>
      <PageHeader title={t('pages.users.title')} description={t('pages.users.desc')} />

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm">{t('pages.users.addTitle')}</CardTitle>
            <CardDescription>{t('pages.users.addDesc')}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-1.5">
              <Label>{t('pages.users.username')}</Label>
              <Input value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <div className="space-y-1.5">
              <Label>{t('pages.users.accountPassword')}</Label>
              <Input type="password" autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} />
            </div>
            <div className="space-y-1.5">
              <Label>{t('pages.users.role')}</Label>
              <Select value={role} onValueChange={(v) => setRole(v as Role)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="client">{t('pages.users.roleClient')}</SelectItem>
                  <SelectItem value="admin">{t('pages.users.roleAdmin')}</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <Button
              className="w-full"
              disabled={!name.trim() || pw.length < 10 || create.isPending}
              onClick={() => {
                create.mutate({ username: name.trim(), password: pw, role });
                setName('');
                setPw('');
              }}
            >
              <Plus className="size-4" /> {t('pages.users.add')}
            </Button>
            <p className="text-xs text-muted-foreground">{t('pages.users.passwordFloor')}</p>

            <div className="flex items-center justify-between border-t pt-3">
              <div>
                <div className="text-sm font-medium">{t('pages.users.registration')}</div>
                <div className="text-xs text-muted-foreground">{t('pages.users.registrationHint')}</div>
              </div>
              <OpenRegistrationSwitch />
            </div>
          </CardContent>
        </Card>

        <div className="space-y-4 lg:col-span-2">
          {requests.length > 0 && <Requests requests={requests} />}
          {users.map((u) => (
            <UserCard key={u.id} u={u} onChanged={invalidate} isMe={u.id === me?.id} />
          ))}
        </div>
      </div>
    </div>
  );
}

function UserCard({ u, onChanged, isMe }: { u: User; onChanged: () => void; isMe: boolean }) {
  const { t } = useTranslation();
  const err = (e: unknown) => toast.error(String((e as Error).message));
  const [proxyPw, setProxyPw] = useState('');
  const [newPw, setNewPw] = useState('');
  // Changing your own password means proving you know the current one — otherwise a
  // stolen session could lock the owner out of an account they still own. Two
  // exemptions: an admin resetting somebody else does not know it, and a password
  // `install` generated and told nobody is being *set* rather than changed.
  const [curPw, setCurPw] = useState('');
  const needsCurrent = isMe && !u.password_generated;
  const [freshKey, setFreshKey] = useState('');

  const patch = useMutation({
    mutationFn: (p: Parameters<typeof api.patchUser>[1]) => api.patchUser(u.id, p),
    onSuccess: () => {
      toast.success(t('pages.users.saved'));
      onChanged();
    },
    onError: err,
  });
  const del = useMutation({ mutationFn: () => api.delUser(u.id), onSuccess: onChanged, onError: err });
  const mintKey = useMutation({
    mutationFn: () => api.createAPIKey(u.id, 'console'),
    onSuccess: (k) => setFreshKey(k.key),
    onError: err,
  });
  const revoke = useMutation({ mutationFn: (id: string) => api.delAPIKey(u.id, id), onSuccess: onChanged, onError: err });

  return (
    <Card className={u.disabled ? 'opacity-60' : ''}>
      <CardContent className="space-y-3 p-5">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 font-semibold">
            {u.username}
            {u.role === 'admin' && (
              <Badge variant="success">
                <ShieldCheck className="size-3" /> {t('pages.users.roleAdmin')}
              </Badge>
            )}
            {u.disabled && <Badge variant="danger">{t('pages.users.disabled')}</Badge>}
            {u.has_proxy_cred && <Badge variant="secondary">{t('pages.users.hasProxy')}</Badge>}
          </div>
          <div className="flex items-center gap-1">
            <Button
              size="xs"
              variant="ghost"
              onClick={() => patch.mutate({ role: u.role === 'admin' ? 'client' : 'admin' })}
            >
              {u.role === 'admin' ? t('pages.users.demote') : t('pages.users.promote')}
            </Button>
            <Button size="xs" variant="ghost" onClick={() => patch.mutate({ disabled: !u.disabled })}>
              <UserX className="size-3.5" /> {u.disabled ? t('pages.users.enable') : t('pages.users.disable')}
            </Button>
            <Button
              size="icon"
              variant="ghost"
              className="size-7 text-destructive"
              onClick={() => window.confirm(t('pages.users.deleteConfirm', { name: u.username })) && del.mutate()}
            >
              <Trash2 className="size-4" />
            </Button>
          </div>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label className="text-xs">{t('pages.users.resetAccount')}</Label>
            {needsCurrent && (
              <Input
                type="password"
                autoComplete="current-password"
                placeholder={t('pages.users.currentPasswordPlaceholder')}
                value={curPw}
                onChange={(e) => setCurPw(e.target.value)}
              />
            )}
            <div className="flex gap-2">
              <Input type="password" autoComplete="new-password" value={newPw} onChange={(e) => setNewPw(e.target.value)} />
              <Button
                size="sm"
                disabled={newPw.length < 10 || (needsCurrent && curPw.length === 0)}
                onClick={() => {
                  patch.mutate(needsCurrent ? { password: newPw, current_password: curPw } : { password: newPw });
                  setNewPw('');
                  setCurPw('');
                }}
              >
                {t('pages.users.set')}
              </Button>
            </div>
            {isMe && <p className="text-muted-foreground text-xs">{t('pages.users.ownPasswordNote')}</p>}
          </div>
          <div className="space-y-1.5">
            <Label className="text-xs">{t('pages.users.proxyPassword')}</Label>
            <div className="flex gap-2">
              <Input type="password" autoComplete="new-password" value={proxyPw} onChange={(e) => setProxyPw(e.target.value)} />
              <Button
                size="sm"
                disabled={proxyPw.length < 8}
                onClick={() => {
                  patch.mutate({ proxy_password: proxyPw });
                  setProxyPw('');
                }}
              >
                {t('pages.users.set')}
              </Button>
              {u.has_proxy_cred && (
                <Button size="sm" variant="ghost" onClick={() => patch.mutate({ proxy_password: '' })}>
                  {t('pages.users.revoke')}
                </Button>
              )}
            </div>
            <p className="text-[11px] text-muted-foreground">{t('pages.users.proxyHint')}</p>
          </div>
        </div>

        <div className="space-y-2 border-t pt-3">
          <div className="flex items-center justify-between">
            <span className="text-xs text-muted-foreground">{t('pages.users.apiKeys')}</span>
            <Button size="xs" variant="outline" onClick={() => mintKey.mutate()}>
              <KeyRound className="size-3.5" /> {t('pages.users.mintKey')}
            </Button>
          </div>
          {freshKey && (
            <div className="rounded-md border border-primary/40 bg-primary/5 p-2">
              <div className="mb-1 text-[11px] text-muted-foreground">{t('pages.users.keyOnce')}</div>
              <div className="flex items-center gap-2">
                <code className="min-w-0 flex-1 truncate font-mono text-xs">{freshKey}</code>
                <Button
                  size="icon"
                  variant="ghost"
                  className="size-7"
                  onClick={() => {
                    navigator.clipboard?.writeText(freshKey);
                    toast.success(t('pages.users.copied'));
                  }}
                >
                  <Copy className="size-3.5" />
                </Button>
                <Button size="icon" variant="ghost" className="size-7" onClick={() => setFreshKey('')}>
                  <X className="size-3.5" />
                </Button>
              </div>
            </div>
          )}
          {(u.api_keys ?? []).map((k) => (
            <div key={k.id} className="flex items-center justify-between text-xs">
              <span className="truncate">
                <code className="font-mono">{k.prefix}…</code> {k.label}
              </span>
              <Button size="xs" variant="ghost" className="text-destructive" onClick={() => revoke.mutate(k.id)}>
                {t('pages.users.revokeKey')}
              </Button>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

// Pending requests are rules that are not in force yet: approving one is enabling
// it, which is why they live next to the policy they would change.
function Requests({ requests }: { requests: PermitRequest[] }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const err = (e: unknown) => toast.error(String((e as Error).message));
  const done = () => {
    qc.invalidateQueries({ queryKey: ['permitRequests'] });
    qc.invalidateQueries({ queryKey: ['customrules'] });
    qc.invalidateQueries({ queryKey: ['effectiveRules'] });
  };
  const approve = useMutation({ mutationFn: api.approveRequest, onSuccess: done, onError: err });
  const deny = useMutation({ mutationFn: api.denyRequest, onSuccess: done, onError: err });
  const pending = requests.filter((r) => !r.enabled);
  if (pending.length === 0) return null;
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">{t('pages.users.requestsTitle')}</CardTitle>
        <CardDescription>{t('pages.users.requestsDesc')}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-2">
        {pending.map((r) => (
          <div key={r.id} className="flex items-center gap-3 rounded-md border px-3 py-2">
            <div className="min-w-0 flex-1">
              <div className="truncate text-sm font-medium">{r.value}</div>
              <div className="truncate text-xs text-muted-foreground">
                {(r.pack ?? '').replace('request:', '')} — {r.note || t('pages.users.noReason')}
              </div>
            </div>
            <Button size="xs" onClick={() => approve.mutate(r.id)}>
              <Check className="size-3.5" /> {t('pages.users.approve')}
            </Button>
            <Button size="xs" variant="ghost" className="text-destructive" onClick={() => deny.mutate(r.id)}>
              {t('pages.users.deny')}
            </Button>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
