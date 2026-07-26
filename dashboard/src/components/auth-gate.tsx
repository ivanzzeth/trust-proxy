import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Loader2, LogIn, ShieldPlus, UserPlus } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Logo } from '@/components/logo';

// The console's front door.
//
// Three states, and the backend decides which — the page never guesses:
//
//   needs_bootstrap  nobody exists yet: create the first admin (always an admin,
//                    or the gateway would have a console nobody can administer)
//   !authenticated   log in; register only if an admin opened it
//   authenticated    render the app
//
// The session is an httpOnly cookie, so this component cannot read it and does not
// try: it asks /api/auth/state. That is also why a 401 anywhere else is handled by
// invalidating this query rather than by juggling a token in localStorage, which an
// XSS could read.

export function AuthGate({ children }: { children: React.ReactNode }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { data: state, isLoading, isError, refetch } = useQuery({
    queryKey: ['authState'],
    queryFn: api.authState,
    retry: false,
  });

  // A 401 from any other call means the session went away (expired, revoked,
  // account disabled). Re-check instead of leaving the user on a blank page.
  useEffect(() => {
    const onUnauthorized = () => qc.invalidateQueries({ queryKey: ['authState'] });
    window.addEventListener('tp-unauthorized', onUnauthorized);
    return () => window.removeEventListener('tp-unauthorized', onUnauthorized);
  }, [qc]);

  if (isLoading) {
    return (
      <div className="grid h-dvh place-items-center">
        <Loader2 className="size-5 animate-spin text-muted-foreground" />
      </div>
    );
  }
  if (isError) {
    return (
      <Centered title={t('auth.unreachableTitle')} description={t('auth.unreachableDesc')}>
        <Button onClick={() => refetch()} className="w-full">
          {t('auth.retry')}
        </Button>
      </Centered>
    );
  }
  if (state?.needs_bootstrap) return <BootstrapForm needsCode={!!state.needs_bootstrap_code} />;
  if (!state?.authenticated) return <LoginForm allowRegistration={!!state?.allow_registration} />;
  return <>{children}</>;
}

function Centered({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <div className="grid h-dvh place-items-center bg-background p-6">
      <Card className="w-full max-w-sm">
        <CardHeader className="space-y-2">
          <div className="flex items-center gap-2">
            <div className="grid size-7 place-items-center rounded-md bg-primary/15 text-primary">
              <Logo className="size-5" />
            </div>
            <span className="text-sm font-bold tracking-tight">Trust Proxy</span>
          </div>
          <CardTitle className="text-base">{title}</CardTitle>
          <CardDescription>{description}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">{children}</CardContent>
      </Card>
    </div>
  );
}

function useCredentials() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  return { username, setUsername, password, setPassword };
}

function CredentialFields({
  c,
  autoComplete,
  onSubmit,
}: {
  c: ReturnType<typeof useCredentials>;
  autoComplete: 'current-password' | 'new-password';
  onSubmit: () => void;
}) {
  const { t } = useTranslation();
  return (
    <>
      <div className="space-y-1.5">
        <Label htmlFor="tp-username">{t('auth.username')}</Label>
        <Input
          id="tp-username"
          autoComplete="username"
          autoFocus
          value={c.username}
          onChange={(e) => c.setUsername(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && onSubmit()}
        />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="tp-password">{t('auth.password')}</Label>
        <Input
          id="tp-password"
          type="password"
          autoComplete={autoComplete}
          value={c.password}
          onChange={(e) => c.setPassword(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && onSubmit()}
        />
      </div>
    </>
  );
}

// needsCode: this browser is not on the gateway's machine. Being first to reach
// the port is then not proof of anything, so the gateway also wants the one-time
// code it logged at startup — and that is exactly the cloud-gateway case, so the
// field has to be here rather than leaving a form that can only 403.
function BootstrapForm({ needsCode }: { needsCode: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const c = useCredentials();
  const [code, setCode] = useState('');
  const m = useMutation({
    mutationFn: () => api.bootstrap(c.username.trim(), c.password, code.trim()),
    onSuccess: () => {
      toast.success(t('auth.bootstrapDone'));
      qc.invalidateQueries();
    },
    onError: (e) => toast.error(String((e as Error).message)),
  });
  const ready = !!c.username.trim() && !!c.password && (!needsCode || !!code.trim());
  const submit = () => ready && m.mutate();
  return (
    <Centered title={t('auth.bootstrapTitle')} description={t('auth.bootstrapDesc')}>
      <CredentialFields c={c} autoComplete="new-password" onSubmit={submit} />
      {needsCode && (
        <div className="space-y-1.5">
          <Label htmlFor="tp-code">{t('auth.bootstrapCode')}</Label>
          <Input
            id="tp-code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && submit()}
            placeholder="LjY3Yx5I…"
          />
          <p className="text-xs text-muted-foreground">{t('auth.bootstrapCodeHint')}</p>
        </div>
      )}
      <Button className="w-full" disabled={!ready || m.isPending} onClick={submit}>
        {m.isPending ? <Loader2 className="size-4 animate-spin" /> : <ShieldPlus className="size-4" />}{' '}
        {t('auth.createAdmin')}
      </Button>
      <p className="text-xs text-muted-foreground">{t('auth.bootstrapHint')}</p>
    </Centered>
  );
}

function LoginForm({ allowRegistration }: { allowRegistration: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const c = useCredentials();
  const [registering, setRegistering] = useState(false);
  const m = useMutation({
    mutationFn: () =>
      registering ? api.register(c.username.trim(), c.password) : api.login(c.username.trim(), c.password),
    onSuccess: () => qc.invalidateQueries(),
    onError: (e) => toast.error(String((e as Error).message)),
  });
  const submit = () => c.username.trim() && c.password && m.mutate();
  return (
    <Centered
      title={registering ? t('auth.registerTitle') : t('auth.loginTitle')}
      description={registering ? t('auth.registerDesc') : t('auth.loginDesc')}
    >
      <CredentialFields c={c} autoComplete={registering ? 'new-password' : 'current-password'} onSubmit={submit} />
      <Button className="w-full" disabled={!c.username.trim() || !c.password || m.isPending} onClick={submit}>
        {m.isPending ? <Loader2 className="size-4 animate-spin" /> : registering ? <UserPlus className="size-4" /> : <LogIn className="size-4" />}{' '}
        {registering ? t('auth.register') : t('auth.login')}
      </Button>
      {allowRegistration && (
        <button
          className="w-full text-xs text-muted-foreground underline-offset-2 hover:underline"
          onClick={() => setRegistering((v) => !v)}
        >
          {registering ? t('auth.haveAccount') : t('auth.noAccount')}
        </button>
      )}
    </Centered>
  );
}
