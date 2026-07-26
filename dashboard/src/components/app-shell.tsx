import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { NavLink, Outlet } from 'react-router-dom';
import { toast } from 'sonner';
import {
  Activity,
  AlertTriangle,
  ArrowDownUp,
  Cable,
  Github,
  Globe,
  LogOut,
  History as HistoryIcon,
  Layers,
  ListTree,
  Moon,
  Radar,
  ScrollText,
  Server,
  Settings as SettingsIcon,
  ShieldAlert,
  ShieldCheck,
  Sun,
  Terminal,
  Users as UsersIcon,
  Waypoints,
  Wifi,
} from 'lucide-react';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { api, currentNode, setNode } from '@/lib/api';
import { cn, fmtBytes, fmtRate } from '@/lib/utils';
import { useTrafficRate } from '@/hooks/use-traffic-rate';
import { Logo } from '@/components/logo';
import { ExitSwitcher } from '@/components/exit-switcher';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';

// Grouped by the user's mental model: what am I watching / what's my policy /
// where does traffic exit / system.
//
// `admin: true` hides an entry from a client. The API refuses those routes anyway;
// hiding them keeps the console from offering doors that do not open.
type NavItem = {
  to: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  end?: boolean;
  admin?: boolean;
};

const NAV_SECTIONS: { key: string; items: NavItem[] }[] = [
  {
    key: 'nav.grpMonitor',
    items: [
      { to: '/', label: 'nav.overview', icon: Activity, end: true },
      { to: '/connections', label: 'nav.connections', icon: Waypoints },
      { to: '/detection', label: 'nav.detection', icon: ShieldAlert },
      { to: '/history', label: 'nav.history', icon: HistoryIcon },
      { to: '/logs', label: 'nav.logs', icon: Terminal },
    ],
  },
  {
    key: 'nav.grpPolicy',
    items: [
      { to: '/acls', label: 'nav.acls', icon: ShieldCheck, admin: true },
      { to: '/rules', label: 'nav.rules', icon: ListTree, admin: true },
      { to: '/profiles', label: 'nav.profiles', icon: Layers, admin: true },
    ],
  },
  {
    key: 'nav.grpEgress',
    items: [
      { to: '/subscriptions', label: 'nav.nodes', icon: Wifi, admin: true },
      { to: '/proxies', label: 'nav.proxies', icon: Globe, admin: true },
      { to: '/endpoints', label: 'nav.vpn', icon: Cable, admin: true },
    ],
  },
  {
    key: 'nav.grpSystem',
    items: [
      { to: '/dns', label: 'nav.dns', icon: Radar, admin: true },
      { to: '/fleet', label: 'nav.fleet', icon: Server, admin: true },
      { to: '/users', label: 'nav.users', icon: UsersIcon, admin: true },
      { to: '/settings', label: 'nav.settings', icon: SettingsIcon, admin: true },
    ],
  },
];

const MODE_LABEL: Record<string, string> = { manual: 'Manual', system: 'System', tun: 'TUN' };

// A client sees the observability pages and nothing else: policy, nodes, users and
// the fleet are an administrator's. The API refuses them anyway — hiding them keeps
// the console from offering doors that do not open.
function useIsAdmin() {
  const { data } = useQuery({ queryKey: ['authState'], queryFn: api.authState });
  return { isAdmin: data?.user?.role === 'admin', user: data?.user };
}

function AccountMenu() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { user } = useIsAdmin();
  const out = useMutation({
    mutationFn: api.logout,
    onSuccess: () => {
      qc.clear();
      qc.invalidateQueries({ queryKey: ['authState'] });
    },
  });
  if (!user) return null;
  return (
    <div className="flex items-center gap-2 rounded-lg border bg-card px-2 py-1">
      <span className="text-xs">
        {user.username}
        <span className="ml-1 text-[10px] uppercase tracking-wider text-muted-foreground">{user.role}</span>
      </span>
      <button
        className="rounded p-1 text-muted-foreground hover:bg-accent hover:text-foreground"
        title={t('auth.signOut')}
        onClick={() => out.mutate()}
      >
        <LogOut className="size-3.5" />
      </button>
    </div>
  );
}

function useTheme() {
  const [dark, setDark] = useState(() => document.documentElement.classList.contains('dark'));
  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark);
  }, [dark]);
  return { dark, toggle: () => setDark((d) => !d) };
}

function ModeSwitcher() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [help, setHelp] = useState<{ error?: string } | null>(null);
  const { data: st } = useQuery({ queryKey: ['status'], queryFn: api.status, refetchInterval: 5000 });
  const m = useMutation({
    // TUN / system capture can sever remote access — arm a 60s dead-man's switch
    // (auto-reverts unless confirmed). manual is safe, no guard.
    mutationFn: (mode: string) => api.setMode(mode, mode === 'manual' ? undefined : 60),
    onSuccess: () => {
      setHelp(null);
      qc.invalidateQueries({ queryKey: ['status'] });
    },
    onError: (e, mode) => {
      // A TUN failure is a privilege problem → show the guidance dialog, not a
      // scary toast. The gateway has already reverted, so we're still up.
      if (mode === 'tun') setHelp({ error: String((e as Error).message) });
      else toast.error(String((e as Error).message));
    },
  });
  if (!st) return null;

  const clickMode = (mode: string) => {
    // A TUN switch that cannot work fails *after* the gateway has started
    // reconfiguring the network, so guide first. "Can it work" is not the same
    // question as "are we root" (a setcap'd Linux binary can; an elevated
    // Windows process without wintun cannot), so the gateway answers it.
    if (mode === 'tun' && !canTun(st)) {
      setHelp({});
      return;
    }
    m.mutate(mode);
  };

  return (
    <TooltipProvider delayDuration={200}>
      <div className="flex items-center gap-1 rounded-lg border bg-card p-0.5">
        <span className="px-1.5 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">{t('top.capture')}</span>
        {st.modes.map((mode) => {
          const active = mode === st.mode;
          const needRoot = mode === 'tun' && !canTun(st);
          return (
            <Tooltip key={mode}>
              <TooltipTrigger asChild>
                <button
                  disabled={m.isPending}
                  onClick={() => clickMode(mode)}
                  className={cn(
                    'rounded-md px-2.5 py-1 text-xs font-medium transition-colors cursor-pointer',
                    active ? 'bg-primary text-primary-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground',
                  )}
                >
                  {MODE_LABEL[mode] ?? mode}
                </button>
              </TooltipTrigger>
              <TooltipContent>{needRoot ? t('top.tunNeedsRoot') : t('top.captureMode', { mode })}</TooltipContent>
            </Tooltip>
          );
        })}
      </div>
      <TunHelpDialog
        open={help !== null}
        os={st.os}
        error={help?.error}
        pending={m.isPending}
        onTry={() => m.mutate('tun')}
        onClose={() => setHelp(null)}
      />
    </TooltipProvider>
  );
}

// Older gateways only reported `root`; treat that as the answer when the
// capability flag is absent rather than declaring TUN impossible.
function canTun(st: { root: boolean; can_tun?: boolean }) {
  return st.can_tun ?? st.root;
}

// TunHelpDialog explains why TUN needs elevated privileges and how to grant
// them, per OS. Shown before a doomed non-root switch, or after a TUN failure.
function TunHelpDialog({
  open,
  os,
  error,
  pending,
  onTry,
  onClose,
}: {
  open: boolean;
  os?: string;
  error?: string;
  pending: boolean;
  onTry: () => void;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const steps =
    os === 'darwin'
      ? [t('top.tunHelp.mac')]
      : os === 'linux'
        ? [t('top.tunHelp.linuxSudo'), t('top.tunHelp.linuxSetcap')]
        : os === 'windows'
          ? [t('top.tunHelp.win')]
          : [t('top.tunHelp.mac'), t('top.tunHelp.linuxSetcap')];
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('top.tunHelp.title')}</DialogTitle>
          <DialogDescription>{t('top.tunHelp.intro')}</DialogDescription>
        </DialogHeader>
        {error && (
          <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
            {error}
          </div>
        )}
        <ul className="space-y-2 text-sm">
          {steps.map((s, i) => (
            <li key={i} className="rounded-md bg-muted/60 px-3 py-2 font-mono text-xs leading-relaxed">
              {s}
            </li>
          ))}
        </ul>
        <p className="text-xs text-muted-foreground">{t('top.tunHelp.guard')}</p>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            {t('top.tunHelp.cancel')}
          </Button>
          <Button variant="secondary" disabled={pending} onClick={onTry}>
            {t('top.tunHelp.tryAnyway')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// PostureSwitcher toggles Strict (default-deny) ↔ Split (default-allow; L4 routes still apply).
// Dual-slot policy: each side keeps its own ACL/packs/DNS/etc.
function PostureSwitcher() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ['posture'], queryFn: api.posture, refetchInterval: 5000 });
  const m = useMutation({
    mutationFn: (active: string) => api.setPosture(active),
    onSuccess: (res) => {
      qc.clear();
      if (res.forced_clash_rule) toast.message(t('top.postureForcedRule'));
    },
    onError: (e) => toast.error(String((e as Error).message)),
  });
  if (!data) return null;
  const cur = data.active;
  return (
    <TooltipProvider delayDuration={200}>
      <div className="flex items-center gap-1 rounded-lg border bg-card p-0.5">
        <span className="px-1.5 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">{t('top.posture')}</span>
        {(['strict', 'split'] as const).map((mode) => {
          const active = mode === cur;
          const isSplit = mode === 'split';
          return (
            <Tooltip key={mode}>
              <TooltipTrigger asChild>
                <button
                  disabled={m.isPending}
                  onClick={() => m.mutate(mode)}
                  className={cn(
                    'rounded-md px-2.5 py-1 text-xs font-medium transition-colors cursor-pointer',
                    active
                      ? isSplit
                        ? 'bg-sky-600 text-white shadow-sm'
                        : 'bg-primary text-primary-foreground shadow-sm'
                      : 'text-muted-foreground hover:text-foreground',
                  )}
                >
                  {t(`top.posture${mode === 'strict' ? 'Strict' : 'Split'}`)}
                </button>
              </TooltipTrigger>
              <TooltipContent className="max-w-xs">
                {isSplit ? t('top.postureSplitTip') : t('top.postureStrictTip')}
              </TooltipContent>
            </Tooltip>
          );
        })}
      </div>
    </TooltipProvider>
  );
}

// RoutingSwitcher toggles the live Clash routing mode: Rule (whitelist
// default-deny, the safe default) <-> Global (default-deny OFF, unlisted traffic
// egresses via proxy; security floor stays on). Global is styled amber as a
// standing warning. Disabled while Split posture is active (Global fights CN-direct).
function RoutingSwitcher() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ['clash-mode'], queryFn: api.clashMode, refetchInterval: 5000 });
  const { data: posture } = useQuery({ queryKey: ['posture'], queryFn: api.posture, refetchInterval: 5000 });
  const split = posture?.active === 'split';
  const m = useMutation({
    mutationFn: (mode: string) => api.setClashMode(mode),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['clash-mode'] }),
    onError: (e) => toast.error(String((e as Error).message)),
  });
  if (!data) return null;
  const cur = data.mode?.toLowerCase();
  return (
    <TooltipProvider delayDuration={200}>
      <div className="flex items-center gap-1 rounded-lg border bg-card p-0.5">
        <span className="px-1.5 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">{t('top.routing')}</span>
        {data.modes.map((mode) => {
          const active = mode.toLowerCase() === cur;
          const isGlobal = mode.toLowerCase() === 'global';
          const disabled = m.isPending || (split && isGlobal);
          return (
            <Tooltip key={mode}>
              <TooltipTrigger asChild>
                <button
                  disabled={disabled}
                  onClick={() => m.mutate(mode)}
                  className={cn(
                    'rounded-md px-2.5 py-1 text-xs font-medium transition-colors cursor-pointer',
                    active
                      ? isGlobal
                        ? 'bg-amber-500 text-white shadow-sm'
                        : 'bg-primary text-primary-foreground shadow-sm'
                      : 'text-muted-foreground hover:text-foreground',
                    disabled && !active && 'opacity-40 cursor-not-allowed',
                  )}
                >
                  {mode}
                </button>
              </TooltipTrigger>
              <TooltipContent>
                {split && isGlobal
                  ? t('top.routingGlobalDisabledSplit')
                  : isGlobal
                    ? t('top.routingGlobalTip')
                    : t('top.routingRuleTip')}
              </TooltipContent>
            </Tooltip>
          );
        })}
      </div>
    </TooltipProvider>
  );
}

// GlobalModeBanner is a standing amber warning shown whenever routing is in
// Global mode, so "default-deny is off" is never a silent state.
function GlobalModeBanner() {
  const { t } = useTranslation();
  const { data } = useQuery({ queryKey: ['clash-mode'], queryFn: api.clashMode, refetchInterval: 5000 });
  if (data?.mode?.toLowerCase() !== 'global') return null;
  return (
    <div className="flex items-center gap-2 border-b border-amber-500/50 bg-amber-500/15 px-6 py-2 text-sm">
      <AlertTriangle className="size-4 shrink-0 text-amber-500" />
      <span>{t('top.globalBanner')}</span>
    </div>
  );
}

function SplitModeBanner() {
  const { t } = useTranslation();
  const { data } = useQuery({ queryKey: ['posture'], queryFn: api.posture, refetchInterval: 5000 });
  if (data?.active !== 'split') return null;
  return (
    <div className="flex items-center gap-2 border-b border-sky-500/40 bg-sky-500/10 px-6 py-2 text-sm">
      <Globe className="size-4 shrink-0 text-sky-600" />
      <span>{t('top.splitBanner')}</span>
    </div>
  );
}

function AutoBlock() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { data: st } = useQuery({ queryKey: ['status'], queryFn: api.status });
  const m = useMutation({
    mutationFn: api.setAutoBlock,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['status'] }),
  });
  if (!st) return null;
  return (
    <TooltipProvider delayDuration={200}>
      <Tooltip>
        <TooltipTrigger asChild>
          <label className="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer select-none">
            <Switch checked={st.autoBlock} onCheckedChange={(v) => m.mutate(v)} />
            {t('top.autoBlock')}
          </label>
        </TooltipTrigger>
        <TooltipContent className="max-w-xs">
          {t('top.autoBlockTip', { domains: st.threats.domains, ips: st.threats.ips })}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

function NodeSwitcher() {
  const qc = useQueryClient();
  const { data: gws = [] } = useQuery({ queryKey: ['gateways'], queryFn: api.gateways });
  const sel = currentNode() ?? 'local';
  if (gws.length === 0) return null; // no remote gateways registered -> hide
  return (
    <Select
      value={sel}
      onValueChange={(v) => {
        setNode(v === 'local' ? null : v);
        qc.clear(); // drop cached data so every page refetches the selected gateway
      }}
    >
      <SelectTrigger className="h-8 w-44 border bg-card">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="local">This gateway</SelectItem>
        {gws.map((g) => (
          <SelectItem key={g.id} value={g.id}>
            {g.name}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

function RevertBanner() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { data: st } = useQuery({ queryKey: ['status'], queryFn: api.status, refetchInterval: 1000 });
  const confirm = useMutation({
    mutationFn: api.confirmMode,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['status'] }),
  });
  if (!st?.revert) return null;
  return (
    <div className="flex items-center justify-between gap-3 border-b border-warning/50 bg-warning/15 px-6 py-2 text-sm">
      <span className="flex items-center gap-2">
        <AlertTriangle className="size-4 shrink-0 text-warning" />
        {t('top.guard', { to: st.revert.to, sec: st.revert.in_seconds })}
      </span>
      <Button size="sm" disabled={confirm.isPending} onClick={() => confirm.mutate()}>
        {t('top.keepMode')}
      </Button>
    </div>
  );
}

function TrafficPill() {
  const { t } = useTranslation();
  const { data } = useQuery({ queryKey: ['conns'], queryFn: api.connections, refetchInterval: 2000 });
  const { up, down } = useTrafficRate();
  const live = data?.connections?.length ?? 0;
  return (
    <div className="hidden items-center gap-3 rounded-lg border bg-card px-3 py-1.5 text-xs sm:flex">
      <span className="flex items-center gap-1.5">
        <span className={cn('size-1.5 rounded-full', live > 0 ? 'bg-primary animate-pulse' : 'bg-muted-foreground/40')} />
        <span className="tnum">{live}</span>
        <span className="text-muted-foreground">{t('top.live')}</span>
      </span>
      <span className="flex items-center gap-1.5" title={t('top.total')}>
        <span className="text-muted-foreground">{t('top.up')}</span>
        <span className="tnum font-medium text-foreground">{fmtRate(up)}</span>
        <span className="text-muted-foreground">{t('top.down')}</span>
        <span className="tnum font-medium text-foreground">{fmtRate(down)}</span>
      </span>
      <span className="flex items-center gap-1 text-muted-foreground" title={t('top.total')}>
        <ArrowDownUp className="size-3" />
        <span className="tnum">{fmtBytes(data?.uploadTotal ?? 0)}</span>
        <span>/</span>
        <span className="tnum">{fmtBytes(data?.downloadTotal ?? 0)}</span>
      </span>
    </div>
  );
}

export function AppShell() {
  const { isAdmin } = useIsAdmin();
  const { t } = useTranslation();
  const { dark, toggle } = useTheme();
  const { data: st } = useQuery({ queryKey: ['status'], queryFn: api.status });

  return (
    <div className="flex h-dvh overflow-hidden bg-background text-foreground">
      {/* Sidebar */}
      <aside className="flex w-60 shrink-0 flex-col border-r bg-card/40">
        <div className="flex h-14 items-center gap-2.5 px-5">
          <div className="grid size-7 place-items-center rounded-md bg-primary/15 text-primary">
            <Logo className="size-5" />
          </div>
          <div className="flex flex-col leading-none">
            <span className="text-sm font-bold tracking-tight">Trust Proxy</span>
            <span className="text-[10px] uppercase tracking-widest text-muted-foreground">{t('brand.subtitle')}</span>
          </div>
        </div>
        <nav className="flex-1 space-y-4 overflow-y-auto px-3 py-3">
          {NAV_SECTIONS.map((section) => (
            <div key={section.key} className="space-y-0.5">
              <div className="px-3 pb-1 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/60">
                {t(section.key)}
              </div>
              {section.items.filter((i) => !i.admin || isAdmin).map(({ to, label, icon: Icon, end }) => (
                <NavLink
                  key={to}
                  to={to}
                  end={end}
                  className={({ isActive }) =>
                    cn(
                      'group relative flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors',
                      isActive
                        ? 'bg-accent text-foreground'
                        : 'text-muted-foreground hover:bg-accent/50 hover:text-foreground',
                    )
                  }
                >
                  {({ isActive }) => (
                    <>
                      <span
                        className={cn(
                          'absolute left-0 top-1/2 h-4 -translate-y-1/2 rounded-r-full bg-primary transition-all',
                          isActive ? 'w-1 opacity-100' : 'w-0 opacity-0',
                        )}
                      />
                      <Icon className="size-4" />
                      {t(label)}
                    </>
                  )}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <div className="border-t p-3">
          <div className="flex items-center justify-between rounded-md px-2 py-1.5 text-xs text-muted-foreground">
            <span className="flex items-center gap-1.5">
              <ScrollText className="size-3.5" />
              {st ? t('top.intel', { domains: st.threats.domains, ips: st.threats.ips }) : '—'}
            </span>
            <span className="flex items-center gap-0.5">
              <a
                href="https://github.com/ivanzzeth/trust-proxy"
                target="_blank"
                rel="noreferrer noopener"
                title="GitHub"
                className="grid size-6 place-items-center rounded hover:bg-accent hover:text-foreground"
              >
                <Github className="size-3.5" />
              </a>
              <button onClick={toggle} className="grid size-6 place-items-center rounded hover:bg-accent cursor-pointer">
                {dark ? <Sun className="size-3.5" /> : <Moon className="size-3.5" />}
              </button>
            </span>
          </div>
        </div>
      </aside>

      {/* Main */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 shrink-0 items-center justify-end gap-3 border-b bg-background/80 px-6 backdrop-blur">
          {/* "Where does my traffic leave from" is everyone's business; the policy
              switches below are an administrator's. The admin *target* selector is
              on the Gateways page, not here — see exit-switcher.tsx. */}
          <ExitSwitcher />
          <TrafficPill />
          {isAdmin && (
            <>
              <AutoBlock />
              <PostureSwitcher />
              <RoutingSwitcher />
              <ModeSwitcher />
            </>
          )}
          <AccountMenu />
        </header>
        <RevertBanner />
        <SplitModeBanner />
        <GlobalModeBanner />
        <main className="min-h-0 flex-1 overflow-y-auto">
          <div className="mx-auto max-w-[1400px] px-6 py-6">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
