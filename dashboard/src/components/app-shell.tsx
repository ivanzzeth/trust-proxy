import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { NavLink, Outlet } from 'react-router-dom';
import { toast } from 'sonner';
import {
  Activity,
  ArrowDownUp,
  Globe,
  History as HistoryIcon,
  Layers,
  ListChecks,
  Moon,
  Radar,
  ScrollText,
  ShieldCheck,
  Sun,
  Terminal,
  Waypoints,
  Wifi,
} from 'lucide-react';
import { useEffect, useState } from 'react';

import { api } from '@/lib/api';
import { cn, fmtBytes } from '@/lib/utils';
import { Switch } from '@/components/ui/switch';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';

const NAV = [
  { to: '/', label: 'Overview', icon: Activity, end: true },
  { to: '/connections', label: 'Connections', icon: Waypoints },
  { to: '/subscriptions', label: 'Nodes', icon: Wifi },
  { to: '/profiles', label: 'Profiles', icon: Layers },
  { to: '/whitelist', label: 'Whitelist', icon: ShieldCheck },
  { to: '/rulesets', label: 'Rule Sets', icon: ListChecks },
  { to: '/proxies', label: 'Proxies', icon: Globe },
  { to: '/dns', label: 'DNS', icon: Radar },
  { to: '/history', label: 'History', icon: HistoryIcon },
  { to: '/logs', label: 'Logs', icon: Terminal },
];

const MODE_LABEL: Record<string, string> = { manual: 'Manual', system: 'System', tun: 'TUN' };

function useTheme() {
  const [dark, setDark] = useState(() => document.documentElement.classList.contains('dark'));
  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark);
  }, [dark]);
  return { dark, toggle: () => setDark((d) => !d) };
}

function ModeSwitcher() {
  const qc = useQueryClient();
  const { data: st } = useQuery({ queryKey: ['status'], queryFn: api.status, refetchInterval: 5000 });
  const m = useMutation({
    mutationFn: api.setMode,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['status'] }),
    onError: (e) => toast.error(String((e as Error).message)),
  });
  if (!st) return null;
  return (
    <TooltipProvider delayDuration={200}>
      <div className="flex items-center gap-1 rounded-lg border bg-card p-0.5">
        {st.modes.map((mode) => {
          const active = mode === st.mode;
          const needRoot = mode === 'tun' && !st.root;
          return (
            <Tooltip key={mode}>
              <TooltipTrigger asChild>
                <button
                  disabled={m.isPending}
                  onClick={() => m.mutate(mode)}
                  className={cn(
                    'rounded-md px-2.5 py-1 text-xs font-medium transition-colors cursor-pointer',
                    active ? 'bg-primary text-primary-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground',
                  )}
                >
                  {MODE_LABEL[mode] ?? mode}
                </button>
              </TooltipTrigger>
              <TooltipContent>{needRoot ? 'TUN needs root (start with sudo)' : `Capture mode: ${mode}`}</TooltipContent>
            </Tooltip>
          );
        })}
      </div>
    </TooltipProvider>
  );
}

function AutoBlock() {
  const qc = useQueryClient();
  const { data: st } = useQuery({ queryKey: ['status'], queryFn: api.status });
  const m = useMutation({
    mutationFn: api.setAutoBlock,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['status'] }),
  });
  if (!st) return null;
  return (
    <label className="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer select-none">
      <Switch checked={st.autoBlock} onCheckedChange={(v) => m.mutate(v)} />
      Auto-block
    </label>
  );
}

function TrafficPill() {
  const { data } = useQuery({ queryKey: ['conns'], queryFn: api.connections, refetchInterval: 2000 });
  const live = data?.connections?.length ?? 0;
  return (
    <div className="hidden items-center gap-3 rounded-lg border bg-card px-3 py-1.5 text-xs sm:flex">
      <span className="flex items-center gap-1.5">
        <span className={cn('size-1.5 rounded-full', live > 0 ? 'bg-primary animate-pulse' : 'bg-muted-foreground/40')} />
        <span className="tnum">{live}</span>
        <span className="text-muted-foreground">live</span>
      </span>
      <span className="flex items-center gap-1 text-muted-foreground">
        <ArrowDownUp className="size-3" />
        <span className="tnum text-foreground">{fmtBytes(data?.uploadTotal ?? 0)}</span>
        <span>/</span>
        <span className="tnum text-foreground">{fmtBytes(data?.downloadTotal ?? 0)}</span>
      </span>
    </div>
  );
}

export function AppShell() {
  const { dark, toggle } = useTheme();
  const { data: st } = useQuery({ queryKey: ['status'], queryFn: api.status });

  return (
    <div className="flex h-dvh overflow-hidden bg-background text-foreground">
      {/* Sidebar */}
      <aside className="flex w-60 shrink-0 flex-col border-r bg-card/40">
        <div className="flex h-14 items-center gap-2.5 px-5">
          <div className="grid size-7 place-items-center rounded-md bg-primary/15 text-primary">
            <ShieldCheck className="size-4" />
          </div>
          <div className="flex flex-col leading-none">
            <span className="text-sm font-bold tracking-tight">trust-proxy</span>
            <span className="text-[10px] uppercase tracking-widest text-muted-foreground">gateway</span>
          </div>
        </div>
        <nav className="flex-1 space-y-0.5 px-3 py-3">
          {NAV.map(({ to, label, icon: Icon, end }) => (
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
                  {label}
                </>
              )}
            </NavLink>
          ))}
        </nav>
        <div className="border-t p-3">
          <div className="flex items-center justify-between rounded-md px-2 py-1.5 text-xs text-muted-foreground">
            <span className="flex items-center gap-1.5">
              <ScrollText className="size-3.5" />
              {st ? `${st.threats.domains}d / ${st.threats.ips}ip intel` : '—'}
            </span>
            <button onClick={toggle} className="grid size-6 place-items-center rounded hover:bg-accent cursor-pointer">
              {dark ? <Sun className="size-3.5" /> : <Moon className="size-3.5" />}
            </button>
          </div>
        </div>
      </aside>

      {/* Main */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 shrink-0 items-center justify-end gap-3 border-b bg-background/80 px-6 backdrop-blur">
          <TrafficPill />
          <AutoBlock />
          <ModeSwitcher />
        </header>
        <main className="min-h-0 flex-1 overflow-y-auto">
          <div className="mx-auto max-w-[1400px] px-6 py-6">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
