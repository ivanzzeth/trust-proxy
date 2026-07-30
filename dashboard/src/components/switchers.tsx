import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Loader2, ShieldCheck } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { api } from '@/lib/api';
import { inDesktopApp, installServiceViaApp } from '@/lib/desktop';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';

// The four policy axes that used to live only in the header. They are shared,
// not copied: the header and the Settings page mount the *same* component.
//
// Copying one into Settings would give the same setting two writers, and the
// bug that produces is not hypothetical — auto-block already shipped that way
// once, with only one of the two writers persisting anything. The mode switch
// carries a 60-second dead-man's switch; a second copy would eventually be
// written without it, and the failure mode there is a machine you cannot reach.

const MODE_LABEL: Record<string, string> = { manual: 'Manual', system: 'System', tun: 'TUN' };

// Older gateways only reported `root`; treat that as the answer when the
// capability flag is absent rather than declaring TUN impossible.
export function canTun(st: { root: boolean; can_tun?: boolean }) {
  return st.can_tun ?? st.root;
}

/** Shared look for the three segmented pills. `variant` only changes the label
 *  chip: inside a settings row the axis name is already the row label. */
function Segmented({ label, children, compact }: { label: string; children: React.ReactNode; compact?: boolean }) {
  return (
    <div className="flex items-center gap-1 rounded-lg border bg-card p-0.5">
      {!compact && (
        <span className="px-1.5 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">{label}</span>
      )}
      {children}
    </div>
  );
}

export function ModeSwitcher({ compact }: { compact?: boolean } = {}) {
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
      <Segmented label={t('top.capture')} compact={compact}>
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
      </Segmented>
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

// TunHelpDialog explains why TUN needs elevated privileges and how to grant
// them, per OS. Shown before a doomed non-root switch, or after a TUN failure.
export function TunHelpDialog({
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
  // Inside the desktop app there is a button for this, so the shell-command
  // instructions below are the fallback for a browser, not the main event.
  const desktop = inDesktopApp();
  const [elevating, setElevating] = useState(false);
  const elevate = async () => {
    setElevating(true);
    try {
      await installServiceViaApp('tun');
      toast.success(t('top.tunHelp.elevated'));
      // The service now owns the gateway; the shell has re-attached to it, and a
      // reload picks up the new /api/status (root, can_tun, mode).
      setTimeout(() => window.location.reload(), 1200);
    } catch (e) {
      toast.error(String((e as Error).message));
      setElevating(false);
    }
  };
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
        {desktop ? (
          <div className="space-y-2 rounded-md border border-primary/40 bg-primary/5 px-3 py-2.5">
            <div className="text-sm font-medium">{t('top.tunHelp.appTitle')}</div>
            <p className="text-xs text-muted-foreground">{t('top.tunHelp.appBody')}</p>
          </div>
        ) : (
          <ul className="space-y-2 text-sm">
            {steps.map((s, i) => (
              <li key={i} className="rounded-md bg-muted/60 px-3 py-2 font-mono text-xs leading-relaxed">
                {s}
              </li>
            ))}
          </ul>
        )}
        <p className="text-xs text-muted-foreground">{t('top.tunHelp.guard')}</p>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            {t('top.tunHelp.cancel')}
          </Button>
          {desktop ? (
            <Button disabled={elevating} onClick={elevate}>
              {elevating ? <Loader2 className="size-4 animate-spin" /> : <ShieldCheck className="size-4" />}{' '}
              {t('top.tunHelp.appAction')}
            </Button>
          ) : (
            <Button variant="secondary" disabled={pending} onClick={onTry}>
              {t('top.tunHelp.tryAnyway')}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// PostureSwitcher toggles Strict (default-deny) ↔ Split (default-allow; L4 routes still apply).
// Dual-slot policy: each side keeps its own ACL/packs/DNS/etc.
export function PostureSwitcher({ compact }: { compact?: boolean } = {}) {
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
      <Segmented label={t('top.posture')} compact={compact}>
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
      </Segmented>
    </TooltipProvider>
  );
}

// RoutingSwitcher toggles the live Clash routing mode: Rule (whitelist
// default-deny, the safe default) <-> Global (default-deny OFF, unlisted traffic
// egresses via proxy; security floor stays on). Global is styled amber as a
// standing warning. Disabled while Split posture is active (Global fights CN-direct).
export function RoutingSwitcher({ compact }: { compact?: boolean } = {}) {
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
      <Segmented label={t('top.routing')} compact={compact}>
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
      </Segmented>
    </TooltipProvider>
  );
}

/** Auto-disposal. `compact` drops the inline label for a settings row, where the
 *  row already says what it is. */
export function AutoBlock({ compact }: { compact?: boolean } = {}) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { data: st } = useQuery({ queryKey: ['status'], queryFn: api.status });
  const m = useMutation({
    mutationFn: api.setAutoBlock,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['status'] }),
    onError: (e) => toast.error(String((e as Error).message)),
  });
  if (!st) return null;
  if (compact) {
    return <Switch checked={st.autoBlock} disabled={m.isPending} onCheckedChange={(v) => m.mutate(v)} />;
  }
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
