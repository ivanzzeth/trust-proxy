import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { useTranslation } from 'react-i18next';

import { api, Defaults, DetectionConfig, InboundListen, Retention, RetentionRule, TUNConfig } from '@/lib/api';
import { LANGS } from '@/i18n';
import { ThemePref, useTheme } from '@/lib/theme';
import { PageHeader } from '@/components/page-header';
import { SettingGroup, SettingRow } from '@/components/setting-row';
import { FinalRow, OpenRegistrationRow } from '@/components/policy-rows';
import { AutoBlock, ModeSwitcher, PostureSwitcher, RoutingSwitcher } from '@/components/switchers';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';

// Every configurable thing the gateway has, in one page.
//
// It was eight places: four axes lived only in the header (where there is no
// room to say what they do, so the four most dangerous ones were the least
// explained), thresholds lived on the Detection page, DNS and scoring on their
// own, Final on the Rules page, open registration on Users — and two whole
// domains had no UI at all because they were start-up flags.
//
// The rules this page follows:
//   - Defaults come from the gateway (`/api/defaults`). A number typed here in
//     TypeScript is a second source of truth that fails silently.
//   - Shared knobs mount the *same* component as their other home, never a copy.
//   - Anything complicated gets a dialog, so the page stays a readable list.

const STACKS = ['gvisor', 'system', 'mixed'];

const listToText = (l?: string[]) => (l ?? []).join('\n');
const textToList = (t: string) =>
  t
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean);

/** Numeric field with the gateway's own default shown beneath it, so a blank
 *  input is legible as "inherits N" rather than "unset, who knows". */
function NumField({
  label,
  hint,
  value,
  def,
  step,
  onChange,
}: {
  label: string;
  hint?: string;
  value: number;
  def?: number;
  step?: string;
  onChange: (v: number) => void;
}) {
  const { t } = useTranslation();
  return (
    <div className="space-y-1">
      <Label className="text-xs">{label}</Label>
      <Input
        type="number"
        step={step}
        value={value || ''}
        placeholder={def !== undefined ? String(def) : ''}
        onChange={(e) => onChange(e.target.value === '' ? 0 : Number(e.target.value))}
      />
      {(hint || def !== undefined) && (
        <p className="text-[11px] leading-relaxed text-muted-foreground">
          {hint} {def !== undefined && t('pages.settings.defaultNote', { v: def })}
        </p>
      )}
    </div>
  );
}

/** Dialog frame: header, body, and the two-button footer every editor here
 *  shares — "restore defaults" on the left because it is a retreat, save on the
 *  right because it is the commitment. */
function EditorDialog({
  open,
  onClose,
  title,
  description,
  onRestore,
  onSave,
  pending,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  onRestore?: () => void;
  onSave: () => void;
  pending?: boolean;
  children: React.ReactNode;
}) {
  const { t } = useTranslation();
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {description && <DialogDescription>{description}</DialogDescription>}
        </DialogHeader>
        <div className="space-y-4">{children}</div>
        <DialogFooter className="justify-between">
          {onRestore ? (
            <Button variant="ghost" size="sm" onClick={onRestore}>
              {t('pages.settings.restoreDefaults')}
            </Button>
          ) : (
            <span />
          )}
          <div className="flex gap-2">
            <Button variant="ghost" size="sm" onClick={onClose}>
              {t('pages.settings.cancel')}
            </Button>
            <Button size="sm" disabled={pending} onClick={onSave}>
              {t('pages.settings.save')}
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---- TUN -------------------------------------------------------------------

function TunDialog({ open, onClose, defaults }: { open: boolean; onClose: () => void; defaults?: Defaults }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ['tun'], queryFn: api.tun });
  const { data: st } = useQuery({ queryKey: ['status'], queryFn: api.status });
  const [cfg, setCfg] = useState<TUNConfig | null>(null);
  useEffect(() => {
    if (data && open)
      setCfg({
        ...data,
        stack: data.stack || 'gvisor',
        // Missing/undefined must not save as false — that would silently disable
        // Docker capture on the next save after an older gateway's reply.
        auto_redirect: data.auto_redirect !== false,
      });
  }, [data, open]);

  const save = useMutation({
    mutationFn: (c: TUNConfig) => api.setTUN(c),
    onSuccess: () => {
      toast.success(t('pages.settings.tun.toast'));
      qc.invalidateQueries({ queryKey: ['tun'] });
      onClose();
    },
    onError: (e) => toast.error(String((e as Error).message)),
  });
  const installNft = useMutation({
    mutationFn: () => api.installNftables(true),
    onSuccess: () => {
      toast.success(t('pages.settings.tun.redirectNftInstalled'));
      qc.invalidateQueries({ queryKey: ['status'] });
    },
    onError: (e) => toast.error(String((e as Error).message)),
  });

  if (!cfg) return null;
  const nft = st?.nftables;
  const nftMissing = cfg.auto_redirect !== false && nft && (!nft.supported || !nft.usable);

  return (
    <EditorDialog
      open={open}
      onClose={onClose}
      title={t('pages.settings.tun.title')}
      description={t('pages.settings.tun.desc')}
      pending={save.isPending}
      onRestore={defaults ? () => setCfg({ ...defaults.tun }) : undefined}
      onSave={() => save.mutate(cfg)}
    >
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1">
          <Label className="text-xs">{t('pages.settings.tun.stack')}</Label>
          <Select value={cfg.stack || 'gvisor'} onValueChange={(v) => setCfg({ ...cfg, stack: v })}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {STACKS.map((s) => (
                <SelectItem key={s} value={s}>
                  {s}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <p className="text-[11px] leading-relaxed text-muted-foreground">{t('pages.settings.tun.stackDesc')}</p>
        </div>
        <NumField
          label={t('pages.settings.tun.mtu')}
          hint={t('pages.settings.tun.mtuPh')}
          value={cfg.mtu || 0}
          def={defaults?.tun.mtu}
          onChange={(v) => setCfg({ ...cfg, mtu: v })}
        />
      </div>

      <label className="flex items-center justify-between gap-4">
        <span>
          <span className="text-sm">{t('pages.settings.tun.strict')}</span>
          <p className="text-[11px] leading-relaxed text-muted-foreground">{t('pages.settings.tun.strictDesc')}</p>
        </span>
        <Switch checked={cfg.strict_route} onCheckedChange={(v) => setCfg({ ...cfg, strict_route: v })} />
      </label>

      <label className="flex items-center justify-between gap-4">
        <span>
          <span className="text-sm">{t('pages.settings.tun.redirect')}</span>
          <p className="text-[11px] leading-relaxed text-muted-foreground">{t('pages.settings.tun.redirectDesc')}</p>
        </span>
        <Switch checked={cfg.auto_redirect !== false} onCheckedChange={(v) => setCfg({ ...cfg, auto_redirect: v })} />
      </label>

      {nftMissing && (
        <div className="space-y-1 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
          <div className="font-medium">{t('pages.settings.tun.redirectNftMissingTitle')}</div>
          <div className="leading-relaxed">
            {t('pages.settings.tun.redirectNftMissingBody', { cmd: nft?.suggested_install_cmd ?? '' })}
          </div>
          {nft?.auto_install_supported && (
            <div className="flex justify-end">
              <Button variant="secondary" size="sm" disabled={installNft.isPending} onClick={() => installNft.mutate()}>
                {t('pages.settings.tun.redirectNftInstall')}
              </Button>
            </div>
          )}
        </div>
      )}

      {(
        [
          ['address', 'address', cfg.address],
          ['exclude', 'exclude_package', cfg.exclude_package],
          ['include', 'include_package', cfg.include_package],
        ] as const
      ).map(([key, field, val]) => (
        <div key={key} className="space-y-1">
          <Label className="text-xs">{t(`pages.settings.tun.${key}`)}</Label>
          <p className="text-[11px] leading-relaxed text-muted-foreground">{t(`pages.settings.tun.${key}Desc`)}</p>
          <Textarea
            className="min-h-16 w-full rounded-md border border-input bg-transparent px-2 py-1.5 font-mono text-xs shadow-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            placeholder={t(`pages.settings.tun.${key}Ph`)}
            value={listToText(val)}
            onChange={(e) => setCfg({ ...cfg, [field]: textToList(e.target.value) })}
          />
        </div>
      ))}
    </EditorDialog>
  );
}

// ---- proxy inbound ---------------------------------------------------------

// Moving the listener disconnects every client pointed at the old address, so
// the change is guarded exactly like a mode switch: the gateway puts the old
// address back unless someone confirms from the new one.
function InboundDialog({ open, onClose, defaults }: { open: boolean; onClose: () => void; defaults?: Defaults }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ['inbound'], queryFn: api.inbound, refetchInterval: open ? 2000 : false });
  const [draft, setDraft] = useState<InboundListen | null>(null);
  useEffect(() => {
    if (data && open && !draft) setDraft({ ...data.resolved });
  }, [data, open, draft]);

  const save = useMutation({
    mutationFn: (l: InboundListen) => api.setInbound(l, 60),
    onSuccess: (res) => {
      toast.success(
        t('pages.settings.inboundSaved', { addr: `${res.resolved.listen}:${res.resolved.port}` }),
      );
      qc.invalidateQueries({ queryKey: ['inbound'] });
    },
    onError: (e) => toast.error(String((e as Error).message)),
  });
  const confirm = useMutation({
    mutationFn: api.confirmInbound,
    onSuccess: () => {
      toast.success(t('pages.settings.inboundConfirmed'));
      qc.invalidateQueries({ queryKey: ['inbound'] });
    },
    onError: (e) => toast.error(String((e as Error).message)),
  });

  if (!draft) return null;
  const exposed = !!draft.listen && draft.listen !== '127.0.0.1' && draft.listen !== '::1';
  const revert = data?.revert;

  return (
    <EditorDialog
      open={open}
      onClose={() => {
        setDraft(null);
        onClose();
      }}
      title={t('pages.settings.inboundTitle')}
      description={t('pages.settings.inboundDesc')}
      pending={save.isPending}
      onRestore={defaults ? () => setDraft({ ...defaults.inbound }) : undefined}
      onSave={() => save.mutate(draft)}
    >
      {/* The pending revert is the loudest thing in the dialog on purpose: it is
          a countdown, and missing it costs the operator their access. */}
      {revert && (
        <div className="flex items-center justify-between gap-3 rounded-md border border-amber-500/50 bg-amber-500/15 px-3 py-2 text-xs">
          <span>
            {t('pages.settings.inboundRevert', {
              addr: `${revert.to.listen}:${revert.to.port}`,
              sec: revert.in_seconds,
            })}
          </span>
          <Button size="sm" disabled={confirm.isPending} onClick={() => confirm.mutate()}>
            {t('pages.settings.inboundKeep')}
          </Button>
        </div>
      )}

      <div className="space-y-1">
        <Label className="text-xs">{t('pages.settings.inboundListen')}</Label>
        <Input
          value={draft.listen ?? ''}
          placeholder={defaults?.inbound.listen}
          onChange={(e) => setDraft({ ...draft, listen: e.target.value.trim() })}
        />
        <p className="text-[11px] leading-relaxed text-muted-foreground">{t('pages.settings.inboundListenHint')}</p>
      </div>

      <NumField
        label={t('pages.settings.inboundPort')}
        hint={t('pages.settings.inboundPortHint')}
        value={draft.port ?? 0}
        def={defaults?.inbound.port}
        onChange={(v) => setDraft({ ...draft, port: v })}
      />

      {exposed && (
        <div className="rounded-md border border-amber-500/50 bg-amber-500/15 px-3 py-2 text-xs leading-relaxed">
          {t('pages.settings.inboundExposeWarn')}
        </div>
      )}
      <p className="text-[11px] leading-relaxed text-muted-foreground">{t('pages.settings.inboundGuardHint')}</p>
    </EditorDialog>
  );
}

// ---- retention -------------------------------------------------------------

function RetentionFields({
  title,
  rule,
  def,
  noRotateHint,
  onChange,
}: {
  title: string;
  rule: RetentionRule;
  def?: RetentionRule;
  noRotateHint?: string;
  onChange: (r: RetentionRule) => void;
}) {
  const { t } = useTranslation();
  return (
    <div className="space-y-3 rounded-md border p-3">
      <div className="text-sm font-medium">{title}</div>
      <div className="grid grid-cols-2 gap-3">
        <NumField
          label={t('pages.settings.maxSize')}
          hint={noRotateHint ?? t('pages.settings.maxSizeHint')}
          value={rule.max_size_mb ?? 0}
          def={def?.max_size_mb}
          onChange={(v) => onChange({ ...rule, max_size_mb: v })}
        />
        <NumField
          label={t('pages.settings.maxBackups')}
          hint={t('pages.settings.maxBackupsHint')}
          value={rule.max_backups ?? 0}
          def={def?.max_backups}
          onChange={(v) => onChange({ ...rule, max_backups: v })}
        />
        <NumField
          label={t('pages.settings.maxAge')}
          hint={t('pages.settings.maxAgeHint')}
          value={rule.max_age_days ?? 0}
          def={def?.max_age_days}
          onChange={(v) => onChange({ ...rule, max_age_days: v })}
        />
        <label className="flex items-start justify-between gap-2 pt-5">
          <span className="text-xs">{t('pages.settings.compress')}</span>
          {/* Tri-state on the wire, but a checkbox has two states, so an absent
              value renders as the default rather than as "off". */}
          <Switch
            checked={rule.compress ?? def?.compress ?? true}
            onCheckedChange={(v) => onChange({ ...rule, compress: v })}
          />
        </label>
      </div>
    </div>
  );
}

function RetentionDialog({ open, onClose, defaults }: { open: boolean; onClose: () => void; defaults?: Defaults }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ['retention'], queryFn: api.retention });
  const [draft, setDraft] = useState<Retention | null>(null);
  useEffect(() => {
    if (data && open) setDraft({ log: { ...data.log }, history: { ...data.history } });
  }, [data, open]);

  const save = useMutation({
    mutationFn: (r: Retention) => api.setRetention(r),
    onSuccess: () => {
      toast.success(t('pages.settings.retentionSaved'));
      qc.invalidateQueries({ queryKey: ['retention'] });
      onClose();
    },
    onError: (e) => toast.error(String((e as Error).message)),
  });

  if (!draft) return null;
  return (
    <EditorDialog
      open={open}
      onClose={onClose}
      title={t('pages.settings.retentionTitle')}
      description={t('pages.settings.retentionDesc')}
      pending={save.isPending}
      onRestore={defaults ? () => setDraft({ log: { ...defaults.retention.log }, history: { ...defaults.retention.history } }) : undefined}
      onSave={() => save.mutate(draft)}
    >
      <RetentionFields
        title={t('pages.settings.retentionLog')}
        rule={draft.log}
        def={defaults?.retention.log}
        onChange={(log) => setDraft({ ...draft, log })}
      />
      <RetentionFields
        title={t('pages.settings.retentionHistory')}
        rule={draft.history}
        def={defaults?.retention.history}
        noRotateHint={t('pages.settings.historyNoRotateHint')}
        onChange={(history) => setDraft({ ...draft, history })}
      />
      <p className="text-[11px] leading-relaxed text-muted-foreground">{t('pages.settings.compressHint')}</p>
    </EditorDialog>
  );
}

// ---- detection -------------------------------------------------------------

/** A switch with a sentence under it. Same rhythm as NumField so a dialog can
 *  mix the two without the layout going ragged. */
function BoolField({
  label,
  hint,
  checked,
  onChange,
}: {
  label: string;
  hint?: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label className="flex items-start justify-between gap-4">
      <span>
        <span className="text-sm">{label}</span>
        {hint && <p className="text-[11px] leading-relaxed text-muted-foreground">{hint}</p>}
      </span>
      <Switch className="mt-0.5" checked={checked} onCheckedChange={onChange} />
    </label>
  );
}

/** A titled block inside a detection dialog: the enable switch lives in the
 *  heading, because a threshold you can still type into while the detector is
 *  off reads as if it were doing something. */
function DetSection({
  title,
  hint,
  enabled,
  onToggle,
  children,
}: {
  title: string;
  hint: string;
  enabled?: boolean;
  onToggle?: (v: boolean) => void;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-3 rounded-md border p-3">
      <div className="flex items-center justify-between gap-3">
        <div className="text-sm font-medium">{title}</div>
        {onToggle && <Switch checked={!!enabled} onCheckedChange={onToggle} />}
      </div>
      <p className="text-[11px] leading-relaxed text-muted-foreground">{hint}</p>
      {children}
    </div>
  );
}

/** Both detection dialogs edit one document and PUT it whole, so they share a
 *  draft: the wire type now names every field, which is what keeps the dialog
 *  that does not show a knob from writing a zero over it. */
function useDetectionDraft(open: boolean, onClose: () => void) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ['detection-config'], queryFn: api.detectionConfig });
  const [draft, setDraft] = useState<DetectionConfig | null>(null);
  useEffect(() => {
    if (data && open) setDraft({ ...data });
  }, [data, open]);

  const save = useMutation({
    mutationFn: (c: DetectionConfig) => api.setDetectionConfig(c),
    onSuccess: () => {
      toast.success(t('pages.settings.det.saved'));
      qc.invalidateQueries({ queryKey: ['detection-config'] });
      onClose();
    },
    onError: (e) => toast.error(String((e as Error).message)),
  });

  const patch = (p: Partial<DetectionConfig>) => setDraft((d) => (d ? { ...d, ...p } : d));
  return { draft, setDraft, patch, save };
}

function DetThresholdsDialog({ open, onClose, defaults }: { open: boolean; onClose: () => void; defaults?: Defaults }) {
  const { t } = useTranslation();
  const { draft, setDraft, patch, save } = useDetectionDraft(open, onClose);
  if (!draft) return null;
  const d = defaults?.detection;
  return (
    <EditorDialog
      open={open}
      onClose={onClose}
      title={t('pages.settings.detThresholds')}
      description={t('pages.settings.det.thresholdsDesc')}
      pending={save.isPending}
      // Only this dialog's own fields go back to default; the other half of the
      // document is left as the operator set it.
      onRestore={
        d
          ? () =>
              setDraft({
                ...draft,
                beacon_enabled: d.beacon_enabled,
                beacon_min_sample: d.beacon_min_sample,
                beacon_cv: d.beacon_cv,
                beacon_min_interval_s: d.beacon_min_interval_s,
                beacon_max_interval_s: d.beacon_max_interval_s,
                beacon_realert_s: d.beacon_realert_s,
                beacon_realert_factor: d.beacon_realert_factor,
                dga_enabled: d.dga_enabled,
                dga_min_label_len: d.dga_min_label_len,
                dga_min_entropy: d.dga_min_entropy,
                tunnel_min_label_len: d.tunnel_min_label_len,
                tunnel_min_entropy: d.tunnel_min_entropy,
                subdomain_alert_at: d.subdomain_alert_at,
                exfil_upload_bytes: d.exfil_upload_bytes,
                exfil_min_ratio: d.exfil_min_ratio,
                exfil_new_dest_hours: d.exfil_new_dest_hours,
              })
          : undefined
      }
      onSave={() => save.mutate(draft)}
    >
      <DetSection
        title={t('pages.settings.det.beaconTitle')}
        hint={t('pages.settings.det.beaconHint')}
        enabled={draft.beacon_enabled}
        onToggle={(v) => patch({ beacon_enabled: v })}
      >
        <div className="grid grid-cols-2 gap-3">
          <NumField label={t('pages.settings.det.beaconMinSample')} value={draft.beacon_min_sample ?? 0} def={d?.beacon_min_sample} onChange={(v) => patch({ beacon_min_sample: v })} />
          <NumField label={t('pages.settings.det.beaconCV')} step="0.05" value={draft.beacon_cv ?? 0} def={d?.beacon_cv} onChange={(v) => patch({ beacon_cv: v })} />
          <NumField label={t('pages.settings.det.beaconWindow')} value={draft.beacon_min_interval_s ?? 0} def={d?.beacon_min_interval_s} onChange={(v) => patch({ beacon_min_interval_s: v })} />
          <NumField label={t('pages.settings.det.beaconWindowMax')} value={draft.beacon_max_interval_s ?? 0} def={d?.beacon_max_interval_s} onChange={(v) => patch({ beacon_max_interval_s: v })} />
          <NumField label={t('pages.settings.det.beaconReAlert')} value={draft.beacon_realert_s ?? 0} def={d?.beacon_realert_s} onChange={(v) => patch({ beacon_realert_s: v })} />
          <NumField label={t('pages.settings.det.beaconFactor')} value={draft.beacon_realert_factor ?? 0} def={d?.beacon_realert_factor} onChange={(v) => patch({ beacon_realert_factor: v })} />
        </div>
      </DetSection>

      <DetSection
        title={t('pages.settings.det.dgaTitle')}
        hint={t('pages.settings.det.dgaHint')}
        enabled={draft.dga_enabled}
        onToggle={(v) => patch({ dga_enabled: v })}
      >
        <div className="grid grid-cols-2 gap-3">
          <NumField label={t('pages.settings.det.dgaLabel')} value={draft.dga_min_label_len ?? 0} def={d?.dga_min_label_len} onChange={(v) => patch({ dga_min_label_len: v })} />
          <NumField label={t('pages.settings.det.dgaEntropy')} step="0.1" value={draft.dga_min_entropy ?? 0} def={d?.dga_min_entropy} onChange={(v) => patch({ dga_min_entropy: v })} />
          <NumField label={t('pages.settings.det.tunnelLabel')} value={draft.tunnel_min_label_len ?? 0} def={d?.tunnel_min_label_len} onChange={(v) => patch({ tunnel_min_label_len: v })} />
          <NumField label={t('pages.settings.det.tunnelEntropy')} step="0.1" value={draft.tunnel_min_entropy ?? 0} def={d?.tunnel_min_entropy} onChange={(v) => patch({ tunnel_min_entropy: v })} />
          <NumField label={t('pages.settings.det.subdomainAt')} value={draft.subdomain_alert_at ?? 0} def={d?.subdomain_alert_at} onChange={(v) => patch({ subdomain_alert_at: v })} />
        </div>
      </DetSection>

      <DetSection title={t('pages.settings.det.exfilTitle')} hint={t('pages.settings.det.exfilHint')}>
        <div className="grid grid-cols-2 gap-3">
          <NumField label={t('pages.settings.det.exfilBytes')} value={draft.exfil_upload_bytes ?? 0} def={d?.exfil_upload_bytes} onChange={(v) => patch({ exfil_upload_bytes: v })} />
          <NumField label={t('pages.settings.det.exfilRatio')} step="0.5" value={draft.exfil_min_ratio ?? 0} def={d?.exfil_min_ratio} onChange={(v) => patch({ exfil_min_ratio: v })} />
          <NumField label={t('pages.settings.det.exfilNewDest')} value={draft.exfil_new_dest_hours ?? 0} def={d?.exfil_new_dest_hours} onChange={(v) => patch({ exfil_new_dest_hours: v })} />
        </div>
      </DetSection>
    </EditorDialog>
  );
}

/** The ten knobs that existed in Go and on the CLI but had never been drawn. */
function DetObservationDialog({ open, onClose, defaults }: { open: boolean; onClose: () => void; defaults?: Defaults }) {
  const { t } = useTranslation();
  const { draft, setDraft, patch, save } = useDetectionDraft(open, onClose);
  if (!draft) return null;
  const d = defaults?.detection;
  return (
    <EditorDialog
      open={open}
      onClose={onClose}
      title={t('pages.settings.detObservation')}
      description={t('pages.settings.det.observationDesc')}
      pending={save.isPending}
      onRestore={
        d
          ? () =>
              setDraft({
                ...draft,
                query_window_s: d.query_window_s,
                query_nxdomain_burst: d.query_nxdomain_burst,
                query_parent_rate: d.query_parent_rate,
                query_odd_type_at: d.query_odd_type_at,
                dns_bypass_detect: d.dns_bypass_detect,
                dns_bypass_realert_s: d.dns_bypass_realert_s,
                route_watch_s: d.route_watch_s,
                route_watch_host_routes: d.route_watch_host_routes,
                ja4_enabled: d.ja4_enabled,
                ja4_learn_minutes: d.ja4_learn_minutes,
              })
          : undefined
      }
      onSave={() => save.mutate(draft)}
    >
      <DetSection title={t('pages.settings.det.queriesTitle')} hint={t('pages.settings.det.queriesHint')}>
        <div className="grid grid-cols-2 gap-3">
          <NumField label={t('pages.settings.det.queryWindow')} value={draft.query_window_s ?? 0} def={d?.query_window_s} onChange={(v) => patch({ query_window_s: v })} />
          <NumField label={t('pages.settings.det.queryNX')} value={draft.query_nxdomain_burst ?? 0} def={d?.query_nxdomain_burst} onChange={(v) => patch({ query_nxdomain_burst: v })} />
          <NumField label={t('pages.settings.det.queryParent')} value={draft.query_parent_rate ?? 0} def={d?.query_parent_rate} onChange={(v) => patch({ query_parent_rate: v })} />
          <NumField label={t('pages.settings.det.queryOddType')} value={draft.query_odd_type_at ?? 0} def={d?.query_odd_type_at} onChange={(v) => patch({ query_odd_type_at: v })} />
        </div>
      </DetSection>

      <DetSection title={t('pages.settings.det.bypassTitle')} hint={t('pages.settings.det.bypassHint')}>
        <BoolField
          label={t('pages.settings.det.bypassEnabled')}
          checked={draft.dns_bypass_detect}
          onChange={(v) => patch({ dns_bypass_detect: v })}
        />
        <NumField
          label={t('pages.settings.det.bypassReAlert')}
          value={draft.dns_bypass_realert_s ?? 0}
          def={d?.dns_bypass_realert_s}
          onChange={(v) => patch({ dns_bypass_realert_s: v })}
        />
      </DetSection>

      <DetSection title={t('pages.settings.det.routeTitle')} hint={t('pages.settings.det.routeHint')}>
        <NumField
          label={t('pages.settings.det.routeWatch')}
          value={draft.route_watch_s ?? 0}
          def={d?.route_watch_s}
          onChange={(v) => patch({ route_watch_s: v })}
        />
        <BoolField
          label={t('pages.settings.det.routeHostRoutes')}
          hint={t('pages.settings.det.routeHostRoutesHint')}
          checked={!!draft.route_watch_host_routes}
          onChange={(v) => patch({ route_watch_host_routes: v })}
        />
      </DetSection>

      <DetSection title={t('pages.settings.det.ja4Title')} hint={t('pages.settings.det.ja4Hint')}>
        <BoolField
          label={t('pages.settings.det.ja4Enabled')}
          checked={draft.ja4_enabled}
          onChange={(v) => patch({ ja4_enabled: v })}
        />
        <NumField
          label={t('pages.settings.det.ja4Learn')}
          value={draft.ja4_learn_minutes ?? 0}
          def={d?.ja4_learn_minutes}
          onChange={(v) => patch({ ja4_learn_minutes: v })}
        />
      </DetSection>
    </EditorDialog>
  );
}

/** Disposal waits for the Permit index. Lives here rather than in a dialog
 *  because it is one switch and it is the one that decides whether a finding
 *  can ban something you approved. */
function WarmPermitRow() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ['detection-config'], queryFn: api.detectionConfig });
  const m = useMutation({
    mutationFn: (v: boolean) => api.setDetectionConfig({ ...(data as DetectionConfig), require_warm_permit: v }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['detection-config'] }),
    onError: (e) => toast.error(String((e as Error).message)),
  });
  return (
    <SettingRow label={t('pages.settings.warmPermit')} hint={t('pages.settings.warmPermitHint')}>
      <Switch
        checked={data?.require_warm_permit ?? true}
        disabled={!data || m.isPending}
        onCheckedChange={(v) => m.mutate(v)}
      />
    </SettingRow>
  );
}

// ---- interface -------------------------------------------------------------

function LanguageRow() {
  const { t, i18n } = useTranslation();
  const cur = (i18n.resolvedLanguage ?? 'en').startsWith('zh') ? 'zh' : 'en';
  return (
    <SettingRow label={t('pages.settings.language')} hint={t('pages.settings.languageHint')}>
      <Select value={cur} onValueChange={(v) => void i18n.changeLanguage(v)}>
        <SelectTrigger className="h-8 w-32">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {LANGS.map((l) => (
            <SelectItem key={l.code} value={l.code}>
              {l.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </SettingRow>
  );
}

/** Theme. Three states, not two: "follow the system" is the one a console left
 *  open all day wants, and it was the one the sidebar toggle could not express. */
function ThemeRow() {
  const { t } = useTranslation();
  const { pref, setPref } = useTheme();
  return (
    <SettingRow label={t('pages.settings.theme')} hint={t('pages.settings.themeHint')}>
      <Select value={pref} onValueChange={(v) => setPref(v as ThemePref)}>
        <SelectTrigger className="h-8 w-32">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="system">{t('pages.settings.themeSystem')}</SelectItem>
          <SelectItem value="dark">{t('pages.settings.themeDark')}</SelectItem>
          <SelectItem value="light">{t('pages.settings.themeLight')}</SelectItem>
        </SelectContent>
      </Select>
    </SettingRow>
  );
}

// ---- page ------------------------------------------------------------------

type DialogName = 'tun' | 'inbound' | 'retention' | 'detThresholds' | 'detObservation' | null;

export default function Settings() {
  const { t } = useTranslation();
  const [dialog, setDialog] = useState<DialogName>(null);
  const { data: defaults } = useQuery({ queryKey: ['defaults'], queryFn: api.defaults });
  const { data: st } = useQuery({ queryKey: ['status'], queryFn: api.status, refetchInterval: 5000 });
  const { data: inbound } = useQuery({ queryKey: ['inbound'], queryFn: api.inbound });
  const { data: retention } = useQuery({ queryKey: ['retention'], queryFn: api.retention });
  const { data: dns } = useQuery({ queryKey: ['dns'], queryFn: api.dns });

  const inboundAddr = inbound ? `${inbound.resolved.listen}:${inbound.resolved.port}` : undefined;
  const logSize = retention?.log.max_size_mb ?? defaults?.retention.log.max_size_mb;

  return (
    <div>
      <PageHeader title={t('nav.settings')} description={t('pages.settings.pageDesc')} />

      <div className="grid gap-4 lg:grid-cols-2 lg:items-start">
        <div className="space-y-4">
          <SettingGroup title={t('pages.settings.grpGateway')} description={t('pages.settings.grpGatewayDesc')}>
            <SettingRow label={t('pages.settings.capture')} hint={t('pages.settings.captureHint')} tone="warn">
              <ModeSwitcher compact />
            </SettingRow>
            <SettingRow label={t('pages.settings.routing')} hint={t('pages.settings.routingHint')} tone="warn">
              <RoutingSwitcher compact />
            </SettingRow>
            <SettingRow label={t('pages.settings.posture')} hint={t('pages.settings.postureHint')} tone="warn">
              <PostureSwitcher compact />
            </SettingRow>
            <SettingRow
              label={t('pages.settings.tunAdvanced')}
              hint={t('pages.settings.tunAdvancedHint')}
              onClick={() => setDialog('tun')}
            />
            <SettingRow
              label={t('pages.settings.inbound')}
              hint={t('pages.settings.inboundHint')}
              tone="warn"
              value={inboundAddr}
              onClick={() => setDialog('inbound')}
            />
          </SettingGroup>

          <SettingGroup title={t('pages.settings.grpPolicy')} description={t('pages.settings.grpPolicyDesc')}>
            <FinalRow />
            <SettingRow
              label={t('pages.settings.dns')}
              hint={t('pages.settings.dnsHint')}
              value={dns?.final || dns?.servers?.[0]?.tag}
              to="/dns"
            />
            <SettingRow label={t('pages.settings.proxyTuning')} hint={t('pages.settings.proxyTuningHint')} to="/proxies" />
          </SettingGroup>
        </div>

        <div className="space-y-4">
          <SettingGroup title={t('pages.settings.grpDetection')} description={t('pages.settings.grpDetectionDesc')}>
            <SettingRow label={t('pages.settings.autoBlock')} hint={t('pages.settings.autoBlockHint')} tone="warn">
              <AutoBlock compact />
            </SettingRow>
            <WarmPermitRow />
            <SettingRow
              label={t('pages.settings.detThresholds')}
              hint={t('pages.settings.detThresholdsHint')}
              onClick={() => setDialog('detThresholds')}
            />
            <SettingRow
              label={t('pages.settings.detObservation')}
              hint={t('pages.settings.detObservationHint')}
              onClick={() => setDialog('detObservation')}
            />
          </SettingGroup>

          <SettingGroup title={t('pages.settings.grpSystem')} description={t('pages.settings.grpSystemDesc')}>
            <SettingRow
              label={t('pages.settings.retention')}
              hint={t('pages.settings.retentionHint')}
              value={logSize ? `${logSize} MB` : undefined}
              onClick={() => setDialog('retention')}
            />
            <OpenRegistrationRow />
            {/* Read-only facts about this installation. Admin-only server-side,
                which is also who can open this page. */}
            <SettingRow label={t('pages.settings.version')} value={st?.version ?? '—'} />
            <SettingRow label={t('pages.settings.dataDir')} value={st?.data_dir ?? '—'} />
            <SettingRow
              label={t('pages.settings.privileged')}
              value={st ? (st.privileged ?? st.root ? 'yes' : 'no') : '—'}
            />
          </SettingGroup>

          <SettingGroup title={t('pages.settings.grpUI')}>
            <LanguageRow />
            <ThemeRow />
          </SettingGroup>
        </div>
      </div>

      <TunDialog open={dialog === 'tun'} onClose={() => setDialog(null)} defaults={defaults} />
      <InboundDialog open={dialog === 'inbound'} onClose={() => setDialog(null)} defaults={defaults} />
      <RetentionDialog open={dialog === 'retention'} onClose={() => setDialog(null)} defaults={defaults} />
      <DetThresholdsDialog open={dialog === 'detThresholds'} onClose={() => setDialog(null)} defaults={defaults} />
      <DetObservationDialog open={dialog === 'detObservation'} onClose={() => setDialog(null)} defaults={defaults} />
    </div>
  );
}
