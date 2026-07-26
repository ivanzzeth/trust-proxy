import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { ShieldAlert, Save, Undo2 } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { api, DetectionConfig } from '@/lib/api';
import { PageHeader } from '@/components/page-header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';

// Detection tuning + the gateway's own quarantine list.
//
// Thresholds were constants, so the alert stream was whatever the defaults
// produced: on a real box, 1082 of 1137 daily alerts were ordinary keepalives.
// Quarantine is deliberately not the deny list — deny is operator policy stored
// in the posture slot, and a Strict<->Split switch replaces it wholesale, which
// would silently un-block something the gateway blocked for cause.
export default function Detection() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ['detection-config'], queryFn: api.detectionConfig });
  const { data: quarantined = [] } = useQuery({ queryKey: ['quarantine'], queryFn: api.quarantine, refetchInterval: 10000 });
  const [cfg, setCfg] = useState<DetectionConfig | null>(null);
  useEffect(() => { if (data) setCfg(data); }, [data]);

  const save = useMutation({
    mutationFn: (c: DetectionConfig) => api.setDetectionConfig(c),
    onSuccess: () => { toast.success(t('pages.detection.saved')); qc.invalidateQueries({ queryKey: ['detection-config'] }); },
    onError: (e: Error) => toast.error(e.message),
  });
  const release = useMutation({
    mutationFn: (value: string) => api.releaseQuarantine(value),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['quarantine'] }),
    onError: (e: Error) => toast.error(e.message),
  });

  if (!cfg) return null;
  const patch = (p: Partial<DetectionConfig>) => setCfg({ ...cfg, ...p });
  const num = (v: string) => (v === '' ? 0 : Number(v));

  return (
    <div>
      <PageHeader title={t('pages.detection.title')} description={t('pages.detection.description')} />

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="flex-row items-center gap-2 pb-3">
            <CardTitle className="text-sm">{t('pages.detection.beaconTitle')}</CardTitle>
            <Switch className="ml-auto" checked={cfg.beacon_enabled} onCheckedChange={(v) => patch({ beacon_enabled: v })} />
          </CardHeader>
          <CardContent className="space-y-2">
            <p className="text-xs leading-relaxed text-muted-foreground">{t('pages.detection.beaconHint')}</p>
            <Field label={t('pages.detection.beaconMinSample')} value={cfg.beacon_min_sample ?? 0} onChange={(v) => patch({ beacon_min_sample: num(v) })} />
            <Field label={t('pages.detection.beaconCV')} value={cfg.beacon_cv ?? 0} step="0.05" onChange={(v) => patch({ beacon_cv: num(v) })} />
            <Field label={t('pages.detection.beaconWindow')} value={cfg.beacon_min_interval_s ?? 0} onChange={(v) => patch({ beacon_min_interval_s: num(v) })} />
            <Field label={t('pages.detection.beaconWindowMax')} value={cfg.beacon_max_interval_s ?? 0} onChange={(v) => patch({ beacon_max_interval_s: num(v) })} />
            <Field label={t('pages.detection.beaconReAlert')} value={cfg.beacon_realert_s ?? 0} onChange={(v) => patch({ beacon_realert_s: num(v) })} />
            <Field label={t('pages.detection.beaconFactor')} value={cfg.beacon_realert_factor ?? 0} onChange={(v) => patch({ beacon_realert_factor: num(v) })} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex-row items-center gap-2 pb-3">
            <CardTitle className="text-sm">{t('pages.detection.dgaTitle')}</CardTitle>
            <Switch className="ml-auto" checked={cfg.dga_enabled} onCheckedChange={(v) => patch({ dga_enabled: v })} />
          </CardHeader>
          <CardContent className="space-y-2">
            <p className="text-xs leading-relaxed text-muted-foreground">{t('pages.detection.dgaHint')}</p>
            <Field label={t('pages.detection.dgaLabel')} value={cfg.dga_min_label_len ?? 0} onChange={(v) => patch({ dga_min_label_len: num(v) })} />
            <Field label={t('pages.detection.dgaEntropy')} value={cfg.dga_min_entropy ?? 0} step="0.1" onChange={(v) => patch({ dga_min_entropy: num(v) })} />
            <Field label={t('pages.detection.tunnelLabel')} value={cfg.tunnel_min_label_len ?? 0} onChange={(v) => patch({ tunnel_min_label_len: num(v) })} />
            <Field label={t('pages.detection.tunnelEntropy')} value={cfg.tunnel_min_entropy ?? 0} step="0.1" onChange={(v) => patch({ tunnel_min_entropy: num(v) })} />
            <Field label={t('pages.detection.subdomainAt')} value={cfg.subdomain_alert_at ?? 0} onChange={(v) => patch({ subdomain_alert_at: num(v) })} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3"><CardTitle className="text-sm">{t('pages.detection.exfilTitle')}</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            <p className="text-xs leading-relaxed text-muted-foreground">{t('pages.detection.exfilHint')}</p>
            <Field label={t('pages.detection.exfilBytes')} value={cfg.exfil_upload_bytes ?? 0} onChange={(v) => patch({ exfil_upload_bytes: num(v) })} />
            <Field label={t('pages.detection.exfilRatio')} value={cfg.exfil_min_ratio ?? 0} step="0.5" onChange={(v) => patch({ exfil_min_ratio: num(v) })} />
            <Field label={t('pages.detection.exfilNewDest')} value={cfg.exfil_new_dest_hours ?? 0} onChange={(v) => patch({ exfil_new_dest_hours: num(v) })} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3"><CardTitle className="text-sm">{t('pages.detection.disposalTitle')}</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            <label className="flex items-center gap-2 text-xs text-muted-foreground">
              <Switch checked={cfg.auto_block} onCheckedChange={(v) => patch({ auto_block: v })} />
              {t('pages.detection.autoBlock')}
            </label>
            <label className="flex items-center gap-2 text-xs text-muted-foreground">
              <Switch checked={cfg.require_warm_permit} onCheckedChange={(v) => patch({ require_warm_permit: v })} />
              {t('pages.detection.requireWarm')}
            </label>
            <p className="text-xs leading-relaxed text-muted-foreground">{t('pages.detection.requireWarmHint')}</p>
          </CardContent>
        </Card>
      </div>

      <div className="mt-4 flex justify-end">
        <Button size="sm" disabled={save.isPending} onClick={() => save.mutate(cfg)}>
          <Save className="size-3.5" /> {t('pages.detection.apply')}
        </Button>
      </div>

      <Card className="mt-6">
        <CardHeader className="flex-row items-center gap-2 pb-3">
          <ShieldAlert className="size-4 text-amber-500" />
          <CardTitle className="text-sm">{t('pages.detection.quarantineTitle')}</CardTitle>
          <Badge variant="muted" className="ml-auto tnum">{quarantined.length}</Badge>
        </CardHeader>
        <CardContent>
          <p className="mb-3 text-xs leading-relaxed text-muted-foreground">{t('pages.detection.quarantineHint')}</p>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('pages.detection.colValue')}</TableHead>
                <TableHead>{t('pages.detection.colWhen')}</TableHead>
                <TableHead>{t('pages.detection.colReason')}</TableHead>
                <TableHead></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {quarantined.length === 0 && (
                <TableRow className="hover:bg-transparent">
                  <TableCell colSpan={4} className="py-8 text-center text-muted-foreground">{t('pages.detection.quarantineEmpty')}</TableCell>
                </TableRow>
              )}
              {quarantined.map((e) => (
                <TableRow key={e.value}>
                  <TableCell className="font-mono text-xs">{e.value}</TableCell>
                  <TableCell className="tnum text-xs text-muted-foreground">{e.time}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{e.reason}</TableCell>
                  <TableCell className="text-right">
                    <Button size="xs" variant="secondary" onClick={() => release.mutate(e.value)}>
                      <Undo2 className="size-3.5" /> {t('pages.detection.release')}
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

function Field({ label, value, step, onChange }: { label: string; value: number; step?: string; onChange: (v: string) => void }) {
  return (
    <label className="grid grid-cols-[1fr_8rem] items-center gap-2 text-xs text-muted-foreground">
      {label}
      <Input className="h-8 tnum" type="number" step={step} value={value} onChange={(e) => onChange(e.target.value)} />
    </label>
  );
}
