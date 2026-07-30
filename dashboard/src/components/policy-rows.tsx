import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';

import { api } from '@/lib/api';
import { SettingRow } from '@/components/setting-row';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';

// Two settings that legitimately belong on two pages each: Final also belongs
// at the top of the routing view (it is the last row of that table), and open
// registration also belongs on Accounts (it is about accounts).
//
// They are components, not copies. The first draft of the Settings page had its
// own Final select offering `proxy` and `direct` while the Rules page offered
// `proxy`, `direct` and `blocked` — a third of the setting was unreachable from
// one of its two homes, and nothing failed. Sharing the query key on top of that
// is what keeps one mount from showing a value the other just changed.

const FINAL_BUILTINS = ['proxy', 'direct', 'blocked'] as const;

/** The control itself, so each page can put it in its own layout. */
export function FinalSelect({ className }: { className?: string }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ['final'], queryFn: api.final });
  const m = useMutation({
    mutationFn: (outbound: string) => api.setFinal(outbound),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['final'] });
      qc.invalidateQueries({ queryKey: ['effectiveRules'] });
    },
    onError: (e) => toast.error(String((e as Error).message)),
  });
  return (
    <Select value={data?.outbound ?? 'proxy'} onValueChange={(v) => m.mutate(v)} disabled={m.isPending}>
      <SelectTrigger className={className}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {FINAL_BUILTINS.map((o) => (
          <SelectItem key={o} value={o}>
            {t(`pages.rules.final.${o}`)}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

export function FinalRow() {
  const { t } = useTranslation();
  return (
    <SettingRow label={t('pages.settings.final')} hint={t('pages.settings.finalHint')}>
      <FinalSelect className="h-8 w-32" />
    </SettingRow>
  );
}

export function OpenRegistrationSwitch() {
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ['authSettings'], queryFn: api.authSettings });
  const m = useMutation({
    mutationFn: (v: boolean) => api.setAuthSettings(v),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['authSettings'] }),
    onError: (e) => toast.error(String((e as Error).message)),
  });
  return (
    <Switch
      checked={data?.allow_registration ?? false}
      disabled={m.isPending}
      onCheckedChange={(v) => m.mutate(v)}
    />
  );
}

export function OpenRegistrationRow() {
  const { t } = useTranslation();
  return (
    <SettingRow label={t('pages.settings.openReg')} hint={t('pages.settings.openRegHint')} tone="warn">
      <OpenRegistrationSwitch />
    </SettingRow>
  );
}
