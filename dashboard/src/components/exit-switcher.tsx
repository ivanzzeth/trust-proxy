import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { useTranslation } from 'react-i18next';

import { api } from '@/lib/api';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';

// "Where does my traffic leave from" — the control everybody needs, so it lives in
// the top bar for every role.
//
// It must not be the same control as "which gateway am I administering". Merging
// them means an admin who opens a remote gateway's config silently reroutes their
// own traffic, which is a surprise nobody wants twice. The admin target lives on
// the Gateways page instead.
//
// Switching an exit needs no special mechanism: subscription nodes, WireGuard
// endpoints and gateways are all members of the proxy group, so this is the
// existing proxy-group select.

export function ExitSwitcher() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ['proxies'], queryFn: api.proxies, refetchInterval: 10000 });

  const group = data?.proxies?.['proxy'];
  const members = group?.all ?? [];
  const now = group?.now ?? '';

  const select = useMutation({
    mutationFn: (name: string) => api.selectProxy('proxy', name),
    onSuccess: (_r, name) => {
      toast.success(t('top.exitSwitched', { name }));
      qc.invalidateQueries({ queryKey: ['proxies'] });
      qc.invalidateQueries({ queryKey: ['conns'] });
    },
    onError: (e) => toast.error(String((e as Error).message)),
  });

  if (members.length === 0) return null;

  return (
    <div className="flex items-center gap-1 rounded-lg border bg-card p-0.5">
      <span className="px-1.5 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
        {t('top.exit')}
      </span>
      <Select value={now} onValueChange={(v) => select.mutate(v)}>
        <SelectTrigger className="h-7 w-[150px] border-0 bg-transparent px-2 text-xs shadow-none focus:ring-0">
          <SelectValue placeholder={t('top.exitPick')} />
        </SelectTrigger>
        <SelectContent>
          {members.map((m) => (
            <SelectItem key={m} value={m}>
              {m}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}
