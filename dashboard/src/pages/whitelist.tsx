import { type ElementType, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Cpu, Globe, MonitorSmartphone, Network, Plus, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { api, WLType } from '@/lib/api';
import { PageHeader } from '@/components/page-header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

export default function Whitelist() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { data: wl } = useQuery({ queryKey: ['whitelist'], queryFn: api.whitelist });
  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['whitelist'] });
    qc.invalidateQueries({ queryKey: ['status'] });
  };
  const add = useMutation({
    mutationFn: (v: { type: WLType; value: string }) => api.addWL(v.type, v.value),
    onSuccess: invalidate,
    onError: (e) => toast.error(String((e as Error).message)),
  });
  const del = useMutation({
    mutationFn: (v: { type: WLType; value: string }) => api.delWL(v.type, v.value),
    onSuccess: invalidate,
  });

  return (
    <div>
      <PageHeader title={t('nav.whitelist')} description={t('pages.whitelist.desc')} />
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <WLCard
          type="domain"
          icon={Globe}
          title={t('pages.whitelist.domains')}
          hint={t('pages.whitelist.domainsHint')}
          placeholder={t('pages.whitelist.domainsPh')}
          items={wl?.domains ?? []}
          onAdd={(v) => add.mutate({ type: 'domain', value: v })}
          onDel={(v) => del.mutate({ type: 'domain', value: v })}
        />
        <WLCard
          type="ip"
          icon={Network}
          title={t('pages.whitelist.ip')}
          placeholder={t('pages.whitelist.ipPh')}
          items={wl?.ips ?? []}
          onAdd={(v) => add.mutate({ type: 'ip', value: v })}
          onDel={(v) => del.mutate({ type: 'ip', value: v })}
        />
        <WLCard
          type="process"
          icon={Cpu}
          title={t('pages.whitelist.processes')}
          hint={t('pages.whitelist.processesHint')}
          placeholder={t('pages.whitelist.processesPh')}
          items={wl?.processes ?? []}
          onAdd={(v) => add.mutate({ type: 'process', value: v })}
          onDel={(v) => del.mutate({ type: 'process', value: v })}
        />
        <WLCard
          type="device"
          icon={MonitorSmartphone}
          title={t('pages.whitelist.devices')}
          hint={t('pages.whitelist.devicesHint')}
          placeholder={t('pages.whitelist.devicesPh')}
          items={wl?.devices ?? []}
          onAdd={(v) => add.mutate({ type: 'device', value: v })}
          onDel={(v) => del.mutate({ type: 'device', value: v })}
        />
      </div>
    </div>
  );
}

function WLCard({
  icon: Icon,
  title,
  hint,
  placeholder,
  items,
  onAdd,
  onDel,
}: {
  type: WLType;
  icon: ElementType;
  title: string;
  hint?: string;
  placeholder: string;
  items: string[];
  onAdd: (v: string) => void;
  onDel: (v: string) => void;
}) {
  const { t } = useTranslation();
  const [v, setV] = useState('');
  const submit = () => {
    const val = v.trim();
    if (val) {
      onAdd(val);
      setV('');
    }
  };
  return (
    <Card className="flex flex-col">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icon className="size-4 text-primary" />
          {title}
          <Badge variant="muted" className="ml-auto tnum">
            {items.length}
          </Badge>
        </CardTitle>
        {hint && <p className="text-xs leading-relaxed text-muted-foreground">{hint}</p>}
      </CardHeader>
      <CardContent className="flex flex-1 flex-col gap-3">
        <div className="flex gap-2">
          <Input
            value={v}
            placeholder={placeholder}
            onChange={(e) => setV(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && submit()}
          />
          <Button size="icon" variant="secondary" onClick={submit} disabled={!v.trim()}>
            <Plus className="size-4" />
          </Button>
        </div>
        <div className="min-h-24 space-y-1">
          {items.length === 0 && <p className="py-4 text-center text-xs text-muted-foreground">{t('common.empty')}</p>}
          {items.map((it) => (
            <div
              key={it}
              className="group flex items-center justify-between rounded-md px-2 py-1 text-sm hover:bg-muted/60"
            >
              <span className="tnum truncate">{it}</span>
              <button
                onClick={() => onDel(it)}
                className="ml-2 shrink-0 text-muted-foreground opacity-0 transition-opacity hover:text-destructive group-hover:opacity-100 cursor-pointer"
              >
                <X className="size-3.5" />
              </button>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
