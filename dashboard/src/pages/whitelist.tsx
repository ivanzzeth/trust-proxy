import { type ElementType, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Cpu, Globe, MonitorSmartphone, Network, Plus, X } from 'lucide-react';

import { api, WLType } from '@/lib/api';
import { PageHeader } from '@/components/page-header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

export default function Whitelist() {
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
      <PageHeader
        title="Whitelist"
        description="Default-deny egress allow-list. Domains & IPs are destinations; Processes & Devices are opt-in source gates (empty = off)."
      />
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <WLCard
          type="domain"
          icon={Globe}
          title="Domains"
          placeholder="example.com"
          items={wl?.domains ?? []}
          onAdd={(v) => add.mutate({ type: 'domain', value: v })}
          onDel={(v) => del.mutate({ type: 'domain', value: v })}
        />
        <WLCard
          type="ip"
          icon={Network}
          title="IP / CIDR"
          placeholder="1.2.3.4/32"
          items={wl?.ips ?? []}
          onAdd={(v) => add.mutate({ type: 'ip', value: v })}
          onDel={(v) => del.mutate({ type: 'ip', value: v })}
        />
        <WLCard
          type="process"
          icon={Cpu}
          title="Processes"
          hint="When non-empty, unknown binaries can't egress at all — even to a whitelisted destination."
          placeholder="curl  /usr/bin/ssh"
          items={wl?.processes ?? []}
          onAdd={(v) => add.mutate({ type: 'process', value: v })}
          onDel={(v) => del.mutate({ type: 'process', value: v })}
        />
        <WLCard
          type="device"
          icon={MonitorSmartphone}
          title="Devices (source)"
          hint="When non-empty, only these source IPs/CIDRs may egress. For gateway/router deployments."
          placeholder="192.168.1.20"
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
  const [v, setV] = useState('');
  const submit = () => {
    const t = v.trim();
    if (t) {
      onAdd(t);
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
          {items.length === 0 && <p className="py-4 text-center text-xs text-muted-foreground">empty</p>}
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
