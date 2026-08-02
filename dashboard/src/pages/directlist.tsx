import { type ElementType, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Globe, Lock, Network, Plus, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { api, DLType } from '@/lib/api';
import { PageHeader } from '@/components/page-header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

// DirectList is the "no-proxy" / bypass list: domains + IPs that egress DIRECT
// instead of through the proxy. It's a routing concern, separate from the
// whitelist (allow/deny). Private/LAN ranges are always bypassed by the gateway
// and don't need to be listed here.
export default function DirectList({ embedded }: { embedded?: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { data: dl } = useQuery({ queryKey: ['directlist'], queryFn: api.directlist });
  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['directlist'] });
    qc.invalidateQueries({ queryKey: ['status'] });
  };
  const add = useMutation({
    mutationFn: (v: { type: DLType; value: string; note?: string }) =>
      api.addDL(v.type, v.value, v.note),
    onSuccess: invalidate,
    onError: (e) => toast.error(String((e as Error).message)),
  });
  const del = useMutation({
    mutationFn: (v: { type: DLType; value: string }) => api.delDL(v.type, v.value),
    onSuccess: invalidate,
  });
  const notes = dl?.notes ?? {};

  return (
    <div>
      {!embedded && <PageHeader title={t('nav.acls')} description={t('pages.directlist.desc')} />}

      <Card className="mb-4">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-sm">
            <Lock className="size-4 text-muted-foreground" />
            {t('pages.directlist.builtinTitle')}
            <Badge variant="muted" className="ml-auto tnum">{dl?.builtin?.length ?? 0}</Badge>
          </CardTitle>
          <p className="text-xs leading-relaxed text-muted-foreground">{t('pages.directlist.builtinHint')}</p>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-1.5">
          {(dl?.builtin ?? []).map((c) => (
            <Badge key={c} variant="outline" className="tnum font-mono text-[10px]">{c}</Badge>
          ))}
        </CardContent>
      </Card>

      <div className="grid gap-4 md:grid-cols-2">
        <DLCard
          type="domain"
          icon={Globe}
          title={t('pages.directlist.domains')}
          hint={t('pages.directlist.domainsHint')}
          placeholder={t('pages.directlist.domainsPh')}
          items={dl?.domains ?? []}
          notes={notes}
          onAdd={(v, note) => add.mutate({ type: 'domain', value: v, note })}
          onDel={(v) => del.mutate({ type: 'domain', value: v })}
        />
        <DLCard
          type="ip"
          icon={Network}
          title={t('pages.directlist.ip')}
          hint={t('pages.directlist.ipHint')}
          placeholder={t('pages.directlist.ipPh')}
          items={dl?.ips ?? []}
          notes={notes}
          onAdd={(v, note) => add.mutate({ type: 'ip', value: v, note })}
          onDel={(v) => del.mutate({ type: 'ip', value: v })}
        />
      </div>
    </div>
  );
}

function DLCard({
  type,
  icon: Icon,
  title,
  hint,
  placeholder,
  items,
  notes,
  onAdd,
  onDel,
}: {
  type: DLType;
  icon: ElementType;
  title: string;
  hint?: string;
  placeholder: string;
  items: string[];
  notes: Record<string, string>;
  onAdd: (v: string, note?: string) => void;
  onDel: (v: string) => void;
}) {
  const { t } = useTranslation();
  const [v, setV] = useState('');
  const [note, setNote] = useState('');
  const submit = () => {
    const val = v.trim();
    if (val) {
      onAdd(val, note.trim() || undefined);
      setV('');
      setNote('');
    }
  };
  return (
    <Card className="flex flex-col">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icon className="size-4 text-sky-500" />
          {title}
          <Badge variant="muted" className="ml-auto tnum">
            {items.length}
          </Badge>
        </CardTitle>
        {hint && <p className="text-xs leading-relaxed text-muted-foreground">{hint}</p>}
      </CardHeader>
      <CardContent className="flex flex-1 flex-col gap-3">
        <div className="flex flex-col gap-2">
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
          <Input
            value={note}
            placeholder={t('pages.acls.notePh')}
            onChange={(e) => setNote(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && submit()}
          />
        </div>
        <div className="min-h-24 space-y-1">
          {items.length === 0 && <p className="py-4 text-center text-xs text-muted-foreground">{t('common.empty')}</p>}
          {items.map((it) => {
            const remark = notes[`${type}:${it}`];
            return (
              <div
                key={it}
                className="group flex items-start justify-between gap-2 rounded-md px-2 py-1 text-sm hover:bg-muted/60"
              >
                <div className="min-w-0">
                  <div className="tnum truncate">{it}</div>
                  {remark && <div className="truncate text-xs text-muted-foreground">{remark}</div>}
                </div>
                <button
                  onClick={() => onDel(it)}
                  className="mt-0.5 ml-2 shrink-0 text-muted-foreground opacity-0 transition-opacity hover:text-destructive group-hover:opacity-100 cursor-pointer"
                >
                  <X className="size-3.5" />
                </button>
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}
