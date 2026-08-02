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

export default function Whitelist({
  embedded,
  section = 'all',
}: {
  embedded?: boolean;
  /** permit = destinations only; subjects = process/device; all = both */
  section?: 'all' | 'permit' | 'subjects';
}) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { data: wl } = useQuery({ queryKey: ['whitelist'], queryFn: api.whitelist });
  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['whitelist'] });
    qc.invalidateQueries({ queryKey: ['status'] });
  };
  const add = useMutation({
    mutationFn: (v: { type: WLType; value: string; note?: string }) =>
      api.addWL(v.type, v.value, v.note),
    onSuccess: invalidate,
    onError: (e) => toast.error(String((e as Error).message)),
  });
  const del = useMutation({
    mutationFn: (v: { type: WLType; value: string }) => api.delWL(v.type, v.value),
    onSuccess: invalidate,
  });

  const showPermit = section === 'all' || section === 'permit';
  const showSubjects = section === 'all' || section === 'subjects';
  const notes = wl?.notes ?? {};

  return (
    <div>
      {!embedded && <PageHeader title={t('nav.whitelist')} description={t('pages.whitelist.desc')} />}
      {section === 'permit' && (
        <p className="mb-4 text-xs text-muted-foreground">{t('pages.acls.permitHint')}</p>
      )}
      {section === 'subjects' && (
        <p className="mb-4 text-xs text-muted-foreground">{t('pages.acls.subjectsHint')}</p>
      )}
      <div className={`grid gap-4 md:grid-cols-2 ${section === 'all' ? 'xl:grid-cols-4' : ''}`}>
        {showPermit && (
          <>
            <WLCard
              type="domain"
              icon={Globe}
              title={t('pages.whitelist.domains')}
              hint={t('pages.whitelist.domainsHint')}
              placeholder={t('pages.whitelist.domainsPh')}
              items={wl?.domains ?? []}
              notes={notes}
              onAdd={(v, note) => add.mutate({ type: 'domain', value: v, note })}
              onDel={(v) => del.mutate({ type: 'domain', value: v })}
            />
            <WLCard
              type="ip"
              icon={Network}
              title={t('pages.whitelist.ip')}
              placeholder={t('pages.whitelist.ipPh')}
              items={wl?.ips ?? []}
              notes={notes}
              onAdd={(v, note) => add.mutate({ type: 'ip', value: v, note })}
              onDel={(v) => del.mutate({ type: 'ip', value: v })}
            />
          </>
        )}
        {showSubjects && (
          <>
            <WLCard
              type="process"
              icon={Cpu}
              title={t('pages.whitelist.processes')}
              hint={t('pages.whitelist.processesHint')}
              placeholder={t('pages.whitelist.processesPh')}
              items={wl?.processes ?? []}
              notes={notes}
              onAdd={(v, note) => add.mutate({ type: 'process', value: v, note })}
              onDel={(v) => del.mutate({ type: 'process', value: v })}
            />
            <WLCard
              type="device"
              icon={MonitorSmartphone}
              title={t('pages.whitelist.devices')}
              hint={t('pages.whitelist.devicesHint')}
              placeholder={t('pages.whitelist.devicesPh')}
              items={wl?.devices ?? []}
              notes={notes}
              onAdd={(v, note) => add.mutate({ type: 'device', value: v, note })}
              onDel={(v) => del.mutate({ type: 'device', value: v })}
            />
          </>
        )}
      </div>
    </div>
  );
}

function WLCard({
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
  type: WLType;
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
          <Icon className="size-4 text-primary" />
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
