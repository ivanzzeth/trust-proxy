import { type ElementType, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Globe, Network, Plus, Regex, Tag, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { api, BLType } from '@/lib/api';
import { PageHeader } from '@/components/page-header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

export default function Blacklist({ embedded }: { embedded?: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { data: bl } = useQuery({ queryKey: ['blacklist'], queryFn: api.blacklist });
  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['blacklist'] });
    qc.invalidateQueries({ queryKey: ['status'] });
  };
  const add = useMutation({
    mutationFn: (v: { type: BLType; value: string; note?: string }) =>
      api.addBL(v.type, v.value, v.note),
    onSuccess: invalidate,
    onError: (e) => toast.error(String((e as Error).message)),
  });
  const del = useMutation({
    mutationFn: (v: { type: BLType; value: string }) => api.delBL(v.type, v.value),
    onSuccess: invalidate,
  });
  const notes = bl?.notes ?? {};

  return (
    <div>
      {!embedded && <PageHeader title={t('nav.blacklist')} description={t('pages.blacklist.desc')} />}
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <BLCard
          type="domain"
          icon={Globe}
          title={t('pages.blacklist.domains')}
          hint={t('pages.blacklist.domainsHint')}
          placeholder={t('pages.blacklist.domainsPh')}
          items={bl?.domains ?? []}
          notes={notes}
          onAdd={(v, note) => add.mutate({ type: 'domain', value: v, note })}
          onDel={(v) => del.mutate({ type: 'domain', value: v })}
        />
        <BLCard
          type="keyword"
          icon={Tag}
          title={t('pages.blacklist.keywords')}
          hint={t('pages.blacklist.keywordsHint')}
          placeholder={t('pages.blacklist.keywordsPh')}
          items={bl?.keywords ?? []}
          notes={notes}
          onAdd={(v, note) => add.mutate({ type: 'keyword', value: v, note })}
          onDel={(v) => del.mutate({ type: 'keyword', value: v })}
        />
        <BLCard
          type="regex"
          icon={Regex}
          title={t('pages.blacklist.regexes')}
          hint={t('pages.blacklist.regexesHint')}
          placeholder={t('pages.blacklist.regexesPh')}
          items={bl?.regexes ?? []}
          notes={notes}
          onAdd={(v, note) => add.mutate({ type: 'regex', value: v, note })}
          onDel={(v) => del.mutate({ type: 'regex', value: v })}
        />
        <BLCard
          type="ip"
          icon={Network}
          title={t('pages.blacklist.ip')}
          hint={t('pages.blacklist.ipHint')}
          placeholder={t('pages.blacklist.ipPh')}
          items={bl?.ips ?? []}
          notes={notes}
          onAdd={(v, note) => add.mutate({ type: 'ip', value: v, note })}
          onDel={(v) => del.mutate({ type: 'ip', value: v })}
        />
      </div>
    </div>
  );
}

function BLCard({
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
  type: BLType;
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
          <Icon className="size-4 text-destructive" />
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
