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
    mutationFn: (v: { type: BLType; value: string }) => api.addBL(v.type, v.value),
    onSuccess: invalidate,
    onError: (e) => toast.error(String((e as Error).message)),
  });
  const del = useMutation({
    mutationFn: (v: { type: BLType; value: string }) => api.delBL(v.type, v.value),
    onSuccess: invalidate,
  });

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
          onAdd={(v) => add.mutate({ type: 'domain', value: v })}
          onDel={(v) => del.mutate({ type: 'domain', value: v })}
        />
        <BLCard
          type="keyword"
          icon={Tag}
          title={t('pages.blacklist.keywords')}
          hint={t('pages.blacklist.keywordsHint')}
          placeholder={t('pages.blacklist.keywordsPh')}
          items={bl?.keywords ?? []}
          onAdd={(v) => add.mutate({ type: 'keyword', value: v })}
          onDel={(v) => del.mutate({ type: 'keyword', value: v })}
        />
        <BLCard
          type="regex"
          icon={Regex}
          title={t('pages.blacklist.regexes')}
          hint={t('pages.blacklist.regexesHint')}
          placeholder={t('pages.blacklist.regexesPh')}
          items={bl?.regexes ?? []}
          onAdd={(v) => add.mutate({ type: 'regex', value: v })}
          onDel={(v) => del.mutate({ type: 'regex', value: v })}
        />
        <BLCard
          type="ip"
          icon={Network}
          title={t('pages.blacklist.ip')}
          hint={t('pages.blacklist.ipHint')}
          placeholder={t('pages.blacklist.ipPh')}
          items={bl?.ips ?? []}
          onAdd={(v) => add.mutate({ type: 'ip', value: v })}
          onDel={(v) => del.mutate({ type: 'ip', value: v })}
        />
      </div>
    </div>
  );
}

function BLCard({
  icon: Icon,
  title,
  hint,
  placeholder,
  items,
  onAdd,
  onDel,
}: {
  type: BLType;
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
          <Icon className="size-4 text-destructive" />
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
