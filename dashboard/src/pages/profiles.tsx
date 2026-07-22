import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Check, Layers, Play, Plus, Trash2 } from 'lucide-react';

import { api } from '@/lib/api';
import { PageHeader } from '@/components/page-header';
import { Card, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

export default function Profiles() {
  const qc = useQueryClient();
  const { data: profiles = [] } = useQuery({ queryKey: ['profiles'], queryFn: api.profiles });
  const invalidate = () => {
    for (const k of ['profiles', 'whitelist', 'rulesets', 'status', 'subs', 'conns', 'events'])
      qc.invalidateQueries({ queryKey: [k] });
  };
  const err = (e: unknown) => toast.error(String((e as Error).message));
  const add = useMutation({ mutationFn: api.addProfile, onSuccess: invalidate, onError: err });
  const activate = useMutation({ mutationFn: api.activateProfile, onSuccess: () => { toast.success('Profile activated'); invalidate(); }, onError: err });
  const del = useMutation({ mutationFn: api.delProfile, onSuccess: invalidate, onError: err });

  const [name, setName] = useState('');

  return (
    <div>
      <PageHeader
        title="Profiles"
        description="Bundle nodes + whitelist + rule sets + capture mode. Activate one to switch your whole policy in a single reload."
        actions={
          <div className="flex gap-2">
            <Input className="w-48" placeholder="new profile name" value={name} onChange={(e) => setName(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && name.trim() && (add.mutate(name.trim()), setName(''))} />
            <Button disabled={!name.trim() || add.isPending} onClick={() => { add.mutate(name.trim()); setName(''); }}>
              <Plus className="size-4" /> Save current
            </Button>
          </div>
        }
      />

      {profiles.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center gap-2 py-16 text-center">
            <Layers className="size-8 text-muted-foreground/50" />
            <p className="text-sm text-muted-foreground">No profiles yet. Configure your policy, then “Save current”.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {profiles.map((p) => (
            <Card key={p.id} className={p.active ? 'ring-1 ring-primary/50' : ''}>
              <CardContent className="p-5">
                <div className="mb-3 flex items-center justify-between">
                  <div className="flex items-center gap-2 font-semibold">
                    <Layers className="size-4 text-primary" />
                    {p.name}
                  </div>
                  {p.active && <Badge variant="success"><Check className="size-3" /> active</Badge>}
                </div>
                <dl className="space-y-1.5 text-sm">
                  <Stat k="Whitelist" v={`${p.whitelist?.domains?.length ?? 0} domains · ${p.whitelist?.ips?.length ?? 0} IPs`} />
                  <Stat k="Rule sets" v={`${p.ruleset_tags?.length ?? 0}`} />
                  <Stat k="Mode" v={p.mode || '—'} />
                </dl>
                <div className="mt-4 flex gap-2">
                  <Button size="sm" className="flex-1" disabled={p.active || activate.isPending} onClick={() => activate.mutate(p.id)}>
                    <Play className="size-3.5" /> Activate
                  </Button>
                  <Button size="icon" variant="ghost" className="text-destructive" onClick={() => del.mutate(p.id)}>
                    <Trash2 className="size-4" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

function Stat({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex items-center justify-between">
      <dt className="text-muted-foreground">{k}</dt>
      <dd className="tnum capitalize">{v}</dd>
    </div>
  );
}
