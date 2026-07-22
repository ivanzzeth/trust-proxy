import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Save } from 'lucide-react';

import { api, InboundAuth } from '@/lib/api';
import { PageHeader } from '@/components/page-header';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';

export default function Settings() {
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ['inbound'], queryFn: api.inbound });
  const [auth, setAuth] = useState<InboundAuth | null>(null);
  useEffect(() => {
    if (data && !auth) setAuth({ username: data.username ?? '', password: data.password ?? '' });
  }, [data, auth]);

  const save = useMutation({
    mutationFn: (a: InboundAuth) => api.setInbound(a),
    onSuccess: (a) => {
      toast.success(a.username ? 'Proxy inbound auth enabled' : 'Proxy inbound auth disabled (open)');
      setAuth({ username: a.username ?? '', password: a.password ?? '' });
      qc.invalidateQueries({ queryKey: ['inbound'] });
    },
    onError: (e) => toast.error(String((e as Error).message)),
  });

  if (!auth) return null;
  const enabled = auth.username !== '' || auth.password !== '';

  return (
    <div>
      <PageHeader title="Settings" description="Gateway configuration." />

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Proxy inbound auth</CardTitle>
            <CardDescription>
              Require a username/password on the mixed proxy inbound (:17070). Leave both empty to keep it open.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="inbound-user">Username</Label>
              <Input
                id="inbound-user"
                autoComplete="off"
                placeholder="(empty = open)"
                value={auth.username}
                onChange={(e) => setAuth({ ...auth, username: e.target.value })}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="inbound-pass">Password</Label>
              <Input
                id="inbound-pass"
                type="password"
                autoComplete="new-password"
                placeholder="(empty = open)"
                value={auth.password}
                onChange={(e) => setAuth({ ...auth, password: e.target.value })}
              />
            </div>
            <div className="flex items-center justify-between">
              <p className="text-xs text-muted-foreground">
                {enabled ? 'Auth required for clients on :17070.' : 'Inbound is open — no auth required.'}
              </p>
              <Button disabled={save.isPending} onClick={() => save.mutate(auth)}>
                <Save className="size-4" /> Save
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
