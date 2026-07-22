import { useQuery } from '@tanstack/react-query';

import { api } from '@/lib/api';
import { PageHeader } from '@/components/page-header';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';

export default function Rules() {
  const { data } = useQuery({ queryKey: ['rules'], queryFn: api.rules, refetchInterval: 5000 });
  const rules = data?.rules ?? [];

  return (
    <div>
      <PageHeader
        title="Rules"
        description="Active route rules on the data plane (via the Clash API). Read-only; edit routing through the whitelist and rule sets."
      />
      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="w-40">Type</TableHead>
                <TableHead>Payload</TableHead>
                <TableHead className="w-48">Proxy</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rules.length === 0 ? (
                <TableRow className="hover:bg-transparent">
                  <TableCell colSpan={3} className="py-10 text-center text-muted-foreground">No rules</TableCell>
                </TableRow>
              ) : (
                rules.map((r, i) => (
                  <TableRow key={i}>
                    <TableCell>
                      <Badge variant="outline" className="font-mono text-xs">{r.type}</Badge>
                    </TableCell>
                    <TableCell className="max-w-[520px] truncate font-mono text-xs" title={r.payload}>
                      {r.payload || '—'}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{r.proxy}</TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
