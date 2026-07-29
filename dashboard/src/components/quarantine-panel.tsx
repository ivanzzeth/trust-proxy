import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { ShieldAlert, ShieldCheck, Undo2 } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';

import { api, QuarantineEntry } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';

/** Shared quarantine list: release (lift L1 only) or Permit (release + whitelist).
 *  Shown on Detection and under Policy → Deny so an auto-ban is not a silent
 *  "remote died" failure mode. */
export function QuarantinePanel({ compact }: { compact?: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { data: quarantined = [] } = useQuery({
    queryKey: ['quarantine'],
    queryFn: api.quarantine,
    refetchInterval: 5000,
  });

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['quarantine'] });
    qc.invalidateQueries({ queryKey: ['whitelist'] });
    qc.invalidateQueries({ queryKey: ['status'] });
  };

  const release = useMutation({
    mutationFn: (value: string) => api.releaseQuarantine(value),
    onSuccess: (_d, value) => {
      toast.success(t('pages.detection.released', { value }));
      invalidate();
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const permit = useMutation({
    mutationFn: (value: string) => api.permitQuarantine(value),
    onSuccess: (res) => {
      toast.success(
        t('pages.detection.permitted', {
          type: res.permitted.type,
          value: res.permitted.value,
        }),
      );
      invalidate();
    },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <Card className={compact ? undefined : 'mt-6'}>
      <CardHeader className="flex-row items-center gap-2 pb-3">
        <ShieldAlert className="size-4 text-amber-500" />
        <CardTitle className="text-sm">{t('pages.detection.quarantineTitle')}</CardTitle>
        <Badge variant={quarantined.length > 0 ? 'warning' : 'muted'} className="ml-auto tnum">
          {quarantined.length}
        </Badge>
      </CardHeader>
      <CardContent>
        <p className="mb-3 text-xs leading-relaxed text-muted-foreground">{t('pages.detection.quarantineHint')}</p>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t('pages.detection.colValue')}</TableHead>
              <TableHead>{t('pages.detection.colWhen')}</TableHead>
              <TableHead>{t('pages.detection.colReason')}</TableHead>
              <TableHead></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {quarantined.length === 0 && (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={4} className="py-8 text-center text-muted-foreground">
                  {t('pages.detection.quarantineEmpty')}
                </TableCell>
              </TableRow>
            )}
            {quarantined.map((e: QuarantineEntry) => (
              <TableRow key={e.value}>
                <TableCell className="font-mono text-xs">{e.value}</TableCell>
                <TableCell className="tnum text-xs text-muted-foreground">{e.time}</TableCell>
                <TableCell className="text-xs text-muted-foreground">{e.reason}</TableCell>
                <TableCell className="text-right">
                  <div className="flex flex-wrap justify-end gap-1.5">
                    <Button
                      size="xs"
                      variant="default"
                      disabled={permit.isPending || release.isPending}
                      onClick={() => permit.mutate(e.value)}
                      title={t('pages.detection.permitTip')}
                    >
                      <ShieldCheck className="size-3.5" /> {t('pages.detection.permit')}
                    </Button>
                    <Button
                      size="xs"
                      variant="secondary"
                      disabled={permit.isPending || release.isPending}
                      onClick={() => release.mutate(e.value)}
                      title={t('pages.detection.releaseTip')}
                    >
                      <Undo2 className="size-3.5" /> {t('pages.detection.release')}
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {!compact && quarantined.length > 0 && (
          <p className="mt-3 text-xs text-muted-foreground">
            <Link to="/acls" className="underline underline-offset-2 hover:text-foreground">
              {t('pages.detection.quarantineAlsoInDeny')}
            </Link>
          </p>
        )}
      </CardContent>
    </Card>
  );
}
