import { useEffect, useRef, useState } from 'react';
import { Pause, Play, Trash2 } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { logsURL } from '@/lib/api';
import { cn } from '@/lib/utils';
import { PageHeader } from '@/components/page-header';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';

interface LogLine {
  id: number;
  type: string;
  payload: string;
}
const LEVELS = ['debug', 'info', 'warning', 'error'];
const LEVEL_LABEL_KEYS: Record<string, string> = {
  debug: 'levelDebug',
  info: 'levelInfo',
  warning: 'levelWarning',
  error: 'levelError',
};
const typeColor = (t: string) =>
  t === 'error' ? 'danger' : t === 'warning' ? 'warning' : t === 'debug' ? 'muted' : 'outline';

export default function Logs() {
  const { t } = useTranslation();
  const [level, setLevel] = useState('info');
  const [paused, setPaused] = useState(false);
  const [lines, setLines] = useState<LogLine[]>([]);
  const seq = useRef(0);

  useEffect(() => {
    if (paused) return;
    const es = new EventSource(logsURL(level));
    es.onmessage = (e) => {
      try {
        const d = JSON.parse(e.data);
        setLines((prev) => [{ id: seq.current++, type: d.type ?? 'info', payload: d.payload ?? e.data }, ...prev].slice(0, 500));
      } catch {
        /* ignore */
      }
    };
    es.onerror = () => {
      /* browser auto-reconnects */
    };
    return () => es.close();
  }, [level, paused]);

  return (
    <div>
      <PageHeader
        title={t('pages.logs.title')}
        description={t('pages.logs.description')}
        actions={
          <>
            <Select value={level} onValueChange={setLevel}>
              <SelectTrigger className="w-32">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {LEVELS.map((l) => (
                  <SelectItem key={l} value={l}>
                    {t(`pages.logs.${LEVEL_LABEL_KEYS[l]}`)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button variant="outline" size="sm" onClick={() => setPaused((p) => !p)}>
              {paused ? <Play className="size-4" /> : <Pause className="size-4" />} {paused ? t('pages.logs.resume') : t('pages.logs.pause')}
            </Button>
            <Button variant="ghost" size="sm" onClick={() => setLines([])}>
              <Trash2 className="size-4" /> {t('pages.logs.clear')}
            </Button>
          </>
        }
      />
      <Card className="overflow-hidden">
        <div className="max-h-[calc(100dvh-13rem)] overflow-y-auto font-mono text-xs">
          {lines.length === 0 ? (
            <div className="py-16 text-center text-sm text-muted-foreground">
              {paused ? t('pages.logs.paused') : t('pages.logs.waitingForLogs')}
            </div>
          ) : (
            lines.map((l) => (
              <div key={l.id} className="flex items-start gap-2 border-b border-border/40 px-4 py-1.5 last:border-0 hover:bg-muted/30">
                <Badge variant={typeColor(l.type)} className="mt-px shrink-0 uppercase">
                  {l.type}
                </Badge>
                <span className={cn('whitespace-pre-wrap break-all leading-relaxed', l.type === 'error' && 'text-destructive')}>
                  {l.payload}
                </span>
              </div>
            ))
          )}
        </div>
      </Card>
    </div>
  );
}
