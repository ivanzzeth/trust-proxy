import { useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Check, Copy, Loader2, Plus, Server, Wand2 } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { api, ProxyGenResult } from '@/lib/api';
import { copyToClipboard } from '@/lib/clipboard';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';

// Self-hosted exit generator.
//
// The page used to say "run `trust-proxy proxy gen` and paste the client node
// here", which assumes a terminal and — worse — invites generating twice: the
// server keeps one keypair while the console holds another. Here the gateway
// generates once (POST /api/proxy-gen) and hands back both halves plus the shell
// script that deploys the server one, so the only manual step is pasting that
// script on the exit host.

export function ExitGenerator({ onAdded }: { onAdded?: () => void }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const { data: protocols = [] } = useQuery({ queryKey: ['proxyProtocols'], queryFn: api.proxyProtocols, enabled: open });

  const [type, setType] = useState('vless-reality');
  const [server, setServer] = useState('');
  const [port, setPort] = useState('443');
  const [sni, setSni] = useState('');
  const [name, setName] = useState('');
  const [res, setRes] = useState<ProxyGenResult | null>(null);

  const err = (e: unknown) => toast.error(String((e as Error).message));
  const gen = useMutation({
    mutationFn: () =>
      api.proxyGen({
        type,
        server: server.trim(),
        port: Number(port) || 443,
        sni: sni.trim() || undefined,
        name: name.trim() || undefined,
      }),
    onSuccess: setRes,
    onError: err,
  });
  const addNode = useMutation({
    // A single Clash proxy dict is what the importer accepts (JSON is valid
    // YAML), so the generated node goes in without a round trip through text.
    mutationFn: () => api.importNodes(String(res?.client?.name || name.trim() || type), JSON.stringify(res?.client ?? {})),
    onSuccess: () => {
      toast.success(t('pages.exitGen.added'));
      onAdded?.();
      setOpen(false);
      setRes(null);
    },
    onError: err,
  });

  return (
    <Dialog
      open={open}
      onOpenChange={(v) => {
        setOpen(v);
        if (!v) setRes(null); // secrets are shown once; don't keep them around
      }}
    >
      <DialogTrigger asChild>
        <Button variant="outline" size="sm">
          <Wand2 className="size-3.5" /> {t('pages.exitGen.trigger')}
        </Button>
      </DialogTrigger>
      <DialogContent className="max-h-[85vh] max-w-2xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Server className="size-4 text-primary" /> {t('pages.exitGen.title')}
          </DialogTitle>
          <DialogDescription>{t('pages.exitGen.intro')}</DialogDescription>
        </DialogHeader>

        <div className="grid gap-3 sm:grid-cols-2">
          <Field label={t('pages.exitGen.protocol')}>
            <Select value={type} onValueChange={setType}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {(protocols.length ? protocols : [type]).map((p) => (
                  <SelectItem key={p} value={p}>
                    {p}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          <Field label={t('pages.exitGen.port')}>
            <Input value={port} inputMode="numeric" onChange={(e) => setPort(e.target.value.replace(/\D/g, ''))} />
          </Field>
          <Field label={t('pages.exitGen.server')}>
            <Input placeholder={t('pages.exitGen.serverPh')} value={server} onChange={(e) => setServer(e.target.value)} />
          </Field>
          <Field label={t('pages.exitGen.name')}>
            <Input placeholder={t('pages.exitGen.namePh')} value={name} onChange={(e) => setName(e.target.value)} />
          </Field>
          <Field label={t('pages.exitGen.sni')} className="sm:col-span-2">
            <Input placeholder={t('pages.exitGen.sniPh')} value={sni} onChange={(e) => setSni(e.target.value)} />
          </Field>
        </div>

        <div className="flex items-center gap-3">
          <Button disabled={!server.trim() || gen.isPending} onClick={() => gen.mutate()}>
            {gen.isPending ? <Loader2 className="size-4 animate-spin" /> : <Wand2 className="size-4" />}{' '}
            {res ? t('pages.exitGen.regenerate') : t('pages.exitGen.generate')}
          </Button>
          <span className="text-xs text-muted-foreground">
            {!server.trim() ? t('pages.exitGen.needServer') : res ? t('pages.exitGen.regenWarning') : null}
          </span>
        </div>

        {res && (
          <div className="space-y-4 border-t pt-4">
            <Step title={t('pages.exitGen.step1')} hint={t('pages.exitGen.step1Hint')}>
              <CodeBlock text={res.install_script} />
            </Step>

            <Step title={t('pages.exitGen.step2')} hint={t('pages.exitGen.step2Hint')}>
              <Button size="sm" disabled={addNode.isPending} onClick={() => addNode.mutate()}>
                {addNode.isPending ? <Loader2 className="size-4 animate-spin" /> : <Plus className="size-4" />}{' '}
                {t('pages.exitGen.addNode')}
              </Button>
              <Collapsible label={t('pages.exitGen.clientNode')}>
                <CodeBlock text={JSON.stringify(res.client, null, 2)} />
              </Collapsible>
              {res.share && (
                <Collapsible label={t('pages.exitGen.shareLink')}>
                  <CodeBlock text={res.share} />
                </Collapsible>
              )}
            </Step>

            <Collapsible label={t('pages.exitGen.serverConfig')}>
              <CodeBlock text={JSON.stringify(res.server, null, 2)} />
            </Collapsible>
            <Collapsible label={t('pages.exitGen.equivalentCli')}>
              <CodeBlock text={res.gen_command} />
            </Collapsible>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

function Field({ label, className, children }: { label: string; className?: string; children: React.ReactNode }) {
  return (
    <div className={className}>
      <Label className="mb-1 block text-xs text-muted-foreground">{label}</Label>
      {children}
    </div>
  );
}

function Step({ title, hint, children }: { title: string; hint: string; children: React.ReactNode }) {
  return (
    <div className="space-y-2">
      <div>
        <div className="text-sm font-medium">{title}</div>
        <div className="text-xs text-muted-foreground">{hint}</div>
      </div>
      {children}
    </div>
  );
}

function Collapsible({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <details className="rounded-md border bg-background/40">
      <summary className="cursor-pointer px-3 py-2 text-xs text-muted-foreground">{label}</summary>
      <div className="px-3 pb-3">{children}</div>
    </details>
  );
}

function CodeBlock({ text }: { text: string }) {
  const { t } = useTranslation();
  const [done, setDone] = useState(false);
  const copy = async () => {
    if (!(await copyToClipboard(text))) {
      toast.error(t('pages.exitGen.copyFailed'));
      return;
    }
    setDone(true);
    setTimeout(() => setDone(false), 1500);
    toast.success(t('pages.exitGen.copied'));
  };
  return (
    <div className="relative">
      <pre className="max-h-64 overflow-auto rounded-md border bg-muted/40 p-3 pr-12 font-mono text-xs leading-relaxed">
        {text}
      </pre>
      <Button size="icon" variant="ghost" className="absolute right-1.5 top-1.5 size-7" onClick={copy}>
        {done ? <Check className="size-3.5 text-emerald-500" /> : <Copy className="size-3.5" />}
      </Button>
    </div>
  );
}
