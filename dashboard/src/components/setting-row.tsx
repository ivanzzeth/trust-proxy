import { ChevronRight, HelpCircle, Loader2, Settings2, TriangleAlert } from 'lucide-react';
import { NavLink } from 'react-router-dom';

import { cn } from '@/lib/utils';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';

// The settings grammar, borrowed from Clash Verge: one row primitive that
// switches between "shows a value" and "opens something" on the presence of an
// action, so every setting reads the same way down the page regardless of how
// complicated it is underneath.
//
// The hint is not decoration. "Every knob must have a sentence of plain
// language" is half the ask this page exists to answer — the other half being
// that the knobs were scattered across eight places. A row without a hint is a
// setting the reader still has to guess at.

type Tone = 'default' | 'warn';

/** The icon carries the meaning, so it has to match the kind of row:
 *  ⓘ explains, ⚙ opens an editor, ⚠ says "this can cut you off". */
function HintIcon({ hint, tone, kind }: { hint: string; tone: Tone; kind: 'info' | 'dialog' }) {
  const Icon = tone === 'warn' ? TriangleAlert : kind === 'dialog' ? Settings2 : HelpCircle;
  return (
    <TooltipProvider delayDuration={200}>
      <Tooltip>
        <TooltipTrigger asChild>
          {/* A span, not a button: an action row IS a button, and a nested
              button is invalid markup the browser hoists out of the row. It is
              not focusable anyway — the hint is also the row's aria-label. */}
          <span
            role="img"
            aria-label={hint}
            className={cn(
              'grid size-4 shrink-0 place-items-center rounded text-muted-foreground/70 hover:text-foreground',
              tone === 'warn' && 'text-amber-500 hover:text-amber-400',
            )}
          >
            <Icon className="size-3.5" />
          </span>
        </TooltipTrigger>
        <TooltipContent className="max-w-xs leading-relaxed">{hint}</TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

export type SettingRowProps = {
  label: string;
  /** One sentence of plain language, shown as a tooltip beside the label. */
  hint?: string;
  /** Amber warning styling: this setting can sever access if set wrong. */
  tone?: Tone;
  /** A short summary of the current value, shown left of the chevron. */
  value?: React.ReactNode;
  /** Right-hand control (Switch / Select / segmented). Mutually exclusive with onClick/to. */
  children?: React.ReactNode;
  /** Action row: opens a dialog. */
  onClick?: () => void;
  /** Navigation row: this setting has its own page. */
  to?: string;
  pending?: boolean;
  disabled?: boolean;
};

export function SettingRow({ label, hint, tone = 'default', value, children, onClick, to, pending, disabled }: SettingRowProps) {
  const interactive = !!onClick || !!to;
  const body = (
    <>
      <div className="flex min-w-0 items-center gap-1.5">
        <span className={cn('truncate text-sm', tone === 'warn' && 'text-amber-600 dark:text-amber-400')}>{label}</span>
        {hint && <HintIcon hint={hint} tone={tone} kind={interactive ? 'dialog' : 'info'} />}
      </div>
      <div className="flex shrink-0 items-center gap-2">
        {value !== undefined && (
          <span className="max-w-[16rem] truncate text-xs text-muted-foreground">{value}</span>
        )}
        {children}
        {pending && <Loader2 className="size-4 animate-spin text-muted-foreground" />}
        {interactive && !pending && <ChevronRight className="size-4 text-muted-foreground/60" />}
      </div>
    </>
  );

  const rowClass = cn(
    'flex min-h-11 items-center justify-between gap-3 px-4 py-2',
    interactive && 'w-full cursor-pointer text-left transition-colors hover:bg-accent/50',
    disabled && 'pointer-events-none opacity-50',
  );

  if (to) {
    return (
      <NavLink to={to} className={rowClass}>
        {body}
      </NavLink>
    );
  }
  if (onClick) {
    return (
      <button type="button" disabled={disabled || pending} onClick={onClick} className={rowClass}>
        {body}
      </button>
    );
  }
  return <div className={rowClass}>{body}</div>;
}

/** A settings section. Rows are separated by hairlines rather than spacing, so
 *  a long section stays one object instead of becoming a list of cards. */
export function SettingGroup({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children: React.ReactNode;
}) {
  return (
    <Card className="overflow-hidden">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm">{title}</CardTitle>
        {description && <CardDescription>{description}</CardDescription>}
      </CardHeader>
      <CardContent className="divide-y border-t p-0">{children}</CardContent>
    </Card>
  );
}
