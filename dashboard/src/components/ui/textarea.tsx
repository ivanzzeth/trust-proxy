import * as React from 'react';
import { cn } from '@/lib/utils';

const noRewrite = {
  autoCorrect: 'off',
  autoCapitalize: 'none',
  autoComplete: 'off',
  spellCheck: false,
  lang: 'zxx',
} as const;

export const Textarea = React.forwardRef<HTMLTextAreaElement, React.ComponentProps<'textarea'>>(
  ({ className, ...props }, ref) => (
    <textarea
      ref={ref}
      className={cn(
        'flex min-h-16 w-full rounded-md border bg-background/40 px-3 py-2 text-sm shadow-sm transition-colors',
        'placeholder:text-muted-foreground/70 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/60 focus-visible:border-ring',
        'disabled:cursor-not-allowed disabled:opacity-50',
        className,
      )}
      {...props}
      {...noRewrite}
    />
  ),
);
Textarea.displayName = 'Textarea';
