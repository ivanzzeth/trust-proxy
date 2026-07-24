import { ChevronLeft, ChevronRight, Search } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { cn } from '@/lib/utils';

/** Compact search field for list toolbars. */
export function ListSearch({
  value,
  onChange,
  placeholder,
  className,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  className?: string;
}) {
  const { t } = useTranslation();
  return (
    <div className={cn('relative', className)}>
      <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
      <Input
        className="h-8 w-full min-w-[12rem] pl-8 sm:w-64"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder ?? t('common.searchPlaceholder')}
      />
    </div>
  );
}

/** Prev/next pager. Safe to keep mounted while a list is polled — page state lives in the parent. */
export function PaginationBar({
  page,
  totalPages,
  total,
  from,
  to,
  onPageChange,
  className,
}: {
  page: number;
  totalPages: number;
  total: number;
  from: number;
  to: number;
  onPageChange: (page: number) => void;
  className?: string;
}) {
  const { t } = useTranslation();
  if (total === 0) return null;
  return (
    <div className={cn('flex flex-wrap items-center justify-between gap-2 border-t px-3 py-2 text-xs text-muted-foreground', className)}>
      <span className="tnum">
        {t('common.paginationRange', { from, to, total })}
      </span>
      <div className="flex items-center gap-1">
        <Button
          type="button"
          variant="ghost"
          size="xs"
          disabled={page <= 0}
          onClick={() => onPageChange(page - 1)}
          aria-label={t('common.prevPage')}
        >
          <ChevronLeft className="size-3.5" />
        </Button>
        <span className="tnum min-w-[4.5rem] text-center">
          {t('common.paginationPage', { page: page + 1, pages: totalPages })}
        </span>
        <Button
          type="button"
          variant="ghost"
          size="xs"
          disabled={page >= totalPages - 1}
          onClick={() => onPageChange(page + 1)}
          aria-label={t('common.nextPage')}
        >
          <ChevronRight className="size-3.5" />
        </Button>
      </div>
    </div>
  );
}
