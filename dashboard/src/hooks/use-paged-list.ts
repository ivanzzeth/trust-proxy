import { useEffect, useMemo, useState } from 'react';

export const DEFAULT_PAGE_SIZE = 50;

/** Client-side page slice. Keeps the current page across poll refreshes; clamps
 *  when the filtered set shrinks; resets to 0 when `resetKey` changes (search/tab). */
export function usePagedList<T>(items: T[], resetKey: string, pageSize = DEFAULT_PAGE_SIZE) {
  const [page, setPage] = useState(0);
  useEffect(() => {
    setPage(0);
  }, [resetKey]);

  const total = items.length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize) || 1);
  const safePage = Math.min(Math.max(0, page), totalPages - 1);

  useEffect(() => {
    if (safePage !== page) setPage(safePage);
  }, [safePage, page]);

  const pageItems = useMemo(
    () => items.slice(safePage * pageSize, safePage * pageSize + pageSize),
    [items, safePage, pageSize],
  );

  return {
    page: safePage,
    setPage,
    pageSize,
    total,
    totalPages,
    pageItems,
    from: total === 0 ? 0 : safePage * pageSize + 1,
    to: Math.min(total, (safePage + 1) * pageSize),
  };
}

/** Case-insensitive substring match across string fields. */
export function matchesQuery(q: string, ...fields: Array<string | number | undefined | null>): boolean {
  const needle = q.trim().toLowerCase();
  if (!needle) return true;
  return fields.some((f) => f != null && String(f).toLowerCase().includes(needle));
}
