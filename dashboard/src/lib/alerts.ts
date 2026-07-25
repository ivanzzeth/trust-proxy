import type { DetectionKind } from '@/lib/api';

/** Deep-link into Connections → Alerts (optional kind chip). */
export function alertsHref(kind?: DetectionKind) {
  const q = new URLSearchParams({ tab: 'alerts' });
  if (kind) q.set('kind', kind);
  return `/connections?${q.toString()}`;
}
