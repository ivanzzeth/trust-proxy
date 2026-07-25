import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function fmtBytes(n: number): string {
  if (!n) return '0 B';
  if (n < 1024) return `${n} B`;
  const u = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(1)} ${u[i]}`;
}

/** Format a byte-rate (bytes per second). */
export function fmtRate(n: number): string {
  return `${fmtBytes(Math.max(0, Math.round(n)))}/s`;
}

/** Format a connection duration (ms) for the history/connections tables. */
export function fmtDuration(ms: number): string {
  if (!ms || ms < 0) return '—';
  if (ms < 1000) return `${ms}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)}s`;
  const m = Math.floor(s / 60);
  const rem = Math.round(s % 60);
  return `${m}m${rem}s`;
}

/**
 * Format the DNS/connect/TLS phase breakdown for a connection's duration
 * tooltip. Returns null when no breakdown is available at all (e.g. UDP),
 * so callers can fall back to a plain duration-only tooltip.
 */
export function fmtLatencyBreakdown(
  totalMs: number,
  dnsMs?: number,
  connectMs?: number,
  tlsMs?: number,
): string | null {
  if (!dnsMs && !connectMs && !tlsMs) return null;
  const parts: string[] = [];
  if (dnsMs) parts.push(`DNS ${fmtDuration(dnsMs)}`);
  if (connectMs) parts.push(`Connect ${fmtDuration(connectMs)}`);
  if (tlsMs) parts.push(`TLS ${fmtDuration(tlsMs)}`);
  const known = (dnsMs ?? 0) + (connectMs ?? 0) + (tlsMs ?? 0);
  const rest = totalMs - known;
  if (rest > 0) parts.push(`Data/wait ${fmtDuration(rest)}`);
  return parts.join(' · ');
}
