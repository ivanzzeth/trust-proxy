import { DelayMapping, ProxiesMapping } from '~/store/types';

export const PROXY_SORT_OPTIONS = [
  ['Natural', 'order_natural'],
  ['LatencyAsc', 'order_latency_asc'],
  ['LatencyDesc', 'order_latency_desc'],
  ['NameAsc', 'order_name_asc'],
  ['NameDesc', 'order_name_desc'],
] as const;

export function formatQty(qty: number) {
  return qty < 100 ? String(qty) : '99+';
}

export function splitItemsByLayout<T>(items: T[], layout: string) {
  if (layout !== 'double') {
    return [items];
  }

  const left: T[] = [];
  const right: T[] = [];
  items.forEach((item, index) => {
    if (index % 2 === 0) {
      left.push(item);
    } else {
      right.push(item);
    }
  });

  return [left, right];
}

export function getProxyLatency(
  proxies: ProxiesMapping,
  delay: DelayMapping,
  name: string,
  visited = new Set<string>()
) {
  if (visited.has(name)) return undefined;
  visited.add(name);

  const latency = delay[name];
  if (latency && (latency.testing || typeof latency.number === 'number' || latency.error)) {
    return latency;
  }

  const proxy = proxies[name];
  if (proxy && proxy.now && proxies[proxy.now]) {
    return getProxyLatency(proxies, delay, proxy.now, visited);
  }

  const delayFromHistory = proxy?.history?.[proxy.history.length - 1]?.delay;
  if (typeof delayFromHistory === 'number' && delayFromHistory > 0) {
    return { number: delayFromHistory };
  }

  return latency;
}
