import { useEffect, useState } from 'react';

import { onNodeChange, trafficURL } from '@/lib/api';

/** Live uplink/downlink rates (bytes/sec) from Clash /traffic via SSE. */
export function useTrafficRate() {
  const [up, setUp] = useState(0);
  const [down, setDown] = useState(0);

  useEffect(() => {
    let es: EventSource | null = null;
    let cancelled = false;

    const connect = () => {
      es?.close();
      if (cancelled) return;
      es = new EventSource(trafficURL());
      es.onmessage = (ev) => {
        try {
          const t = JSON.parse(ev.data) as { up?: number; down?: number };
          setUp(Number(t.up) || 0);
          setDown(Number(t.down) || 0);
        } catch {
          /* ignore malformed */
        }
      };
      es.onerror = () => {
        // EventSource retries; zero the display while disconnected.
        setUp(0);
        setDown(0);
      };
    };

    connect();
    const unsub = onNodeChange(() => connect());
    return () => {
      cancelled = true;
      unsub();
      es?.close();
    };
  }, []);

  return { up, down };
}
