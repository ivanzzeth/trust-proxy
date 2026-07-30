import { afterEach, describe, expect, it, vi, beforeEach } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';

import Detection from '@/pages/detection';
import { api } from '@/lib/api';

// The console is the last layer in the chain and the one where a wire-shape
// change shows up as a blank panel rather than a compile error (tsc happily
// accepts `data?.sets ?? []` against an array). These render the page against a
// mocked API and assert it displays what the backend actually returns.
//
// The thresholds used to be asserted here too. They are edited on Settings now,
// and their test moved with them — see settings.test.tsx.
vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k: string, opts?: Record<string, unknown>) => {
    if (opts && typeof opts === 'object') return `${k}:${JSON.stringify(opts)}`;
    return k;
  } }),
}));

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <Detection />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function mockObservation() {
  vi.spyOn(api, 'fingerprints').mockResolvedValue({ learning: false, fingerprints: [] });
  vi.spyOn(api, 'netcheck').mockResolvedValue({ supported: false });
  vi.spyOn(api, 'dnsQueryStats').mockResolvedValue({ total: 0, nxdomain: 0, odd_type: 0, tracked_windows: 0, top_parents: [] });
}

describe('Detection page', () => {
  beforeEach(() => vi.restoreAllMocks());
  // Without this the first test's tree is still mounted for the second, and
  // every getBy* silently becomes ambiguous.
  afterEach(cleanup);

  it('lists quarantined destinations with release and permit actions', async () => {
    mockObservation();
    vi.spyOn(api, 'quarantine').mockResolvedValue([
      {
        value: '47.108.206.242/32',
        is_ip: true,
        reason: 'large upload to non-whitelist destination (process=frpc, dest=47.108.206.242:7000)',
        time: '2026-07-29T17:12:47+08:00',
      },
    ]);

    renderPage();
    await waitFor(() => {
      expect(screen.getByText('47.108.206.242/32')).toBeDefined();
      expect(screen.getByText(/process=frpc/)).toBeDefined();
      expect(screen.getByText('pages.detection.permit')).toBeDefined();
      expect(screen.getByText('pages.detection.release')).toBeDefined();
    });
  });

  it('shows what the DNS-query observer counted, and no threshold editors', async () => {
    mockObservation();
    vi.spyOn(api, 'dnsQueryStats').mockResolvedValue({
      total: 4242,
      nxdomain: 40,
      odd_type: 3,
      tracked_windows: 2,
      top_parents: [],
    });
    vi.spyOn(api, 'quarantine').mockResolvedValue([]);

    renderPage();
    await waitFor(() => expect(screen.getByText('4242')).toBeDefined());
    // Tuning lives on Settings; this page offers the trip there and nothing to
    // type into. A stray number input here means a threshold card came back and
    // there are now two editors for one document.
    expect(screen.queryAllByRole('spinbutton')).toHaveLength(0);
    expect(screen.getByText('pages.detection.tuning')).toBeDefined();
  });
});
