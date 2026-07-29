import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';

import Detection from '@/pages/detection';
import { api } from '@/lib/api';

// The console is the last layer in the chain and the one where a wire-shape
// change shows up as a blank panel rather than a compile error (tsc happily
// accepts `data?.sets ?? []` against an array). These render the page against a
// mocked API and assert it displays what the backend actually returns.
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

describe('Detection page', () => {
  beforeEach(() => vi.restoreAllMocks());

  it('shows the thresholds the backend reports, not hardcoded defaults', async () => {
    vi.spyOn(api, 'detectionConfig').mockResolvedValue({
      beacon_enabled: true,
      beacon_min_sample: 9,
      beacon_realert_factor: 12,
      dga_enabled: true,
      exfil_upload_bytes: 20971520,
      exfil_min_ratio: 7,
      exfil_new_dest_hours: 48,
      auto_block: true,
      require_warm_permit: true,
    });
    vi.spyOn(api, 'quarantine').mockResolvedValue([]);
    vi.spyOn(api, 'fingerprints').mockResolvedValue({ learning: false, fingerprints: [] });
    vi.spyOn(api, 'netcheck').mockResolvedValue({ supported: false });
    vi.spyOn(api, 'dnsQueryStats').mockResolvedValue({ total: 0, nxdomain: 0, odd_type: 0, tracked_windows: 0, top_parents: [] });

    renderPage();
    await waitFor(() => {
      const values = screen.getAllByRole('spinbutton').map((i) => (i as HTMLInputElement).value);
      expect(values).toContain('9');
      expect(values).toContain('12');
      expect(values).toContain('7');
      expect(values).toContain('48');
    });
  });

  it('lists quarantined destinations with release and permit actions', async () => {
    vi.spyOn(api, 'detectionConfig').mockResolvedValue({
      beacon_enabled: true, dga_enabled: true, auto_block: true, require_warm_permit: true,
    });
    vi.spyOn(api, 'quarantine').mockResolvedValue([
      {
        value: '47.108.206.242/32',
        is_ip: true,
        reason: 'large upload to non-whitelist destination (process=frpc, dest=47.108.206.242:7000)',
        time: '2026-07-29T17:12:47+08:00',
      },
    ]);
    vi.spyOn(api, 'fingerprints').mockResolvedValue({ learning: false, fingerprints: [] });
    vi.spyOn(api, 'netcheck').mockResolvedValue({ supported: false });
    vi.spyOn(api, 'dnsQueryStats').mockResolvedValue({ total: 0, nxdomain: 0, odd_type: 0, tracked_windows: 0, top_parents: [] });

    renderPage();
    await waitFor(() => {
      expect(screen.getByText('47.108.206.242/32')).toBeDefined();
      expect(screen.getByText(/process=frpc/)).toBeDefined();
      expect(screen.getByText('pages.detection.permit')).toBeDefined();
      expect(screen.getByText('pages.detection.release')).toBeDefined();
    });
  });
});
