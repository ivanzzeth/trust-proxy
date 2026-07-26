import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

import Detection from '@/pages/detection';
import { api } from '@/lib/api';

// The console is the last layer in the chain and the one where a wire-shape
// change shows up as a blank panel rather than a compile error (tsc happily
// accepts `data?.sets ?? []` against an array). These render the page against a
// mocked API and assert it displays what the backend actually returns.
vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k: string) => k }),
}));

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <Detection />
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

    renderPage();
    await waitFor(() => {
      const values = screen.getAllByRole('spinbutton').map((i) => (i as HTMLInputElement).value);
      expect(values).toContain('9');
      expect(values).toContain('12');
      expect(values).toContain('7');
      expect(values).toContain('48');
    });
  });

  it('lists quarantined destinations with the reason the gateway recorded', async () => {
    vi.spyOn(api, 'detectionConfig').mockResolvedValue({
      beacon_enabled: true, dga_enabled: true, auto_block: true, require_warm_permit: true,
    });
    vi.spyOn(api, 'quarantine').mockResolvedValue([
      { value: 'evil.example', is_ip: false, reason: 'threat-intel auto-block', time: '2026-07-26T12:00:00Z' },
    ]);

    renderPage();
    await waitFor(() => {
      expect(screen.getByText('evil.example')).toBeDefined();
      expect(screen.getByText('threat-intel auto-block')).toBeDefined();
    });
  });
});
