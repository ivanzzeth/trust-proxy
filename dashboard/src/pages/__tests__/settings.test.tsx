import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';

import Settings from '@/pages/settings';
import { api, Defaults } from '@/lib/api';

// Two claims this page makes, both of which have failed before elsewhere in
// this codebase:
//
//   1. Defaults come from the gateway. "Restore defaults" must fill the form
//      from GET /api/defaults, not from a number typed in TypeScript — a second
//      copy of a default is a second source of truth and it drifts silently.
//   2. Moving the inbound listener is guarded. A pending revert has to be
//      visible with a way to confirm; a countdown nobody can see is the same as
//      no countdown, and the cost of missing it is losing access to the box.

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (k: string, opts?: Record<string, unknown>) => (opts ? `${k}:${JSON.stringify(opts)}` : k),
    i18n: { resolvedLanguage: 'en', changeLanguage: vi.fn() },
  }),
  // The page imports LANGS from '@/i18n', which runs the real init on import.
  initReactI18next: { type: '3rdParty', init: () => {} },
}));

// The four policy switchers are the header's components; they poll their own
// endpoints and are covered by the shell's tests. Stub them so a failure here
// is unambiguously about this page.
vi.mock('@/components/switchers', () => ({
  ModeSwitcher: () => <div data-testid="mode" />,
  RoutingSwitcher: () => <div data-testid="routing" />,
  PostureSwitcher: () => <div data-testid="posture" />,
  AutoBlock: () => <div data-testid="autoblock" />,
}));

const DEFAULTS = {
  tun: { stack: 'gvisor', mtu: 9000, strict_route: true, auto_redirect: true },
  dns: {},
  detection: {},
  retention: {
    // Deliberately not the real built-in numbers (32/3, 64/5): if the page
    // ever grows its own copy of a default, matching these by accident is what
    // would let the copy pass unnoticed.
    log: { max_size_mb: 777, max_backups: 7, max_age_days: 0, compress: true },
    history: { max_size_mb: 888, max_backups: 8, max_age_days: 0, compress: true },
  },
  inbound: { listen: '127.0.0.1', port: 21584 },
  failover: {},
  scoring: {},
} as unknown as Defaults;

function mockApi(over: Partial<Record<keyof typeof api, unknown>> = {}) {
  vi.spyOn(api, 'defaults').mockResolvedValue(DEFAULTS);
  vi.spyOn(api, 'status').mockResolvedValue({
    root: true,
    privileged: true,
    version: 'v1.2.3',
    data_dir: '/var/lib/trust-proxy',
  } as unknown as Awaited<ReturnType<typeof api.status>>);
  vi.spyOn(api, 'inbound').mockResolvedValue({
    listen: {},
    resolved: { listen: '127.0.0.1', port: 21584 },
    ...(over.inbound as object),
  });
  // Distinct numbers everywhere so an assertion names exactly one field.
  vi.spyOn(api, 'retention').mockResolvedValue({
    log: { max_size_mb: 11, max_backups: 12, max_age_days: 13, compress: false },
    history: { max_size_mb: 21, max_backups: 22, max_age_days: 23, compress: false },
  });
  vi.spyOn(api, 'dns').mockResolvedValue({} as unknown as Awaited<ReturnType<typeof api.dns>>);
  vi.spyOn(api, 'final').mockResolvedValue({ outbound: 'proxy' });
  vi.spyOn(api, 'authSettings').mockResolvedValue({ allow_registration: false });
  vi.spyOn(api, 'tun').mockResolvedValue({ stack: 'system', mtu: 1400, strict_route: false, auto_redirect: false });
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <Settings />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('Settings', () => {
  it('restores defaults from the gateway, not from hard-coded numbers', async () => {
    mockApi();
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByText('pages.settings.retention'));
    const dialog = await screen.findByRole('dialog');
    // Current values, straight from GET /api/retention.
    expect(within(dialog).getByDisplayValue('11')).toBeTruthy();
    expect(within(dialog).getByDisplayValue('21')).toBeTruthy();

    await user.click(within(dialog).getByText('pages.settings.restoreDefaults'));

    // 777/888 came from GET /api/defaults and nowhere else.
    await waitFor(() => {
      expect(within(dialog).getByDisplayValue('777')).toBeTruthy();
      expect(within(dialog).getByDisplayValue('888')).toBeTruthy();
    });
  });

  it('surfaces a pending inbound revert with a way to keep the new address', async () => {
    mockApi({ inbound: { revert: { to: { listen: '127.0.0.1', port: 21584 }, in_seconds: 42 } } });
    const confirm = vi.spyOn(api, 'confirmInbound').mockResolvedValue({
      listen: {},
      resolved: { listen: '127.0.0.1', port: 9999 },
    });
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByText('pages.settings.inbound'));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText(/pages\.settings\.inboundRevert/)).toBeTruthy();

    await user.click(within(dialog).getByText('pages.settings.inboundKeep'));
    await waitFor(() => expect(confirm).toHaveBeenCalled());
  });

  it('shows the build and data directory an admin gets from /api/status', async () => {
    mockApi();
    renderPage();
    expect(await screen.findByText('v1.2.3')).toBeTruthy();
    expect(await screen.findByText('/var/lib/trust-proxy')).toBeTruthy();
  });
});
