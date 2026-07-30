import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';

import Rules from '@/pages/rules';
import Settings from '@/pages/settings';
import { api, Defaults } from '@/lib/api';

// Final egress and open registration each have two legitimate homes. The first
// draft gave each home its own implementation, and Settings' copy offered only
// `proxy` and `direct` while the Rules page offered `proxy`, `direct` and
// `blocked` — a third of the setting was unreachable from one of its homes and
// nothing failed. This asserts the thing that fixes it: both mounts are the
// same component, so they cannot disagree about what the setting can be.

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (k: string, opts?: Record<string, unknown>) => (opts ? `${k}:${JSON.stringify(opts)}` : k),
    i18n: { resolvedLanguage: 'en', changeLanguage: vi.fn() },
  }),
  initReactI18next: { type: '3rdParty', init: () => {} },
}));

vi.mock('@/components/switchers', () => ({
  ModeSwitcher: () => <div />,
  RoutingSwitcher: () => <div />,
  PostureSwitcher: () => <div />,
  AutoBlock: () => <div />,
}));

// Radix's Select drives itself with Pointer Events, which jsdom does not
// implement. These three stubs are the whole gap.
beforeAll(() => {
  Element.prototype.hasPointerCapture = () => false;
  Element.prototype.setPointerCapture = () => {};
  Element.prototype.releasePointerCapture = () => {};
  Element.prototype.scrollIntoView = () => {};
});

function mockApi() {
  vi.spyOn(api, 'final').mockResolvedValue({ outbound: 'proxy' });
  vi.spyOn(api, 'effectiveRules').mockResolvedValue([]);
  vi.spyOn(api, 'authSettings').mockResolvedValue({ allow_registration: false });
  vi.spyOn(api, 'defaults').mockResolvedValue({ tun: {}, retention: { log: {}, history: {} }, inbound: {}, detection: {} } as unknown as Defaults);
  vi.spyOn(api, 'status').mockResolvedValue({} as unknown as Awaited<ReturnType<typeof api.status>>);
  vi.spyOn(api, 'inbound').mockResolvedValue({ listen: {}, resolved: { listen: '127.0.0.1', port: 21584 } });
  vi.spyOn(api, 'retention').mockResolvedValue({ log: {}, history: {} });
  vi.spyOn(api, 'dns').mockResolvedValue({} as unknown as Awaited<ReturnType<typeof api.dns>>);
  vi.spyOn(api, 'tun').mockResolvedValue({ stack: 'gvisor', mtu: 9000, strict_route: true });
  vi.spyOn(api, 'detectionConfig').mockResolvedValue({
    beacon_enabled: true,
    dga_enabled: true,
    dns_bypass_detect: true,
    ja4_enabled: true,
    auto_block: false,
    require_warm_permit: true,
  });
}

function renderPage(el: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{el}</MemoryRouter>
    </QueryClientProvider>,
  );
}

/** Open the Final select on the page under test and read back what it offers. */
async function finalOptions(el: React.ReactElement): Promise<string[]> {
  const user = userEvent.setup();
  renderPage(el);
  // Settings has other selects (language, theme); find the Final one by the
  // value it is showing rather than by position.
  await screen.findByText('pages.rules.final.proxy');
  const trigger = screen
    .getAllByRole('combobox')
    .find((c) => c.textContent?.startsWith('pages.rules.final.'));
  await user.click(trigger!);
  const list = await screen.findByRole('listbox');
  return within(list)
    .getAllByRole('option')
    .map((o) => o.textContent ?? '');
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('settings with two homes', () => {
  it('offers the same Final outbounds on Settings and on the routing view', async () => {
    mockApi();
    const onRules = await finalOptions(<Rules />);
    cleanup();
    mockApi();
    const onSettings = await finalOptions(<Settings />);

    expect(onSettings).toEqual(onRules);
    // And `blocked` is in there: the option the duplicated copy had dropped is
    // also the one that shuts the gateway's default-deny catch-all, so losing
    // it from a home is losing the safest setting from that home.
    expect(onRules).toContain('pages.rules.final.blocked');
  });
});
