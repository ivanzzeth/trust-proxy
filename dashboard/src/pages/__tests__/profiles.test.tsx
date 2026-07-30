import { describe, expect, it, vi, beforeEach } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

import Profiles from '@/pages/profiles';
import { api } from '@/lib/api';

// The page's failure mode was not a crash: with a fully configured policy and no
// saved snapshot it showed "no profiles yet", which reads as a broken page. So
// the invariant under test is "an empty list still tells you what you have and
// what saving would capture" — plus the two irreversible actions must confirm.
vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k: string, o?: Record<string, unknown>) => (o ? `${k} ${JSON.stringify(o)}` : k) }),
}));

function mockPolicy() {
  vi.spyOn(api, 'whitelist').mockResolvedValue({ domains: ['a.com', 'b.com', 'c.com'], ips: ['1.2.3.4'], processes: [], devices: [] });
  vi.spyOn(api, 'blacklist').mockResolvedValue({ domains: ['bad.com'], keywords: ['ads'], regexes: [], ips: [] });
  vi.spyOn(api, 'directlist').mockResolvedValue({ domains: ['cn.com'], ips: [], builtin: [] });
  vi.spyOn(api, 'customRules').mockResolvedValue([{ id: 'r1' }] as unknown as Awaited<ReturnType<typeof api.customRules>>);
  vi.spyOn(api, 'rulesets').mockResolvedValue([
    { tag: 'geosite-cn' }, { tag: 'geoip-cn' },
  ] as unknown as Awaited<ReturnType<typeof api.rulesets>>);
  vi.spyOn(api, 'proxyGroups').mockResolvedValue({ auto_country: true, exclude_countries: [], groups: [], failover: { interrupt_existing_connections: false } });
  vi.spyOn(api, 'dns').mockResolvedValue({ servers: [{ tag: 'doh' }, { tag: 'local' }] } as unknown as Awaited<ReturnType<typeof api.dns>>);
  vi.spyOn(api, 'status').mockResolvedValue({ mode: 'tun' } as unknown as Awaited<ReturnType<typeof api.status>>);
  vi.spyOn(api, 'posture').mockResolvedValue({ active: 'strict', seeded_split: false });
  vi.spyOn(api, 'subs').mockResolvedValue([
    { id: 's1', name: 'airport', url: 'https://x', node_count: 12, applied: true },
  ] as unknown as Awaited<ReturnType<typeof api.subs>>);
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <Profiles />
    </QueryClientProvider>,
  );
}

describe('Profiles page', () => {
  beforeEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('with no saved profiles, still shows the live policy and how to use the page', async () => {
    vi.spyOn(api, 'profiles').mockResolvedValue([]);
    mockPolicy();

    renderPage();
    // The current policy is rendered from the live stores, not from a profile.
    await waitFor(() => {
      expect(screen.getByText(/permitStat.*"domains":3.*"ips":1/)).toBeTruthy();
    });
    // Read each row by its label: several rows legitimately show the same number.
    const val = (label: string) => screen.getByText(label).nextElementSibling?.textContent;
    expect(val('pages.profiles.statDeny')).toBe('2'); // 1 domain + 1 keyword
    expect(val('pages.profiles.statDirectlist')).toBe('1');
    expect(val('pages.profiles.statCustomRules')).toBe('1');
    expect(val('pages.profiles.statRuleSets')).toBe('2');
    expect(val('pages.profiles.statDNS')).toBe('2');
    expect(val('pages.profiles.statMode')).toBe('tun');
    expect(val('pages.profiles.statPosture')).toBe('strict');
    expect(val('pages.profiles.statSub')).toBe('airport');
    // …and the empty list is replaced by the three-step explanation.
    expect(screen.getByText('pages.profiles.how1')).toBeTruthy();
    expect(screen.getByText('pages.profiles.how3')).toBeTruthy();
  });

  it('asks before overwriting a profile of the same name', async () => {
    vi.spyOn(api, 'profiles').mockResolvedValue([
      { id: 'p1', name: 'home', whitelist: { domains: [], ips: [], processes: [], devices: [] } },
    ] as unknown as Awaited<ReturnType<typeof api.profiles>>);
    mockPolicy();
    const add = vi.spyOn(api, 'addProfile').mockResolvedValue({ id: 'p1', name: 'home' } as unknown as Awaited<ReturnType<typeof api.addProfile>>);
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
    const user = userEvent.setup();

    renderPage();
    await user.type(await screen.findByPlaceholderText('pages.profiles.namePlaceholder'), 'home');
    await user.click(screen.getByRole('button', { name: /saveCurrent/ }));

    expect(confirm).toHaveBeenCalled();
    expect(add).not.toHaveBeenCalled(); // declined → nothing overwritten
  });

  it('warns that activating replaces the whole policy, and does nothing if declined', async () => {
    vi.spyOn(api, 'profiles').mockResolvedValue([
      { id: 'p1', name: 'office', whitelist: { domains: [], ips: [], processes: [], devices: [] } },
    ] as unknown as Awaited<ReturnType<typeof api.profiles>>);
    mockPolicy();
    const act = vi.spyOn(api, 'activateProfile').mockResolvedValue({ id: 'p1', name: 'office' } as unknown as Awaited<ReturnType<typeof api.activateProfile>>);
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
    const user = userEvent.setup();

    renderPage();
    await user.click(await screen.findByRole('button', { name: /profiles.activate/ }));

    expect(confirm).toHaveBeenCalled();
    // No profile is active, so the prompt must say the live policy is unsaved.
    expect(String(confirm.mock.calls[0][0])).toContain('activateNoBackup');
    expect(act).not.toHaveBeenCalled();
  });
});
