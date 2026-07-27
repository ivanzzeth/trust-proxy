import { describe, expect, it, vi, beforeEach } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

import { AppShell } from '@/components/app-shell';
import { api } from '@/lib/api';
import * as desktop from '@/lib/desktop';

// TUN needs a root gateway; the window must not be root. Inside the desktop app
// the console must therefore be able to *ask for* elevation, not just print
// instructions telling the user to go and find a terminal.
vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (k: string) => k }) }));
vi.mock('react-router-dom', () => ({
  NavLink: ({ children }: { children: React.ReactNode }) => <span>{children}</span>,
  Outlet: () => null,
}));

// The shell streams live traffic over SSE, which jsdom has no notion of. Stub it
// rather than mocking the hook: what is under test is the TUN dialog, and a fake
// hook would also hide a shell that crashed on mount.
class FakeEventSource {
  onmessage: ((e: MessageEvent) => void) | null = null;
  onerror: ((e: Event) => void) | null = null;
  close() {}
  addEventListener() {}
  removeEventListener() {}
}
(globalThis as unknown as { EventSource: unknown }).EventSource = FakeEventSource;

function renderShell() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <AppShell />
    </QueryClientProvider>,
  );
}

const status = (over: Record<string, unknown> = {}) => ({
  mode: 'manual', modes: ['manual', 'system', 'tun'], autoBlock: true,
  root: false, can_tun: false, os: 'darwin',
  threats: { domains: 0, ips: 0 }, ...over,
});

describe('TUN elevation from inside the desktop app', () => {
  beforeEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.spyOn(api, 'authState').mockResolvedValue({
      needs_bootstrap: false, allow_registration: false, authenticated: true,
      user: { id: 'u1', username: 'root', role: 'admin', has_proxy_cred: false, created_at: 'now' },
    });
  });

  it('offers to install the service instead of telling the user to open a terminal', async () => {
    vi.spyOn(api, 'status').mockResolvedValue(status());
    vi.spyOn(desktop, 'inDesktopApp').mockReturnValue(true);
    const install = vi.spyOn(desktop, 'installServiceViaApp').mockResolvedValue('{}');

    const user = userEvent.setup();
    renderShell();
    await user.click(await screen.findByRole('button', { name: /TUN/i }));
    // The dialog must lead with the action, not with shell commands.
    await waitFor(() => expect(screen.getByText('top.tunHelp.appTitle')).toBeTruthy());
    expect(screen.queryByText('top.tunHelp.mac')).toBeNull();

    await user.click(screen.getByRole('button', { name: /top.tunHelp.appAction/ }));
    // …and it must ask for TUN specifically: a service installed in manual mode
    // would leave the user exactly where they started.
    await waitFor(() => expect(install).toHaveBeenCalledWith('tun'));
  });

  it('falls back to instructions in a plain browser', async () => {
    vi.spyOn(api, 'status').mockResolvedValue(status());
    vi.spyOn(desktop, 'inDesktopApp').mockReturnValue(false);

    const user = userEvent.setup();
    renderShell();
    await user.click(await screen.findByRole('button', { name: /TUN/i }));
    await waitFor(() => expect(screen.getByText('top.tunHelp.mac')).toBeTruthy());
    expect(screen.queryByText('top.tunHelp.appTitle')).toBeNull();
  });

  it('does not interfere when the gateway can already do TUN', async () => {
    vi.spyOn(api, 'status').mockResolvedValue(status({ root: true, can_tun: true }));
    vi.spyOn(desktop, 'inDesktopApp').mockReturnValue(true);
    const setMode = vi.spyOn(api, 'setMode').mockResolvedValue({ mode: 'tun' } as never);

    const user = userEvent.setup();
    renderShell();
    await user.click(await screen.findByRole('button', { name: /TUN/i }));
    // A root gateway switches directly — no dialog, no elevation.
    await waitFor(() => expect(setMode).toHaveBeenCalled());
    expect(screen.queryByText('top.tunHelp.appTitle')).toBeNull();
  });
});
