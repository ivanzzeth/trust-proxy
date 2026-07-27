import { describe, expect, it, vi, beforeEach } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

import { AppShell } from '@/components/app-shell';
import { api } from '@/lib/api';

// A narrow window used to cost you the branding. The header laid its controls
// out with `justify-end` and no wrapping, so once they no longer fitted they
// overflowed out of the *start* of the row — across the sidebar, over the logo.
//
// jsdom cannot measure that, and a test asserting Tailwind class names would
// only restate the implementation. What it can hold is the structure the fix
// rests on: the navigation is reachable without the sidebar, the brand is
// rendered somewhere that survives the sidebar collapsing, and the drawer that
// replaces the sidebar can be closed again.

vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (k: string) => k }) }));

let pathname = '/';
vi.mock('react-router-dom', () => ({
  NavLink: ({ children, onClick }: { children: React.ReactNode; onClick?: () => void }) => (
    // The real NavLink takes a render-prop child; the shell uses that form.
    <a onClick={onClick}>{typeof children === 'function' ? (children as (s: { isActive: boolean }) => React.ReactNode)({ isActive: false }) : children}</a>
  ),
  Outlet: () => null,
  useLocation: () => ({ pathname }),
}));

class FakeEventSource {
  onmessage: ((e: MessageEvent) => void) | null = null;
  onerror: ((e: Event) => void) | null = null;
  close() {}
  addEventListener() {}
  removeEventListener() {}
}
(globalThis as unknown as { EventSource: unknown }).EventSource = FakeEventSource;

// jsdom has no matchMedia; the shell uses it to drop the drawer when the window
// widens back past the breakpoint.
if (!window.matchMedia) {
  window.matchMedia = ((q: string) => ({
    matches: false,
    media: q,
    addEventListener() {},
    removeEventListener() {},
  })) as unknown as typeof window.matchMedia;
}

function renderShell() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <AppShell />
    </QueryClientProvider>,
  );
}

describe('the shell at a narrow width', () => {
  beforeEach(() => {
    cleanup();
    pathname = '/';
    vi.restoreAllMocks();
    vi.spyOn(api, 'authState').mockResolvedValue({
      needs_bootstrap: false, allow_registration: false, authenticated: true,
      user: { id: 'u1', username: 'root', role: 'admin', has_proxy_cred: false, created_at: 'now' },
    });
    vi.spyOn(api, 'status').mockResolvedValue({
      mode: 'manual', modes: ['manual', 'system', 'tun'], autoBlock: true,
      root: true, can_tun: true, os: 'darwin', threats: { domains: 0, ips: 0 },
    });
  });

  // The brand is rendered twice on purpose — once in the sidebar, once in the
  // header — and CSS picks which one is visible. One copy would mean that at
  // exactly the width where the sidebar goes away, so does the logo.
  it('keeps the brand on screen when the sidebar is not there', async () => {
    renderShell();
    await waitFor(() => expect(screen.getAllByText('Trust Proxy').length).toBe(2));
  });

  // Hiding the sidebar is only safe if the navigation survives it.
  it('reaches every nav item through the drawer', async () => {
    const user = userEvent.setup();
    renderShell();
    const open = await screen.findByRole('button', { name: 'nav.open' });
    const before = screen.getAllByText('nav.overview').length;
    await user.click(open);
    await waitFor(() => expect(screen.getAllByText('nav.overview').length).toBe(before + 1));
    expect(screen.getByRole('button', { name: 'nav.close' })).toBeTruthy();
  });

  // A drawer that cannot be dismissed is worse than no drawer: it covers the
  // page it was opened from.
  it('closes on the close button and on choosing a destination', async () => {
    const user = userEvent.setup();
    renderShell();
    const open = await screen.findByRole('button', { name: 'nav.open' });

    await user.click(open);
    await user.click(screen.getByRole('button', { name: 'nav.close' }));
    await waitFor(() => expect(screen.queryByRole('button', { name: 'nav.close' })).toBeNull());

    // And picking a page closes it too — otherwise the destination is hidden
    // behind the thing used to get there.
    await user.click(open);
    const links = await screen.findAllByText('nav.connections');
    await user.click(links[links.length - 1]);
    await waitFor(() => expect(screen.queryByRole('button', { name: 'nav.close' })).toBeNull());
  });
});
