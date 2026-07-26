import { describe, expect, it, vi, beforeEach } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

import { AuthGate } from '@/components/auth-gate';
import { api } from '@/lib/api';

// The gate decides what a visitor sees before anything else renders, and it must
// take that decision from the backend rather than guess: an unclaimed gateway has
// to offer "create the first admin", a claimed one "sign in", and neither may leak
// the app behind it.
vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k: string) => k }),
}));

function renderGate() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <AuthGate>
        <div>THE APP</div>
      </AuthGate>
    </QueryClientProvider>,
  );
}

describe('AuthGate', () => {
  beforeEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('offers to create the first admin on an unclaimed gateway', async () => {
    vi.spyOn(api, 'authState').mockResolvedValue({
      needs_bootstrap: true, allow_registration: false, authenticated: false,
    });
    renderGate();
    await waitFor(() => expect(screen.getByText('auth.bootstrapTitle')).toBeTruthy());
    expect(screen.queryByText('THE APP')).toBeNull();
  });

  // Off-loopback bootstrap needs the one-time code. Without this field the console
  // on a cloud gateway — the normal remote case — shows a form that can only 403.
  it('asks for the claim code only when the gateway is not local, and sends it', async () => {
    vi.spyOn(api, 'authState').mockResolvedValue({
      needs_bootstrap: true, allow_registration: false, authenticated: false, needs_bootstrap_code: true,
    });
    const boot = vi.spyOn(api, 'bootstrap').mockResolvedValue({
      user: { id: 'u1', username: 'root', role: 'admin', has_proxy_cred: false, created_at: 'now' },
    });
    const user = userEvent.setup();
    renderGate();
    await user.type(await screen.findByLabelText('auth.username'), 'root');
    await user.type(screen.getByLabelText('auth.password'), 'gateway-admin-pw');
    // Until the code is filled in, submitting is pointless — so it is not offered.
    expect(screen.getByRole('button', { name: /auth.createAdmin/ }).hasAttribute('disabled')).toBe(true);
    await user.type(screen.getByLabelText('auth.bootstrapCode'), 'ONE-TIME-CODE');
    await user.click(screen.getByRole('button', { name: /auth.createAdmin/ }));
    await waitFor(() => expect(boot).toHaveBeenCalledWith('root', 'gateway-admin-pw', 'ONE-TIME-CODE'));
  });

  it('does not ask for a claim code on the gateway machine itself', async () => {
    vi.spyOn(api, 'authState').mockResolvedValue({
      needs_bootstrap: true, allow_registration: false, authenticated: false,
    });
    renderGate();
    await waitFor(() => expect(screen.getByText('auth.bootstrapTitle')).toBeTruthy());
    expect(screen.queryByLabelText('auth.bootstrapCode')).toBeNull();
  });

  it('asks for a login on a claimed gateway, and hides registration unless it is open', async () => {
    vi.spyOn(api, 'authState').mockResolvedValue({
      needs_bootstrap: false, allow_registration: false, authenticated: false,
    });
    renderGate();
    await waitFor(() => expect(screen.getByText('auth.loginTitle')).toBeTruthy());
    expect(screen.queryByText('auth.noAccount')).toBeNull();
    expect(screen.queryByText('THE APP')).toBeNull();
  });

  it('offers registration when an admin opened it', async () => {
    vi.spyOn(api, 'authState').mockResolvedValue({
      needs_bootstrap: false, allow_registration: true, authenticated: false,
    });
    renderGate();
    await waitFor(() => expect(screen.getByText('auth.noAccount')).toBeTruthy());
  });

  it('renders the app once authenticated', async () => {
    vi.spyOn(api, 'authState').mockResolvedValue({
      needs_bootstrap: false, allow_registration: false, authenticated: true,
      user: { id: 'u1', username: 'alice', role: 'admin', has_proxy_cred: false, created_at: 'now' },
    });
    renderGate();
    await waitFor(() => expect(screen.getByText('THE APP')).toBeTruthy());
  });

  it('logs in with what was typed', async () => {
    vi.spyOn(api, 'authState').mockResolvedValue({
      needs_bootstrap: false, allow_registration: false, authenticated: false,
    });
    const login = vi.spyOn(api, 'login').mockResolvedValue({
      user: { id: 'u1', username: 'alice', role: 'admin', has_proxy_cred: false, created_at: 'now' },
    });
    const user = userEvent.setup();
    renderGate();
    await user.type(await screen.findByLabelText('auth.username'), 'alice');
    await user.type(screen.getByLabelText('auth.password'), 'a-long-password');
    await user.click(screen.getByRole('button', { name: /auth.login/ }));
    await waitFor(() => expect(login).toHaveBeenCalledWith('alice', 'a-long-password'));
  });

  // A 401 from any other call means the session is gone. Without this the app just
  // renders errors over an empty layout and the user has no way back to a login.
  it('re-checks the session when something reports a 401', async () => {
    const state = vi.spyOn(api, 'authState').mockResolvedValue({
      needs_bootstrap: false, allow_registration: false, authenticated: true,
      user: { id: 'u1', username: 'alice', role: 'admin', has_proxy_cred: false, created_at: 'now' },
    });
    renderGate();
    await waitFor(() => expect(screen.getByText('THE APP')).toBeTruthy());
    const before = state.mock.calls.length;
    state.mockResolvedValue({ needs_bootstrap: false, allow_registration: false, authenticated: false });
    window.dispatchEvent(new Event('tp-unauthorized'));
    await waitFor(() => expect(state.mock.calls.length).toBeGreaterThan(before));
    await waitFor(() => expect(screen.getByText('auth.loginTitle')).toBeTruthy());
  });
});
