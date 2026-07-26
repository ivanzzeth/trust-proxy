import { describe, expect, it, vi, beforeEach } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

import { ExitGenerator } from '@/components/exit-generator';
import { api } from '@/lib/api';

// The generator's whole reason to exist is that the two halves of an exit must
// come from one generation. These assert the flow a user actually walks: open,
// generate, get a runnable script, add the client node — and that the node the
// importer receives is the generated dict, not something rebuilt in the UI.
// userEvent (not fireEvent) so clicks carry the pointer sequence Radix listens for.
vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (k: string) => k }),
}));

function renderGen() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <ExitGenerator />
    </QueryClientProvider>,
  );
}

const RESULT = {
  server: { inbounds: [{ type: 'shadowsocks', password: 'k$ey`' }] },
  client: { name: 'tokyo', type: 'shadowsocks', server: '203.0.113.9', port: 8388, password: 'k$ey`' },
  share: 'ss://abc#tokyo',
  gen_command: 'trust-proxy proxy gen --type shadowsocks --server 203.0.113.9 --port 8388',
  install_script: "cat > server.json <<'TRUST_PROXY_EOF'\n{}\nTRUST_PROXY_EOF\ntrust-proxy proxy run -c server.json -d",
};

describe('Self-hosted exit generator', () => {
  // globals:false means RTL's auto-cleanup afterEach is never registered, so a
  // second render would otherwise find two dialogs.
  beforeEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('generates from the form and shows the deploy script', async () => {
    vi.spyOn(api, 'proxyProtocols').mockResolvedValue(['shadowsocks', 'vless-reality']);
    const gen = vi.spyOn(api, 'proxyGen').mockResolvedValue(RESULT);
    const user = userEvent.setup();

    renderGen();
    await user.click(screen.getByRole('button', { name: /exitGen.trigger/ }));

    // Generate stays disabled until there is an address to dial: a node pointing
    // at a placeholder is worse than no node.
    const button = await screen.findByRole('button', { name: /exitGen.generate/ });
    expect(button.hasAttribute('disabled')).toBe(true);

    await user.type(screen.getByPlaceholderText('pages.exitGen.serverPh'), '203.0.113.9');
    await user.click(screen.getByRole('button', { name: /exitGen.generate/ }));

    await waitFor(() => expect(gen).toHaveBeenCalled());
    expect(gen.mock.calls[0][0]).toMatchObject({ server: '203.0.113.9', port: 443 });
    await waitFor(() => expect(screen.getByText(/proxy run -c server.json -d/)).toBeTruthy());
  });

  it('imports the generated client node verbatim', async () => {
    vi.spyOn(api, 'proxyProtocols').mockResolvedValue(['shadowsocks']);
    vi.spyOn(api, 'proxyGen').mockResolvedValue(RESULT);
    const imp = vi.spyOn(api, 'importNodes').mockResolvedValue({
      id: 's1', name: 'tokyo', url: '', node_count: 1, applied: false,
    } as unknown as Awaited<ReturnType<typeof api.importNodes>>);
    const user = userEvent.setup();

    renderGen();
    await user.click(screen.getByRole('button', { name: /exitGen.trigger/ }));
    await user.type(await screen.findByPlaceholderText('pages.exitGen.serverPh'), '203.0.113.9');
    await user.click(screen.getByRole('button', { name: /exitGen.generate/ }));
    await user.click(await screen.findByRole('button', { name: /exitGen.addNode/ }));

    await waitFor(() => expect(imp).toHaveBeenCalled());
    const [name, content] = imp.mock.calls[0];
    expect(name).toBe('tokyo');
    // Byte-for-byte the generated dict: a password mangled here means a node that
    // cannot dial the server that was just deployed.
    expect(JSON.parse(content)).toEqual(RESULT.client);
  });
});
