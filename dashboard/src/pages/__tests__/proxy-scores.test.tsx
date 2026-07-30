import { describe, expect, it, vi, afterEach, beforeEach } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';

import Proxies from '@/pages/proxies';
import { api, ProxyScore } from '@/lib/api';

// Scoring is only worth having if a user can see why a node was picked. These
// assert the two claims the page makes: a warming node must not read as a
// measured 100, and a demoted node must be labelled as demoted rather than
// hidden — the data plane still uses it as a last resort, so a console that
// dropped it would be describing a different gateway.
vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (k: string, opts?: Record<string, unknown>) => {
      if (opts && typeof opts === 'object') return `${k}:${JSON.stringify(opts)}`;
      return k;
    },
  }),
}));

function score(p: Partial<ProxyScore> & { tag: string }): ProxyScore {
  return {
    score: 100,
    reliability: 100,
    latency_score: 100,
    throughput_score: 50,
    samples: 0,
    min_samples: 10,
    warming: false,
    ok_streak: 0,
    fail_streak: 0,
    breaker: 'closed',
    preferred: true,
    last_ok: true,
    ...p,
  };
}

function mockPage(scores: ProxyScore[], enabled = true) {
  vi.spyOn(api, 'proxies').mockResolvedValue({
    proxies: {
      Auto: { type: 'URLTest', now: scores[0]?.tag ?? '', all: scores.map((s) => s.tag), history: [] },
    },
  } as unknown as Awaited<ReturnType<typeof api.proxies>>);
  vi.spyOn(api, 'proxyGroups').mockResolvedValue({
    auto_country: true,
    exclude_countries: [],
    groups: [],
    failover: { interrupt_existing_connections: false },
    scoring: {},
  });
  vi.spyOn(api, 'proxyScores').mockResolvedValue({
    scores,
    config: { min_samples: 10, weight_reliability: 50, weight_latency: 30, weight_throughput: 20 },
    formula: 'score = (50×reliability + 30×latency + 20×throughput) / 100',
    enabled,
  });
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <Proxies />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('Proxies page scoring', () => {
  beforeEach(() => vi.restoreAllMocks());
  // globals:false means no auto-cleanup, so a previous render stays in the DOM
  // and every queryBy* below would match the wrong page.
  afterEach(() => cleanup());

  it('shows warm-up progress instead of a bare 100', async () => {
    mockPage([score({ tag: 'fresh-node', warming: true, samples: 4 })]);
    renderPage();
    // "100" alone would read as "measured and excellent"; it means the opposite.
    await waitFor(() => expect(screen.getAllByText('100 · 4/10').length).toBeGreaterThan(0));
    expect(screen.queryByText('100')).toBeNull();
  });

  it('renders the formula the backend sent rather than re-deriving it', async () => {
    mockPage([score({ tag: 'n1', score: 82, samples: 30 })]);
    renderPage();
    await waitFor(() =>
      expect(screen.getAllByText('score = (50×reliability + 30×latency + 20×throughput) / 100').length).toBeGreaterThan(0),
    );
  });

  it('labels a demoted node instead of dropping it', async () => {
    mockPage([
      score({ tag: 'good', score: 90, samples: 30 }),
      score({ tag: 'tripped', score: 20, samples: 30, preferred: false, breaker: 'open', breaker_remaining_seconds: 12, fail_streak: 6 }),
    ]);
    renderPage();
    const user = userEvent.setup();
    await waitFor(() => expect(screen.getAllByText('tripped').length).toBeGreaterThan(0));
    await user.click(screen.getByText('pages.proxies.score.table'));
    await waitFor(() => {
      // The row must be there AND say why — not merely the standing note under
      // the table, which is what a looser matcher would have accepted.
      const row = screen.getAllByText('tripped').map((el) => el.closest('tr')).find(Boolean);
      expect(row).toBeTruthy();
      expect(row!.textContent).toContain('pages.proxies.score.demoted · 12s');
    });
  });

  // The user's report: subscriptions ship nodes that dial fine and relay
  // nothing, and traffic piles onto them. A bare "0" in the table reads as
  // "very slow", and slow is worth keeping — so the row has to name the shape.
  it('names a blackhole rather than showing it as a very low score', async () => {
    mockPage([
      score({ tag: 'good', score: 90, samples: 30 }),
      score({
        tag: 'fake-node',
        score: 0,
        samples: 2,
        warming: true,
        preferred: false,
        breaker: 'open',
        blackhole: true,
        blackhole_streak: 3,
      }),
    ]);
    renderPage();
    const user = userEvent.setup();
    await waitFor(() => expect(screen.getAllByText('fake-node').length).toBeGreaterThan(0));
    await user.click(screen.getByText('pages.proxies.score.table'));
    await waitFor(() => {
      const row = screen.getAllByText('fake-node').map((el) => el.closest('tr')).find(Boolean);
      expect(row).toBeTruthy();
      expect(row!.textContent).toContain('pages.proxies.score.blackholeShort');
      // Not "warming up": it is still inside warm-up by sample count, but the
      // verdict is already conclusive and warming would read as "give it time".
      expect(row!.textContent).not.toContain('pages.proxies.score.warmingShort');
    });
    // And it must still be listed — a group that drops every unhealthy member
    // leaves the machine with no egress at all.
    expect(screen.getAllByText('fake-node').length).toBeGreaterThan(0);
  });

  it('degrades to no badges when the gateway has no scores', async () => {
    vi.spyOn(api, 'proxies').mockResolvedValue({
      proxies: { Auto: { type: 'URLTest', now: 'a', all: ['a'], history: [] } },
    } as unknown as Awaited<ReturnType<typeof api.proxies>>);
    vi.spyOn(api, 'proxyGroups').mockResolvedValue({
      auto_country: true, exclude_countries: [], groups: [],
      failover: { interrupt_existing_connections: false }, scoring: {},
    });
    vi.spyOn(api, 'proxyScores').mockRejectedValue(new Error('proxy scores not available'));
    renderPage();
    // The node list must still render: scoring is advisory, not a prerequisite.
    await waitFor(() => expect(screen.getAllByText('a').length).toBeGreaterThan(0));
    expect(screen.queryByText('pages.proxies.score.title')).toBeNull();
  });
});
