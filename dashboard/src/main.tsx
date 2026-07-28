import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { createHashRouter, Navigate, RouterProvider } from 'react-router-dom';

import './index.css';
import '@/i18n';
import { AppShell } from '@/components/app-shell';
import { AuthGate } from '@/components/auth-gate';
import { Toaster } from '@/components/ui/sonner';
import Overview from '@/pages/overview';
import Connections from '@/pages/connections';
import Subscriptions from '@/pages/subscriptions';
import Profiles from '@/pages/profiles';
import ACLs from '@/pages/acls';
import Proxies from '@/pages/proxies';
import Rules from '@/pages/rules';
import Logs from '@/pages/logs';
import DNS from '@/pages/dns';
import History from '@/pages/history';
import Fleet from '@/pages/fleet';
import Settings from '@/pages/settings';
import Endpoints from '@/pages/endpoints';
import Detection from '@/pages/detection';
import Users from '@/pages/users';

const queryClient = new QueryClient({
  defaultOptions: { queries: { refetchOnWindowFocus: false, retry: 1 } },
});

/** Belt-and-suspenders for macOS WKWebView: attributes on <Input> are not
 *  always enough when the system "correct spelling automatically" is on.
 *  Re-stamp every focused field so search bars stop rewriting queries. */
function disarmTextRewrite(el: EventTarget | null) {
  if (!(el instanceof HTMLInputElement) && !(el instanceof HTMLTextAreaElement)) return;
  if (el.type === 'password' || el.type === 'checkbox' || el.type === 'radio' || el.type === 'file') return;
  el.setAttribute('autocorrect', 'off');
  el.setAttribute('autocapitalize', 'none');
  el.setAttribute('autocomplete', 'off');
  el.setAttribute('spellcheck', 'false');
  el.setAttribute('lang', 'zxx');
  el.spellcheck = false;
}
document.addEventListener('focusin', (e) => disarmTextRewrite(e.target), true);

const router = createHashRouter([
  {
    path: '/',
    element: <AppShell />,
    children: [
      { index: true, element: <Overview /> },
      { path: 'connections', element: <Connections /> },
      { path: 'subscriptions', element: <Subscriptions /> },
      { path: 'endpoints', element: <Endpoints /> },
      { path: 'profiles', element: <Profiles /> },
      { path: 'acls', element: <ACLs /> },
      { path: 'whitelist', element: <Navigate to="/acls" replace /> },
      { path: 'blacklist', element: <Navigate to="/acls" replace /> },
      { path: 'rulesets', element: <Navigate to="/rules" replace /> },
      { path: 'custom-rules', element: <Navigate to="/rules" replace /> },
      { path: 'proxies', element: <Proxies /> },
      { path: 'rules', element: <Rules /> },
      { path: 'dns', element: <DNS /> },
      { path: 'detection', element: <Detection /> },
      { path: 'history', element: <History /> },
      { path: 'logs', element: <Logs /> },
      { path: 'fleet', element: <Fleet /> },
      { path: 'users', element: <Users /> },
      { path: 'settings', element: <Settings /> },
      // Anything else — a stale bookmark, a renamed page, a hand-typed hash —
      // goes home. Without this react-router renders its own bare 404 *outside*
      // the shell, so there is not even a nav to get back with.
      { path: '*', element: <Navigate to="/" replace /> },
    ],
  },
]);

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <AuthGate>
        <RouterProvider router={router} />
      </AuthGate>
      <Toaster />
    </QueryClientProvider>
  </StrictMode>,
);
