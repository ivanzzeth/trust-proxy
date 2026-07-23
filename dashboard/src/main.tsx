import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { createHashRouter, Navigate, RouterProvider } from 'react-router-dom';

import './index.css';
import '@/i18n';
import { AppShell } from '@/components/app-shell';
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

const queryClient = new QueryClient({
  defaultOptions: { queries: { refetchOnWindowFocus: false, retry: 1 } },
});

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
      { path: 'history', element: <History /> },
      { path: 'logs', element: <Logs /> },
      { path: 'fleet', element: <Fleet /> },
      { path: 'settings', element: <Settings /> },
    ],
  },
]);

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
      <Toaster />
    </QueryClientProvider>
  </StrictMode>,
);
