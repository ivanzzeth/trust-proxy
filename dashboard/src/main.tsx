import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { createHashRouter, RouterProvider } from 'react-router-dom';

import './index.css';
import { AppShell } from '@/components/app-shell';
import { Toaster } from '@/components/ui/sonner';
import Overview from '@/pages/overview';
import Connections from '@/pages/connections';
import Subscriptions from '@/pages/subscriptions';
import Profiles from '@/pages/profiles';
import Whitelist from '@/pages/whitelist';
import RuleSets from '@/pages/rulesets';

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
      { path: 'profiles', element: <Profiles /> },
      { path: 'whitelist', element: <Whitelist /> },
      { path: 'rulesets', element: <RuleSets /> },
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
