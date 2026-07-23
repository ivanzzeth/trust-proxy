import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { PageHeader } from '@/components/page-header';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import Whitelist from '@/pages/whitelist';
import Blacklist from '@/pages/blacklist';
import DirectList from '@/pages/directlist';

// ACLs unifies the egress allow-list (whitelist) and deny-list (blacklist) —
// the two halves of the access-control decision — with the no-proxy (bypass)
// list, a routing concern (what egresses direct instead of through the proxy).
export default function ACLs() {
  const { t } = useTranslation();
  const [tab, setTab] = useState<'allow' | 'deny' | 'direct'>('allow');
  return (
    <div>
      <PageHeader title={t('nav.acls')} description={t('pages.acls.desc')} />
      <Tabs value={tab} onValueChange={(v) => setTab(v as typeof tab)} className="mb-5">
        <TabsList>
          <TabsTrigger value="allow">{t('pages.acls.allow')}</TabsTrigger>
          <TabsTrigger value="deny">{t('pages.acls.deny')}</TabsTrigger>
          <TabsTrigger value="direct">{t('pages.acls.direct')}</TabsTrigger>
        </TabsList>
      </Tabs>
      {tab === 'allow' && <Whitelist embedded />}
      {tab === 'deny' && <Blacklist embedded />}
      {tab === 'direct' && <DirectList embedded />}
    </div>
  );
}
