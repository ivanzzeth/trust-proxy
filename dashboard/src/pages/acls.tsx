import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { PageHeader } from '@/components/page-header';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import Whitelist from '@/pages/whitelist';
import Blacklist from '@/pages/blacklist';

// ACLs unifies the egress allow-list (whitelist) and deny-list (blacklist) into
// one page — they're the two halves of the same access-control decision.
export default function ACLs() {
  const { t } = useTranslation();
  const [tab, setTab] = useState<'allow' | 'deny'>('allow');
  return (
    <div>
      <PageHeader title={t('nav.acls')} description={t('pages.acls.desc')} />
      <Tabs value={tab} onValueChange={(v) => setTab(v as typeof tab)} className="mb-5">
        <TabsList>
          <TabsTrigger value="allow">{t('pages.acls.allow')}</TabsTrigger>
          <TabsTrigger value="deny">{t('pages.acls.deny')}</TabsTrigger>
        </TabsList>
      </Tabs>
      {tab === 'allow' ? <Whitelist embedded /> : <Blacklist embedded />}
    </div>
  );
}
