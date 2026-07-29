import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { PageHeader } from '@/components/page-header';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import Whitelist from '@/pages/whitelist';
import Blacklist from '@/pages/blacklist';
import DirectList from '@/pages/directlist';
import { QuarantinePanel } from '@/components/quarantine-panel';

// Policy: Permit ⊥ Route ⊥ Deny ⊥ Subjects.
// Permit answers "may this destination leave?"; Route never opens that gate.
export default function ACLs() {
  const { t } = useTranslation();
  const [tab, setTab] = useState<'permit' | 'route' | 'deny' | 'subjects'>('permit');
  return (
    <div>
      <PageHeader title={t('nav.acls')} description={t('pages.acls.desc')} />
      <Tabs value={tab} onValueChange={(v) => setTab(v as typeof tab)} className="mb-5">
        <TabsList>
          <TabsTrigger value="permit">{t('pages.acls.permit')}</TabsTrigger>
          <TabsTrigger value="route">{t('pages.acls.route')}</TabsTrigger>
          <TabsTrigger value="deny">{t('pages.acls.deny')}</TabsTrigger>
          <TabsTrigger value="subjects">{t('pages.acls.subjects')}</TabsTrigger>
        </TabsList>
      </Tabs>
      {tab === 'permit' && <Whitelist embedded section="permit" />}
      {tab === 'route' && <DirectList embedded />}
      {tab === 'deny' && (
        <div className="space-y-4">
          <QuarantinePanel compact />
          <Blacklist embedded />
        </div>
      )}
      {tab === 'subjects' && <Whitelist embedded section="subjects" />}
    </div>
  );
}
