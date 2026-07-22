import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';

import { tp } from '~/api/trustproxy';

import s from './ModeSwitch.module.scss';

const KEY = ['tp', 'status'];

// ModeSwitch is the always-visible gateway control in the sidebar footer:
// capture mode (manual / system-proxy / tun) + auto-block toggle + threat count.
export default function ModeSwitch() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const invalidate = () => qc.invalidateQueries({ queryKey: KEY });

  const { data: st } = useQuery({ queryKey: KEY, queryFn: tp.status, refetchInterval: 5000 });

  const modeM = useMutation({
    mutationFn: (m: string) => tp.setMode(m),
    onSettled: invalidate,
  });
  const blockM = useMutation({
    mutationFn: (v: boolean) => tp.setAutoBlock(v),
    onSettled: invalidate,
  });

  if (!st) return null;
  const modes = st.modes || ['manual', 'system', 'tun'];

  return (
    <div className={s.root}>
      <div className={s.title}>{t('mode_title')}</div>
      <div className={s.modes}>
        {modes.map((m) => {
          const needRoot = m === 'tun' && !st.root;
          return (
            <button
              key={m}
              className={m === st.mode ? s.modeActive : s.mode}
              disabled={modeM.isPending}
              title={needRoot ? t('mode_tun_needs_root') : t('mode_' + m)}
              onClick={() => modeM.mutate(m)}
            >
              {t('mode_' + m)}
            </button>
          );
        })}
      </div>
      {modeM.isError && <div className={s.err}>{String((modeM.error as Error).message)}</div>}

      <label className={s.blockRow}>
        <input
          type="checkbox"
          checked={st.autoBlock}
          disabled={blockM.isPending}
          onChange={(e) => blockM.mutate(e.target.checked)}
        />
        <span>{t('mode_autoblock')}</span>
      </label>

      <div className={s.threats} title={t('mode_threats_hint')}>
        {t('mode_threats', { domains: st.threats?.domains ?? 0, ips: st.threats?.ips ?? 0 })}
      </div>
    </div>
  );
}
