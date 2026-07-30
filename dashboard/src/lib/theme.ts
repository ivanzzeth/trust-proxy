import { useSyncExternalStore } from 'react';

// Theme preference, persisted per browser.
//
// It used to be component state seeded from whatever class index.html happened
// to ship with, so the sidebar toggle survived exactly as long as the tab did —
// and there was no way to say "follow the system", which is what a console you
// leave open all day actually wants. Language went through i18next and was
// persistent; the theme sitting right next to it was not.
//
// The store lives outside React because two places read it (the sidebar toggle
// and the Settings row) and they must not disagree.

export type ThemePref = 'system' | 'dark' | 'light';

const KEY = 'tp-theme';
const listeners = new Set<() => void>();

function read(): ThemePref {
  try {
    const v = localStorage.getItem(KEY);
    if (v === 'dark' || v === 'light' || v === 'system') return v;
  } catch {
    // Private mode / disabled storage: fall back to system rather than throwing
    // on the render path.
  }
  return 'system';
}

let pref: ThemePref = read();

const media = () => (typeof matchMedia === 'function' ? matchMedia('(prefers-color-scheme: dark)') : null);

export function isDark(p: ThemePref = pref): boolean {
  if (p === 'dark') return true;
  if (p === 'light') return false;
  return media()?.matches ?? true;
}

/** Applied before the first render (see main.tsx) so a dark-mode console never
 *  flashes white on load. */
export function applyTheme(): void {
  document.documentElement.classList.toggle('dark', isDark());
}

export function setThemePref(p: ThemePref): void {
  pref = p;
  try {
    localStorage.setItem(KEY, p);
  } catch {
    // Preference is best-effort; the class below is what the user sees.
  }
  applyTheme();
  listeners.forEach((l) => l());
}

// When following the system, track it live: someone with a scheduled dark mode
// should not have to reload at sunset.
media()?.addEventListener?.('change', () => {
  if (pref === 'system') {
    applyTheme();
    listeners.forEach((l) => l());
  }
});

function subscribe(cb: () => void): () => void {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

export function useTheme(): { pref: ThemePref; dark: boolean; setPref: (p: ThemePref) => void; toggle: () => void } {
  const p = useSyncExternalStore(
    subscribe,
    () => pref,
    () => 'system' as ThemePref,
  );
  const dark = isDark(p);
  return {
    pref: p,
    dark,
    setPref: setThemePref,
    // The sidebar button is a two-state affordance, so it commits to the
    // opposite of what is on screen rather than cycling back through "system".
    toggle: () => setThemePref(dark ? 'light' : 'dark'),
  };
}
