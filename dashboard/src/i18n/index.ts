// i18n bootstrap (react-i18next). Language is detected from localStorage
// (key `tp-lang`) then the browser, and persisted on change; <html lang> is
// kept in sync. Import this once, before rendering (see main.tsx).
import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';

import en from './en.json';
import zh from './zh.json';

export const LANGS = [
  { code: 'en', label: 'English' },
  { code: 'zh', label: '中文' },
] as const;

// Per-page translation modules: src/i18n/pages/<name>.ts default-exports
// { en, zh } and is auto-merged under the `pages.<name>` namespace. This lets
// each page be translated in its own file with zero shared-file contention
// (base chrome strings stay in en.json / zh.json).
type PageMod = { default: { en: Record<string, unknown>; zh: Record<string, unknown> } };
const mods = (import.meta as unknown as { glob: (p: string, o: object) => Record<string, PageMod> }).glob(
  './pages/*.ts',
  { eager: true },
);
const pagesEn: Record<string, unknown> = {};
const pagesZh: Record<string, unknown> = {};
for (const [path, mod] of Object.entries(mods)) {
  const ns = path.slice(path.lastIndexOf('/') + 1).replace(/\.ts$/, '');
  pagesEn[ns] = mod.default.en;
  pagesZh[ns] = mod.default.zh;
}

const enRes = { ...en, pages: { ...(en as { pages?: object }).pages, ...pagesEn } };
const zhRes = { ...zh, pages: { ...(zh as { pages?: object }).pages, ...pagesZh } };

void i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: { en: { translation: enRes }, zh: { translation: zhRes } },
    fallbackLng: 'en',
    supportedLngs: ['en', 'zh'],
    interpolation: { escapeValue: false },
    detection: {
      order: ['localStorage', 'navigator'],
      lookupLocalStorage: 'tp-lang',
      caches: ['localStorage'],
    },
  });

const applyLang = (lng: string) => {
  document.documentElement.lang = lng;
};
applyLang(i18n.resolvedLanguage ?? 'en');
i18n.on('languageChanged', applyLang);

export default i18n;
