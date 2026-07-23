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

void i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: { en: { translation: en }, zh: { translation: zh } },
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
