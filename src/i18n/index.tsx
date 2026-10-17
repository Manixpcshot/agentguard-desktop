import { createContext, useContext, useMemo, type ReactNode } from "react";
import { en, type DictKey } from "./en";
import { fa } from "./fa";
import type { Language } from "../types";

interface I18nValue {
  lang: Language;
  dir: "ltr" | "rtl";
  t: (key: DictKey) => string;
}

const I18nContext = createContext<I18nValue>({
  lang: "en",
  dir: "ltr",
  t: (k) => en[k],
});

export function I18nProvider({
  lang,
  children,
}: {
  lang: Language;
  children: ReactNode;
}) {
  const value = useMemo<I18nValue>(
    () => ({
      lang,
      dir: lang === "fa" ? "rtl" : "ltr",
      t: (key) => (lang === "fa" ? fa[key] : en[key]),
    }),
    [lang],
  );
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18nValue {
  return useContext(I18nContext);
}

export type { DictKey };
