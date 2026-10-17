/** Maps backend enum values (snake_case) to i18n dictionary keys. */
import type { DictKey } from "./i18n/en";
import type { Category, Engine, EngineToggles, RiskBand, Severity, Verdict } from "./types";

export const ENGINE_LABEL: Record<Engine, DictKey> = {
  secrets: "engine.secrets",
  dangerous: "engine.dangerous",
  security: "engine.security",
  tests: "engine.tests",
  suspicious: "engine.suspicious",
  supply_chain: "engine.supplyChain",
  ci_cd: "engine.ciCd",
};

export const ENGINE_DESC: Record<Engine, DictKey> = {
  secrets: "engine.secrets.desc",
  dangerous: "engine.dangerous.desc",
  security: "engine.security.desc",
  tests: "engine.tests.desc",
  suspicious: "engine.suspicious.desc",
  supply_chain: "engine.supplyChain.desc",
  ci_cd: "engine.ciCd.desc",
};

export const ENGINE_TOGGLE_KEY: Record<Engine, keyof EngineToggles> = {
  secrets: "secrets",
  dangerous: "dangerous",
  security: "security",
  tests: "tests",
  suspicious: "suspicious",
  supply_chain: "supplyChain",
  ci_cd: "ciCd",
};

export const ALL_ENGINES: Engine[] = [
  "secrets",
  "dangerous",
  "security",
  "tests",
  "suspicious",
  "supply_chain",
  "ci_cd",
];

export const SEV_LABEL: Record<Severity, DictKey> = {
  critical: "severity.critical",
  high: "severity.high",
  medium: "severity.medium",
  low: "severity.low",
  info: "severity.info",
};

export const CAT_LABEL: Record<Category, DictKey> = {
  secret_leak: "category.secret_leak",
  dangerous_operation: "category.dangerous_operation",
  vulnerability: "category.vulnerability",
  test_integrity: "category.test_integrity",
  suspicious_change: "category.suspicious_change",
  supply_chain: "category.supply_chain",
  ci_cd: "category.ci_cd",
};

export const BAND_LABEL: Record<RiskBand, DictKey> = {
  safe: "band.safe",
  low: "band.low",
  elevated: "band.elevated",
  high: "band.high",
  critical: "band.critical",
};

export const VERDICT_LABEL: Record<Verdict, DictKey> = {
  pass: "verdict.pass",
  review: "verdict.review",
  block: "verdict.block",
};
