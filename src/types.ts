/** Shared types mirroring the Rust core (camelCase serde). */

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Category =
  | "secret_leak"
  | "dangerous_operation"
  | "vulnerability"
  | "test_integrity"
  | "suspicious_change"
  | "supply_chain"
  | "ci_cd";
export type Engine =
  | "secrets"
  | "dangerous"
  | "security"
  | "tests"
  | "suspicious"
  | "supply_chain"
  | "ci_cd";
export type Language = "en" | "fa";
export type RiskBand = "safe" | "low" | "elevated" | "high" | "critical";
export type Verdict = "pass" | "review" | "block";
export type ChangeStatus =
  | "added"
  | "modified"
  | "deleted"
  | "renamed"
  | "copied"
  | "typechange"
  | "untracked";

export interface L10n {
  en: string;
  fa: string;
}
export interface RuleText {
  title: L10n;
  description: L10n;
  remediation: L10n;
}

export interface DiffLine {
  kind: "added" | "removed" | "context" | "header";
  oldNo: number | null;
  newNo: number | null;
  text: string;
}
export interface DiffHunk {
  header: string;
  lines: DiffLine[];
}
export interface FileChange {
  path: string;
  oldPath: string | null;
  status: ChangeStatus;
  isBinary: boolean;
  tooLarge: boolean;
  additions: number;
  deletions: number;
  oldExec: boolean;
  newExec: boolean;
  hunks: DiffHunk[];
}

export interface Finding {
  id: string;
  ruleId: string;
  engine: Engine;
  category: Category;
  severity: Severity;
  confidence: number;
  file: string;
  line: number;
  endLine: number | null;
  snippet: string;
  matched: string | null;
  side: string;
  text: RuleText;
  cwe: string[];
  references: string[];
  tags: string[];
  redactable: boolean;
}

export type ScanBase =
  | { kind: "workingTree" }
  | { kind: "staged" }
  | { kind: "branch"; value: string }
  | { kind: "commit"; value: string }
  | { kind: "range"; value: { from: string; to: string } }
  | { kind: "lastCommits"; value: number };

export interface EngineToggles {
  secrets: boolean;
  dangerous: boolean;
  security: boolean;
  tests: boolean;
  suspicious: boolean;
  supplyChain: boolean;
  ciCd: boolean;
}

export interface AiOptions {
  enabled: boolean;
  host: string;
  model: string;
  maxDiffChars: number;
  timeoutSecs: number;
}

export interface ScanOptions {
  projectPath: string;
  base: ScanBase;
  includeUntracked: boolean;
  engines: EngineToggles;
  maxFileBytes: number;
  ignoreGlobs: string[];
  language: Language;
  ai: AiOptions;
  contextLines: number;
}

export interface ScanStats {
  filesChanged: number;
  filesScanned: number;
  filesSkipped: number;
  additions: number;
  deletions: number;
  bytesScanned: number;
  rulesActive: number;
  enginesEnabled: number;
}

export interface ScanSummary {
  stats: ScanStats;
  bySeverity: Partial<Record<Severity, number>>;
  byCategory: Partial<Record<Category, number>>;
  byEngine: Partial<Record<Engine, number>>;
  riskScore: number;
  riskBand: RiskBand;
  verdict: Verdict;
}

export interface BranchInfo {
  name: string;
  isHead: boolean;
  isRemote: boolean;
}
export interface CommitInfo {
  sha: string;
  shortSha: string;
  subject: string;
  author: string;
  timestamp: number;
}
export interface RepoInfo {
  path: string;
  isRepo: boolean;
  branch: string | null;
  headSha: string | null;
  headSubject: string | null;
  commitCount: number;
  dirtyFiles: number;
  untrackedFiles: number;
  branches: BranchInfo[];
  remotes: string[];
  error: string | null;
}

export interface AiInsight {
  title: string;
  detail: string;
  severity: Severity;
  file: string | null;
}
export interface AiAnalysis {
  enabled: boolean;
  available: boolean;
  model: string;
  host: string;
  summary: string;
  insights: AiInsight[];
  raw: string;
  error: string | null;
  durationMs: number;
}

export interface ScanReport {
  id: string;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  projectPath: string;
  repo: RepoInfo;
  options: ScanOptions;
  summary: ScanSummary;
  files: FileChange[];
  findings: Finding[];
  ai: AiAnalysis | null;
  warnings: string[];
  catalogVersion: number;
}

export interface ScanProgress {
  scanId: string;
  phase: string;
  percent: number;
  messageEn: string;
  messageFa: string;
  detail: string | null;
}

export interface OllamaModel {
  name: string;
  sizeBytes: number;
}
export interface OllamaStatus {
  host: string;
  available: boolean;
  version: string | null;
  models: OllamaModel[];
  error: string | null;
}

export interface RecentProject {
  path: string;
  name: string;
  lastOpened: string;
  scanCount: number;
}

export interface HistoryEntry {
  id: string;
  startedAt: string;
  projectPath: string;
  projectName: string;
  branch: string | null;
  base: string;
  riskScore: number;
  riskBand: RiskBand;
  verdict: Verdict;
  findings: number;
  critical: number;
  high: number;
  filesChanged: number;
  durationMs: number;
  language: Language;
}

export interface Settings {
  language: Language;
  theme: "dark" | "light" | "system";
  engines: EngineToggles;
  includeUntracked: boolean;
  maxFileBytes: number;
  ignoreGlobs: string[];
  contextLines: number;
  ai: AiOptions;
  confirmTtlSecs: number;
  autoScanOnOpen: boolean;
  lastProject: string | null;
}

export interface AppInfo {
  name: string;
  version: string;
  os: string;
  arch: string;
  dataDir: string;
  catalogVersion: number;
  rules: number;
}

export interface AppErrorPayload {
  code: string;
  message: string;
}

export interface Confirmation {
  token: string;
  action: string;
  detail: string;
  issuedAt: string;
  expiresAt: number;
}

export interface TestRunnerInfo {
  runner: string;
  command: string[];
  descriptionEn: string;
  descriptionFa: string;
}
export interface TestRunResult {
  runner: string;
  command: string[];
  exitCode: number | null;
  passed: boolean;
  output: string;
  summary: string;
  durationMs: number;
}
