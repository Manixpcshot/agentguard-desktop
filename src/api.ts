/** Thin typed wrapper around the Tauri invoke bridge. */

import { invoke } from "@tauri-apps/api/core";
import type {
  AppInfo,
  CommitInfo,
  Confirmation,
  FileChange,
  Finding,
  HistoryEntry,
  OllamaStatus,
  RecentProject,
  RepoInfo,
  ScanBase,
  ScanOptions,
  ScanReport,
  Settings,
  TestRunResult,
  TestRunnerInfo,
} from "./types";

export const api = {
  appInfo: () => invoke<AppInfo>("app_info"),
  appDataDir: () => invoke<string>("app_data_dir"),
  inspectRepository: (path: string) =>
    invoke<RepoInfo>("inspect_repository", { path }),
  listCommits: (path: string, refname: string | null, limit: number) =>
    invoke<CommitInfo[]>("list_commits", { path, refname, limit }),
  getFileDiff: (path: string, base: ScanBase, file: string) =>
    invoke<FileChange | null>("get_file_diff", { path, base, file }),
  startScan: (options: ScanOptions) =>
    invoke<string>("start_scan", { options }),
  cancelScan: (scanId: string) => invoke<boolean>("cancel_scan", { scanId }),
  ollamaStatus: (host: string) => invoke<OllamaStatus>("ollama_status", { host }),
  runAiReview: (options: ScanOptions, findings: Finding[]) =>
    invoke<import("./types").AiAnalysis>("run_ai_review", { options, findings }),
  exportReport: (report: ScanReport, format: string, dest: string) =>
    invoke<string>("export_report", { report, format, dest }),
  saveReportDialog: (report: ScanReport, format: string) =>
    invoke<string | null>("save_report_dialog", { report, format }),
  listHistory: () => invoke<HistoryEntry[]>("list_history"),
  getHistory: (id: string) => invoke<ScanReport>("get_history", { id }),
  deleteHistory: (id: string) => invoke<void>("delete_history", { id }),
  clearHistory: () => invoke<void>("clear_history"),
  getSettings: () => invoke<Settings>("get_settings"),
  saveSettings: (settings: Settings) =>
    invoke<void>("save_settings", { settings }),
  listRecentProjects: () => invoke<RecentProject[]>("list_recent_projects"),
  rememberProject: (path: string) =>
    invoke<RecentProject[]>("remember_project", { path }),
  forgetProject: (path: string) =>
    invoke<RecentProject[]>("forget_project", { path }),
  issueConfirmation: (action: string, detail: string) =>
    invoke<Confirmation>("issue_confirmation", { action, detail }),
  detectTestRunner: (path: string) =>
    invoke<TestRunnerInfo | null>("detect_test_runner", { path }),
  runTests: (projectPath: string, confirmation: string, timeoutSecs: number) =>
    invoke<TestRunResult>("run_tests", {
      request: { projectPath, confirmation, timeoutSecs },
    }),
  redactSecret: (payload: {
    projectPath: string;
    file: string;
    line: number;
    ruleId: string;
    findingId: string;
    confirmation: string;
    createBackup: boolean;
  }) =>
    invoke<{ file: string; backup: string | null; replaced: number }>(
      "redact_secret",
      { request: payload },
    ),
};

export function errorMessage(e: unknown): string {
  if (e && typeof e === "object" && "message" in e) {
    return String((e as { message: unknown }).message);
  }
  if (typeof e === "string") return e;
  return String(e);
}
