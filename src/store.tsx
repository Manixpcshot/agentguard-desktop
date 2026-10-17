import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { api, errorMessage } from "./api";
import type {
  AppInfo,
  EngineToggles,
  Finding,
  HistoryEntry,
  OllamaStatus,
  RecentProject,
  RepoInfo,
  ScanBase,
  ScanOptions,
  ScanProgress,
  ScanReport,
  Settings,
  TestRunResult,
} from "./types";

export type View =
  | "dashboard"
  | "findings"
  | "changes"
  | "history"
  | "ai"
  | "settings"
  | "about";

export interface Toast {
  id: number;
  kind: "info" | "success" | "error" | "warn";
  text: string;
}

export interface ConfirmSpec {
  title: string;
  body: string;
  confirmLabel: string;
  danger?: boolean;
  onConfirm: () => void | Promise<void>;
}

interface ScanUiState {
  status: "idle" | "running" | "error";
  scanId: string | null;
  percent: number;
  phase: string;
  detail: string | null;
  error: string | null;
}

interface StoreValue {
  booted: boolean;
  view: View;
  setView: (v: View) => void;
  appInfo: AppInfo | null;
  dataDir: string;
  settings: Settings;
  updateSettings: (patch: Partial<Settings>) => void;
  projectPath: string | null;
  repo: RepoInfo | null;
  recent: RecentProject[];
  chooseProject: () => Promise<void>;
  openProject: (path: string) => Promise<void>;
  forgetProject: (path: string) => Promise<void>;
  scanConfig: {
    base: ScanBase;
    includeUntracked: boolean;
    engines: EngineToggles;
  };
  setScanConfig: (patch: Partial<StoreValue["scanConfig"]>) => void;
  scan: ScanUiState;
  startScan: () => Promise<void>;
  cancelScan: () => Promise<void>;
  report: ScanReport | null;
  setReport: (r: ScanReport | null) => void;
  selectedFindingId: string | null;
  selectFinding: (id: string | null) => void;
  selectedFile: string | null;
  selectFile: (p: string | null) => void;
  history: HistoryEntry[];
  reloadHistory: () => Promise<void>;
  openHistory: (id: string) => Promise<void>;
  deleteHistory: (id: string) => Promise<void>;
  clearHistory: () => Promise<void>;
  toasts: Toast[];
  toast: (kind: Toast["kind"], text: string) => void;
  dismissToast: (id: number) => void;
  confirm: ConfirmSpec | null;
  askConfirm: (spec: ConfirmSpec) => void;
  closeConfirm: () => void;
  ollama: OllamaStatus | null;
  setOllama: (s: OllamaStatus | null) => void;
  testResult: TestRunResult | null;
  setTestResult: (r: TestRunResult | null) => void;
  buildOptions: () => ScanOptions;
}

const DEFAULT_SETTINGS: Settings = {
  language: "en",
  theme: "dark",
  engines: {
    secrets: true,
    dangerous: true,
    security: true,
    tests: true,
    suspicious: true,
    supplyChain: true,
    ciCd: true,
  },
  includeUntracked: true,
  maxFileBytes: 1_500_000,
  ignoreGlobs: [],
  contextLines: 3,
  ai: {
    enabled: false,
    host: "http://127.0.0.1:11434",
    model: "",
    maxDiffChars: 24000,
    timeoutSecs: 180,
  },
  confirmTtlSecs: 300,
  autoScanOnOpen: false,
  lastProject: null,
};

const StoreContext = createContext<StoreValue | null>(null);

export function useApp(): StoreValue {
  const ctx = useContext(StoreContext);
  if (!ctx) throw new Error("useApp outside provider");
  return ctx;
}

let toastSeq = 1;

export function AppStoreProvider({ children }: { children: ReactNode }) {
  const [booted, setBooted] = useState(false);
  const [view, setView] = useState<View>("dashboard");
  const [appInfo, setAppInfo] = useState<AppInfo | null>(null);
  const [dataDir, setDataDir] = useState("");
  const [settings, setSettings] = useState<Settings>(DEFAULT_SETTINGS);
  const [projectPath, setProjectPath] = useState<string | null>(null);
  const [repo, setRepo] = useState<RepoInfo | null>(null);
  const [recent, setRecent] = useState<RecentProject[]>([]);
  const [scanConfig, setScanConfigState] = useState<StoreValue["scanConfig"]>({
    base: { kind: "workingTree" },
    includeUntracked: true,
    engines: DEFAULT_SETTINGS.engines,
  });
  const [scan, setScan] = useState<ScanUiState>({
    status: "idle",
    scanId: null,
    percent: 0,
    phase: "",
    detail: null,
    error: null,
  });
  const [report, setReport] = useState<ScanReport | null>(null);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [selectedFile, setSelectedFile] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [confirm, setConfirm] = useState<ConfirmSpec | null>(null);
  const [ollama, setOllama] = useState<OllamaStatus | null>(null);
  const [testResult, setTestResult] = useState<TestRunResult | null>(null);
  const scanRef = useRef<string | null>(null);

  const toast = useCallback((kind: Toast["kind"], text: string) => {
    const id = toastSeq++;
    setToasts((t) => [...t, { id, kind, text }]);
    window.setTimeout(() => {
      setToasts((t) => t.filter((x) => x.id !== id));
    }, 5200);
  }, []);

  const dismissToast = useCallback((id: number) => {
    setToasts((t) => t.filter((x) => x.id !== id));
  }, []);

  const buildOptions = useCallback((): ScanOptions => {
    return {
      projectPath: projectPath ?? "",
      base: scanConfig.base,
      includeUntracked: scanConfig.includeUntracked,
      engines: scanConfig.engines,
      maxFileBytes: settings.maxFileBytes,
      ignoreGlobs: settings.ignoreGlobs,
      language: settings.language,
      ai: { ...settings.ai, enabled: settings.ai.enabled && !!settings.ai.model },
      contextLines: settings.contextLines,
    };
  }, [projectPath, scanConfig, settings]);

  const reloadHistory = useCallback(async () => {
    try {
      setHistory(await api.listHistory());
    } catch {
      setHistory([]);
    }
  }, []);

  const openProject = useCallback(
    async (path: string) => {
      setProjectPath(path);
      setSelectedFile(null);
      setSelectedFindingId(null);
      try {
        const info = await api.inspectRepository(path);
        setRepo(info);
        setRecent(await api.rememberProject(path));
        setSettings((s) => {
          const next = { ...s, lastProject: path };
          void api.saveSettings(next);
          return next;
        });
        void reloadHistory();
      } catch (e) {
        setRepo({
          path,
          isRepo: false,
          branch: null,
          headSha: null,
          headSubject: null,
          commitCount: 0,
          dirtyFiles: 0,
          untrackedFiles: 0,
          branches: [],
          remotes: [],
          error: errorMessage(e),
        });
      }
    },
    [reloadHistory],
  );

  const startScan = useCallback(async () => {
    if (!projectPath) return;
    setScan({ status: "running", scanId: null, percent: 2, phase: "opening", detail: null, error: null });
    try {
      const id = await api.startScan(buildOptions());
      scanRef.current = id;
      setScan((s) => ({ ...s, scanId: id }));
    } catch (e) {
      const msg = errorMessage(e);
      setScan({ status: "error", scanId: null, percent: 0, phase: "", detail: null, error: msg });
      toast("error", msg);
    }
  }, [projectPath, buildOptions, toast]);

  const cancelScan = useCallback(async () => {
    if (scanRef.current) await api.cancelScan(scanRef.current).catch(() => false);
  }, []);

  const chooseProject = useCallback(async () => {
    try {
      const picked = await openDialog({ directory: true, multiple: false, title: "AgentGuard" });
      if (typeof picked === "string") await openProject(picked);
    } catch (e) {
      toast("error", errorMessage(e));
    }
  }, [openProject, toast]);

  const forgetProject = useCallback(async (path: string) => {
    setRecent(await api.forgetProject(path));
  }, []);

  const updateSettings = useCallback((patch: Partial<Settings>) => {
    setSettings((s) => {
      const next = { ...s, ...patch };
      void api.saveSettings(next);
      return next;
    });
  }, []);

  const setScanConfig = useCallback((patch: Partial<StoreValue["scanConfig"]>) => {
    setScanConfigState((c) => ({ ...c, ...patch }));
  }, []);

  const openHistory = useCallback(async (id: string) => {
    const r = await api.getHistory(id);
    setReport(r);
    setProjectPath(r.projectPath);
    setRepo(r.repo);
    setSelectedFindingId(null);
    setView("findings");
  }, []);

  const deleteHistory = useCallback(
    async (id: string) => {
      await api.deleteHistory(id);
      await reloadHistory();
    },
    [reloadHistory],
  );

  const clearHistory = useCallback(async () => {
    await api.clearHistory();
    await reloadHistory();
  }, [reloadHistory]);

  // ------------------------------------------------------------------ boot
  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const [info, s, dir, rec, hist] = await Promise.all([
          api.appInfo(),
          api.getSettings(),
          api.appDataDir(),
          api.listRecentProjects(),
          api.listHistory(),
        ]);
        if (!alive) return;
        setAppInfo(info);
        setSettings(s);
        setDataDir(dir);
        setRecent(rec);
        setHistory(hist);
        setScanConfigState((c) => ({
          ...c,
          includeUntracked: s.includeUntracked,
          engines: s.engines,
        }));
        if (s.lastProject) {
          await openProject(s.lastProject);
        }
      } catch {
        // running outside Tauri (browser preview) — keep defaults
      } finally {
        if (alive) setBooted(true);
      }
    })();
    return () => {
      alive = false;
    };
  }, [openProject]);

  // ------------------------------------------------------- scan event wire
  useEffect(() => {
    const unlisteners: UnlistenFn[] = [];
    (async () => {
      unlisteners.push(
        await listen<ScanProgress>("scan-progress", (ev) => {
          if (scanRef.current && ev.payload.scanId !== scanRef.current) return;
          setScan((s) => ({
            ...s,
            status: "running",
            percent: ev.payload.percent,
            phase: ev.payload.phase,
            detail: ev.payload.detail,
          }));
        }),
      );
      unlisteners.push(
        await listen<{ scanId: string; report: ScanReport }>("scan-finished", (ev) => {
          if (scanRef.current && ev.payload.scanId !== scanRef.current) return;
          scanRef.current = null;
          setReport(ev.payload.report);
          setScan({ status: "idle", scanId: null, percent: 100, phase: "done", detail: null, error: null });
          setSelectedFindingId(null);
          void reloadHistory();
          toast("success", `${ev.payload.report.findings.length} findings`);
        }),
      );
      unlisteners.push(
        await listen<{ scanId: string; error: { code: string; message: string } }>(
          "scan-failed",
          (ev) => {
            if (scanRef.current && ev.payload.scanId !== scanRef.current) return;
            scanRef.current = null;
            const cancelled = ev.payload.error?.code === "cancelled";
            setScan({
              status: cancelled ? "idle" : "error",
              scanId: null,
              percent: 0,
              phase: "",
              detail: null,
              error: cancelled ? null : ev.payload.error?.message,
            });
            toast(cancelled ? "info" : "error", ev.payload.error?.message ?? "scan failed");
          },
        ),
      );
    })();
    return () => unlisteners.forEach((u) => u());
  }, [reloadHistory, toast]);

  // ---------------------------------------------------------- theme & lang
  useEffect(() => {
    const root = document.documentElement;
    const apply = () => {
      let theme = settings.theme;
      if (theme === "system") {
        theme = window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
      }
      root.dataset.theme = theme;
    };
    apply();
    const mq = window.matchMedia("(prefers-color-scheme: light)");
    mq.addEventListener("change", apply);
    root.lang = settings.language;
    root.dir = settings.language === "fa" ? "rtl" : "ltr";
    return () => mq.removeEventListener("change", apply);
  }, [settings.theme, settings.language]);

  const value = useMemo<StoreValue>(
    () => ({
      booted,
      view,
      setView,
      appInfo,
      dataDir,
      settings,
      updateSettings,
      projectPath,
      repo,
      recent,
      chooseProject,
      openProject,
      forgetProject,
      scanConfig,
      setScanConfig,
      scan,
      startScan,
      cancelScan,
      report,
      setReport,
      selectedFindingId,
      selectFinding: setSelectedFindingId,
      selectedFile,
      selectFile: setSelectedFile,
      history,
      reloadHistory,
      openHistory,
      deleteHistory,
      clearHistory,
      toasts,
      toast,
      dismissToast,
      confirm,
      askConfirm: setConfirm,
      closeConfirm: () => setConfirm(null),
      ollama,
      setOllama,
      testResult,
      setTestResult,
      buildOptions,
    }),
    [
      booted, view, appInfo, dataDir, settings, updateSettings, projectPath, repo, recent,
      chooseProject, openProject, forgetProject, scanConfig, setScanConfig, scan, startScan,
      cancelScan, report, selectedFindingId, selectedFile, history, reloadHistory, openHistory,
      deleteHistory, clearHistory, toasts, toast, dismissToast, confirm, ollama, testResult,
      buildOptions,
    ],
  );

  return <StoreContext.Provider value={value}>{children}</StoreContext.Provider>;
}

export function severityOrder(s: string): number {
  return ["critical", "high", "medium", "low", "info"].indexOf(s);
}

export function findingMatches(f: Finding, query: string): boolean {
  if (!query) return true;
  const q = query.toLowerCase();
  return (
    f.file.toLowerCase().includes(q) ||
    f.ruleId.toLowerCase().includes(q) ||
    f.text.title.en.toLowerCase().includes(q) ||
    f.text.title.fa.includes(query) ||
    f.snippet.toLowerCase().includes(q) ||
    f.tags.some((t) => t.includes(q))
  );
}
