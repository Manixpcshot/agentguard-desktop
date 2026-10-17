import { useMemo, useState } from "react";
import { revealItemInDir } from "@tauri-apps/plugin-opener";
import { api, errorMessage } from "../api";
import { EmptyState, Icon, Modal } from "../components/ui";
import { useI18n } from "../i18n";
import { ALL_ENGINES, CAT_LABEL, ENGINE_LABEL, SEV_LABEL } from "../labels";
import { findingMatches, useApp } from "../store";
import type { Engine, Finding, Severity } from "../types";

const SEVS: (Severity | "all")[] = ["all", "critical", "high", "medium", "low", "info"];
const ENGINES: (Engine | "all")[] = ["all", ...ALL_ENGINES];

export function FindingsView() {
  const app = useApp();
  const { t, lang } = useI18n();
  const [sev, setSev] = useState<Severity | "all">("all");
  const [engine, setEngine] = useState<Engine | "all">("all");
  const [query, setQuery] = useState("");

  const report = app.report;
  const findings = useMemo(
    () =>
      (report?.findings ?? []).filter(
        (f) =>
          (sev === "all" || f.severity === sev) &&
          (engine === "all" || f.engine === engine) &&
          findingMatches(f, query),
      ),
    [report, sev, engine, query],
  );
  const selected = report?.findings.find((f) => f.id === app.selectedFindingId) ?? null;

  const exportAs = async (format: string) => {
    if (!report) return;
    try {
      const path = await api.saveReportDialog(report, format);
      if (path) app.toast("success", `${t("toast.exported")}: ${path}`);
    } catch (e) {
      app.toast("error", errorMessage(e));
    }
  };

  const copyDetails = async (f: Finding) => {
    const text = [
      `[${f.severity.toUpperCase()}] ${f.text.title[lang]}`,
      `${f.file}:${f.line}`,
      f.text.description[lang],
      `${t("findings.remediation")}: ${f.text.remediation[lang]}`,
      `rule=${f.ruleId} cwe=${f.cwe.join(",")}`,
    ].join("\n");
    try {
      await navigator.clipboard.writeText(text);
      app.toast("info", t("common.copied"));
    } catch {
      app.toast("error", "clipboard unavailable");
    }
  };

  const runTests = async () => {
    if (!app.projectPath) return;
    try {
      const runner = await api.detectTestRunner(app.projectPath);
      if (!runner) {
        app.toast("warn", t("common.notAvailable"));
        return;
      }
      const project = app.projectPath;
      app.askConfirm({
        title: t("findings.runTestsTitle"),
        body: `${lang === "fa" ? runner.descriptionFa : runner.descriptionEn}\n\n$ ${runner.command.join(" ")}`,
        confirmLabel: t("common.confirm"),
        onConfirm: async () => {
          try {
            const conf = await api.issueConfirmation("run-tests", runner.command.join(" "));
            const res = await api.runTests(project, conf.token, 900);
            app.setTestResult(res);
            app.toast(res.passed ? "success" : "error", res.passed ? t("toast.testPassed") : t("toast.testFailed"));
          } catch (e) {
            app.toast("error", errorMessage(e));
          }
        },
      });
    } catch (e) {
      app.toast("error", errorMessage(e));
    }
  };

  const redact = (f: Finding) => {
    const project = app.projectPath;
    if (!project) return;
    app.askConfirm({
      title: t("findings.redactTitle"),
      body: `${t("findings.redactBody")}\n\n${f.file}:${f.line}`,
      confirmLabel: t("findings.redact"),
      danger: true,
      onConfirm: async () => {
        try {
          const conf = await api.issueConfirmation("redact-secret", `${f.file}:${f.line}`);
          const res = await api.redactSecret({
            projectPath: project,
            file: f.file,
            line: f.line,
            ruleId: f.ruleId,
            findingId: f.id,
            confirmation: conf.token,
            createBackup: true,
          });
          app.toast("success", res.backup ? `${t("toast.redacted")} · ${res.backup}` : t("toast.redacted"));
        } catch (e) {
          app.toast("error", `${t("toast.redactFailed")}: ${errorMessage(e)}`);
        }
      },
    });
  };

  if (!report) {
    return (
      <div className="card">
        <EmptyState icon="scan" title={t("findings.empty")} hint={t("findings.emptyHint")} />
      </div>
    );
  }

  return (
    <>
      <div className="row mb" style={{ gap: 8 }}>
        <button className="btn sm" onClick={() => void exportAs("markdown")}>
          <Icon name="download" size={14} /> Markdown
        </button>
        <button className="btn sm" onClick={() => void exportAs("html")}>
          <Icon name="download" size={14} /> HTML
        </button>
        <button className="btn sm" onClick={() => void exportAs("json")}>
          <Icon name="download" size={14} /> JSON
        </button>
        <span className="spacer grow" />
        <button className="btn sm" onClick={() => void runTests()}>
          <Icon name="terminal" size={14} /> {t("findings.runTests")}
        </button>
      </div>

      <div className="filters">
        {SEVS.map((s) => (
          <button key={s} className={`pill ${sev === s ? "on" : ""}`} onClick={() => setSev(s)}>
            {s === "all" ? t("common.all") : t(SEV_LABEL[s])}
          </button>
        ))}
        <select
          style={{ width: 190 }}
          value={engine}
          onChange={(e) => setEngine(e.target.value as Engine | "all")}
        >
          {ENGINES.map((e) => (
            <option key={e} value={e}>
              {e === "all" ? t("common.all") : t(ENGINE_LABEL[e])}
            </option>
          ))}
        </select>
        <div style={{ position: "relative", flex: 1, minWidth: 180 }}>
          <input
            type="text"
            placeholder={t("findings.search")}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
      </div>

      <div className="content-grid">
        <div className="finding-list">
          {findings.length === 0 ? (
            <div className="card">
              <EmptyState icon="check" title={t("findings.empty")} hint={t("findings.emptyHint")} />
            </div>
          ) : (
            findings.map((f) => (
              <div
                key={f.id}
                className={`finding f-${f.severity} ${selected?.id === f.id ? "sel" : ""}`}
                onClick={() => app.selectFinding(f.id)}
              >
                <div className="head">
                  <span className={`badge sev-${f.severity}`}>{t(SEV_LABEL[f.severity])}</span>
                  <span className="title">{f.text.title[lang]}</span>
                  <span className="tag">{t(ENGINE_LABEL[f.engine])}</span>
                  <span className="loc">
                    {f.file}
                    {f.line ? `:${f.line}` : ""}
                  </span>
                </div>
                {f.snippet ? <div className="snip">{f.snippet}</div> : null}
              </div>
            ))
          )}
        </div>

        <div className="detail">
          {selected ? (
            <div className="card">
              <div className="card-head">
                <span className={`badge sev-${selected.severity}`}>
                  {t(SEV_LABEL[selected.severity])}
                </span>
                <h3 className="grow">{selected.text.title[lang]}</h3>
                <button className="icon-btn" onClick={() => app.selectFinding(null)}>
                  <Icon name="x" size={14} />
                </button>
              </div>
              <div className="card-body">
                <div className="kv">
                  <span className="k">{t("history.project")}</span>
                  <code>{selected.file}{selected.line ? `:${selected.line}` : ""}</code>
                </div>
                <div className="kv">
                  <span className="k">{t(CAT_LABEL[selected.category])}</span>
                  <span>{t(ENGINE_LABEL[selected.engine])}</span>
                </div>
                <div className="kv">
                  <span className="k">{t("findings.confidence")}</span>
                  <span>{Math.round(selected.confidence * 100)}%</span>
                </div>
                <div className="kv">
                  <span className="k">ID</span>
                  <code>{selected.ruleId}</code>
                </div>
                {selected.matched ? (
                  <div className="kv">
                    <span className="k">match</span>
                    <code>{selected.matched}</code>
                  </div>
                ) : null}
                {selected.snippet ? <pre>{selected.snippet}</pre> : null}
                <h4>{t("findings.remediation")}</h4>
                <p className="small" style={{ color: "var(--ink-2)" }}>
                  {selected.text.remediation[lang]}
                </p>
                <p className="small" style={{ color: "var(--ink-2)" }}>
                  {selected.text.description[lang]}
                </p>
                {selected.cwe.length ? (
                  <>
                    <h4>CWE</h4>
                    <div className="tagrow">
                      {selected.cwe.map((c) => (
                        <span className="tag" key={c}>
                          {c}
                        </span>
                      ))}
                    </div>
                  </>
                ) : null}
                {selected.references.length ? (
                  <>
                    <h4>{t("findings.references")}</h4>
                    <ul>
                      {selected.references.map((r) => (
                        <li key={r}>
                          <a href="#" onClick={(e) => e.preventDefault()}>
                            {r}
                          </a>
                        </li>
                      ))}
                    </ul>
                  </>
                ) : null}
                {selected.tags.length ? (
                  <div className="tagrow mt">
                    {selected.tags.map((tag) => (
                      <span className="tag" key={tag}>
                        {tag}
                      </span>
                    ))}
                  </div>
                ) : null}
                <div className="row mt">
                  <button className="btn sm" onClick={() => void copyDetails(selected)}>
                    <Icon name="copy" size={13} /> {t("common.copy")}
                  </button>
                  <button
                    className="btn sm"
                    onClick={() => {
                      app.selectFile(selected.file);
                      app.setView("changes");
                    }}
                  >
                    <Icon name="diff" size={13} /> {t("findings.viewDiff")}
                  </button>
                  <button
                    className="btn sm"
                    onClick={() => {
                      if (app.projectPath)
                        void revealItemInDir(`${app.projectPath}/${selected.file}`.replaceAll("\\", "/"));
                    }}
                  >
                    <Icon name="external" size={13} /> {t("findings.reveal")}
                  </button>
                  {selected.redactable && selected.line > 0 ? (
                    <button className="btn sm danger" onClick={() => redact(selected)}>
                      <Icon name="lock" size={13} /> {t("findings.redact")}
                    </button>
                  ) : null}
                </div>
              </div>
            </div>
          ) : (
            <div className="card">
              <div className="card-body">
                <EmptyState icon="eye" title={t("changes.selectHint")} />
              </div>
            </div>
          )}
        </div>
      </div>

      {app.testResult ? (
        <Modal
          wide
          title={`${app.testResult.runner} — ${app.testResult.passed ? t("toast.testPassed") : t("toast.testFailed")}`}
          onClose={() => app.setTestResult(null)}
          footer={
            <button className="btn" onClick={() => app.setTestResult(null)}>
              {t("common.close")}
            </button>
          }
        >
          <div className="small muted mb mono">$ {app.testResult.command.join(" ")}</div>
          <pre style={{ maxHeight: 380 }}>{app.testResult.output}</pre>
        </Modal>
      ) : null}
    </>
  );
}
