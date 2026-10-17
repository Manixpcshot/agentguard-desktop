import { useState } from "react";
import { api, errorMessage } from "../api";
import { Icon, Toggle } from "../components/ui";
import { useI18n, type DictKey } from "../i18n";
import { useApp } from "../store";
import type { AiAnalysis } from "../types";

export function AiView() {
  const app = useApp();
  const { t } = useI18n();
  const [testing, setTesting] = useState(false);
  const [running, setRunning] = useState(false);
  const [analysis, setAnalysis] = useState<AiAnalysis | null>(app.report?.ai ?? null);
  const ai = app.settings.ai;

  const test = async () => {
    setTesting(true);
    try {
      const status = await api.ollamaStatus(ai.host);
      app.setOllama(status);
      if (status.available && !ai.model && status.models.length > 0) {
        app.updateSettings({ ai: { ...ai, model: status.models[0].name } });
      }
    } catch (e) {
      app.toast("error", errorMessage(e));
    } finally {
      setTesting(false);
    }
  };

  const run = async () => {
    setRunning(true);
    try {
      const result = await api.runAiReview(app.buildOptions(), app.report?.findings ?? []);
      setAnalysis(result);
      if (result.error) app.toast("warn", result.error);
    } catch (e) {
      app.toast("error", errorMessage(e));
    } finally {
      setRunning(false);
    }
  };

  const status = app.ollama;

  return (
    <div className="content-grid">
      <div>
        <div className="card hero ai-card">
          <h2>{t("ai.title")}</h2>
          <p>{t("ai.subtitle")}</p>
          <p className="small muted mt">🔒 {t("ai.privacy")}</p>
        </div>

        <div className="card">
          <div className="card-head">
            <Icon name="cpu" />
            <h3>Ollama</h3>
            <span className="spacer" />
            {status ? (
              <span className={`chip`}>
                <span className="dot" style={{ background: status.available ? "var(--ok)" : "var(--critical)" }} />
                {status.available ? t("ai.available") : t("ai.unavailable")}
              </span>
            ) : null}
          </div>
          <div className="card-body">
            <Toggle
              checked={ai.enabled}
              onChange={(v) => app.updateSettings({ ai: { ...ai, enabled: v } })}
              label={t("settings.ollamaEnabled")}
            />
            <label className="field">
              <span>{t("ai.host")}</span>
              <input
                type="text"
                className="mono"
                value={ai.host}
                onChange={(e) => app.updateSettings({ ai: { ...ai, host: e.target.value } })}
              />
            </label>
            <div className="grid-2">
              <label className="field">
                <span>{t("ai.model")}</span>
                {status && status.models.length > 0 ? (
                  <select
                    value={ai.model}
                    onChange={(e) => app.updateSettings({ ai: { ...ai, model: e.target.value } })}
                  >
                    <option value="">…</option>
                    {status.models.map((m) => (
                      <option key={m.name} value={m.name}>
                        {m.name} ({(m.sizeBytes / 1e9).toFixed(1)} GB)
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    type="text"
                    className="mono"
                    placeholder="qwen2.5-coder:7b"
                    value={ai.model}
                    onChange={(e) => app.updateSettings({ ai: { ...ai, model: e.target.value } })}
                  />
                )}
              </label>
              <label className="field">
                <span>{t("settings.ollamaTimeout")}</span>
                <input
                  type="number"
                  min={10}
                  max={1800}
                  value={ai.timeoutSecs}
                  onChange={(e) =>
                    app.updateSettings({ ai: { ...ai, timeoutSecs: Number(e.target.value || 180) } })
                  }
                />
              </label>
            </div>
            <div className="row">
              <button className="btn" disabled={testing} onClick={() => void test()}>
                {testing ? <span className="spin" /> : <Icon name="refresh" size={14} />}
                {testing ? t("ai.testing") : t("ai.test")}
              </button>
              <button
                className="btn primary"
                disabled={running || !ai.enabled || !ai.model}
                onClick={() => void run()}
              >
                {running ? <span className="spin" /> : <Icon name="sparkles" size={14} />}
                {running ? t("ai.running") : t("ai.run")}
              </button>
            </div>
            {!ai.model ? <p className="small muted mt">{t("ai.notConfigured")}</p> : null}
            {status?.available ? (
              <p className="small muted mt">
                {t("ai.version")}: {status.version ?? "?"} · {status.models.length} {t("ai.modelsFound")}
              </p>
            ) : null}
          </div>
        </div>
      </div>

      <div>
        {analysis ? (
          <div className="card">
            <div className="card-head">
              <Icon name="sparkles" />
              <h3>{analysis.model || "model"}</h3>
              <span className="spacer" />
              <span className="muted small">{(analysis.durationMs / 1000).toFixed(1)} {t("common.seconds")}</span>
            </div>
            <div className="card-body">
              {analysis.error ? (
                <p className="small" style={{ color: "var(--high)" }}>
                  {t("ai.unavailable")}: {analysis.error}
                </p>
              ) : null}
              {analysis.summary ? (
                <>
                  <h4 className="muted" style={{ margin: "0 0 6px", fontSize: 12 }}>{t("ai.summary")}</h4>
                  <p className="small" style={{ color: "var(--ink-2)" }}>{analysis.summary}</p>
                </>
              ) : null}
              {analysis.insights.length ? (
                <>
                  <h4 className="muted" style={{ margin: "14px 0 8px", fontSize: 12 }}>{t("ai.insights")}</h4>
                  <div className="finding-list">
                    {analysis.insights.map((ins, i) => (
                      <div className={`finding f-${ins.severity}`} key={i}>
                        <div className="head">
                          <span className={`badge sev-${ins.severity}`}>
                            {t(`severity.${ins.severity}` as DictKey)}
                          </span>
                          <span className="title">{ins.title}</span>
                          {ins.file ? <span className="loc">{ins.file}</span> : null}
                        </div>
                        <div className="desc">{ins.detail}</div>
                      </div>
                    ))}
                  </div>
                </>
              ) : null}
              {analysis.raw ? (
                <details className="mt">
                  <summary className="muted small">raw</summary>
                  <pre style={{ maxHeight: 260 }}>{analysis.raw}</pre>
                </details>
              ) : null}
            </div>
          </div>
        ) : (
          <div className="card">
            <div className="card-body">
              <p className="muted small">{t("ai.subtitle")}</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
