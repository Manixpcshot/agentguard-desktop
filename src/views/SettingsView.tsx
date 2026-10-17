import { revealItemInDir } from "@tauri-apps/plugin-opener";
import { Icon, Toggle } from "../components/ui";
import { useI18n } from "../i18n";
import { useApp } from "../store";
import { ALL_ENGINES, ENGINE_DESC, ENGINE_LABEL, ENGINE_TOGGLE_KEY } from "../labels";
import type { Language } from "../types";



export function SettingsView() {
  const app = useApp();
  const { t } = useI18n();
  const s = app.settings;

  const setLang = (language: Language) => {
    app.updateSettings({ language });
  };

  return (
    <div className="content-grid">
      <div>
        <div className="card">
          <div className="card-head">
            <Icon name="gear" />
            <h3>{t("settings.title")}</h3>
          </div>
          <div className="card-body">
            <label className="field">
              <span>{t("settings.language")}</span>
              <div className="row">
                <button className={`btn sm ${s.language === "en" ? "primary" : ""}`} onClick={() => setLang("en")}>
                  English
                </button>
                <button className={`btn sm ${s.language === "fa" ? "primary" : ""}`} onClick={() => setLang("fa")}>
                  فارسی
                </button>
              </div>
            </label>
            <label className="field">
              <span>{t("settings.theme")}</span>
              <select
                value={s.theme}
                onChange={(e) => app.updateSettings({ theme: e.target.value as typeof s.theme })}
              >
                <option value="dark">{t("settings.themeDark")}</option>
                <option value="light">{t("settings.themeLight")}</option>
                <option value="system">{t("settings.themeSystem")}</option>
              </select>
            </label>
            <Toggle
              checked={s.autoScanOnOpen}
              onChange={(v) => app.updateSettings({ autoScanOnOpen: v })}
              label={t("settings.autoScan")}
            />
          </div>
        </div>

        <div className="card">
          <div className="card-head">
            <Icon name="scan" />
            <h3>{t("settings.scanDefaults")}</h3>
          </div>
          <div className="card-body">
            <Toggle
              checked={s.includeUntracked}
              onChange={(v) => {
                app.updateSettings({ includeUntracked: v });
                app.setScanConfig({ includeUntracked: v });
              }}
              label={t("settings.includeUntracked")}
            />
            <div className="grid-2">
              <label className="field">
                <span>{t("settings.contextLines")}</span>
                <input
                  type="number"
                  min={0}
                  max={20}
                  value={s.contextLines}
                  onChange={(e) => app.updateSettings({ contextLines: Number(e.target.value || 3) })}
                />
              </label>
              <label className="field">
                <span>{t("settings.maxFile")}</span>
                <input
                  type="number"
                  min={10000}
                  step={100000}
                  value={s.maxFileBytes}
                  onChange={(e) => app.updateSettings({ maxFileBytes: Number(e.target.value || 1500000) })}
                />
              </label>
            </div>
            <label className="field">
              <span>{t("settings.ignoreGlobs")}</span>
              <textarea
                value={s.ignoreGlobs.join("\n")}
                placeholder={t("settings.ignoreHint")}
                onChange={(e) =>
                  app.updateSettings({
                    ignoreGlobs: e.target.value.split("\n").map((x) => x.trim()).filter(Boolean),
                  })
                }
              />
            </label>
            <h4 className="muted" style={{ margin: "6px 0 4px", fontSize: 12 }}>{t("settings.engines")}</h4>
            <div className="grid-2">
              {ALL_ENGINES.map((e) => (
                <div className="engine-row" key={e}>
                  <Toggle
                    checked={s.engines[ENGINE_TOGGLE_KEY[e]]}
                    onChange={(v) => {
                      const engines = { ...s.engines, [ENGINE_TOGGLE_KEY[e]]: v };
                      app.updateSettings({ engines });
                      app.setScanConfig({ engines });
                    }}
                  />
                  <div>
                    <div className="t">{t(ENGINE_LABEL[e])}</div>
                    <div className="d">{t(ENGINE_DESC[e])}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div>
        <div className="card">
          <div className="card-head">
            <Icon name="cpu" />
            <h3>{t("settings.ollama")}</h3>
          </div>
          <div className="card-body">
            <Toggle
              checked={s.ai.enabled}
              onChange={(v) => app.updateSettings({ ai: { ...s.ai, enabled: v } })}
              label={t("settings.ollamaEnabled")}
            />
            <label className="field">
              <span>{t("settings.ollamaHost")}</span>
              <input
                type="text"
                className="mono"
                value={s.ai.host}
                onChange={(e) => app.updateSettings({ ai: { ...s.ai, host: e.target.value } })}
              />
            </label>
            <label className="field">
              <span>{t("settings.ollamaModel")}</span>
              <input
                type="text"
                className="mono"
                value={s.ai.model}
                placeholder="qwen2.5-coder:7b"
                onChange={(e) => app.updateSettings({ ai: { ...s.ai, model: e.target.value } })}
              />
            </label>
            <label className="field">
              <span>{t("settings.ollamaTimeout")}</span>
              <input
                type="number"
                min={10}
                max={1800}
                value={s.ai.timeoutSecs}
                onChange={(e) =>
                  app.updateSettings({ ai: { ...s.ai, timeoutSecs: Number(e.target.value || 180) } })
                }
              />
            </label>
          </div>
        </div>

        <div className="card">
          <div className="card-head">
            <Icon name="lock" />
            <h3>{t("settings.safety")}</h3>
          </div>
          <div className="card-body">
            <label className="field">
              <span>{t("settings.confirmTtl")}</span>
              <input
                type="number"
                min={15}
                max={3600}
                value={s.confirmTtlSecs}
                onChange={(e) => app.updateSettings({ confirmTtlSecs: Number(e.target.value || 300) })}
              />
            </label>
            <p className="small muted">{t("about.safetyBody")}</p>
          </div>
        </div>

        <div className="card">
          <div className="card-head">
            <Icon name="folder" />
            <h3>{t("settings.storage")}</h3>
          </div>
          <div className="card-body">
            <div className="kv small">
              <code className="mono small">{app.dataDir || "…"}</code>
            </div>
            <div className="row mt">
              <button
                className="btn sm"
                disabled={!app.dataDir}
                onClick={() => app.dataDir && void revealItemInDir(app.dataDir)}
              >
                <Icon name="external" size={13} /> {t("common.open")}
              </button>
              <button
                className="btn danger sm"
                onClick={() =>
                  app.askConfirm({
                    title: t("history.clearTitle"),
                    body: t("history.clearBody"),
                    confirmLabel: t("common.clear"),
                    danger: true,
                    onConfirm: async () => {
                      await app.clearHistory();
                      app.toast("info", t("toast.historyCleared"));
                    },
                  })
                }
              >
                <Icon name="trash" size={13} /> {t("history.clear")}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
