import { ConfirmHost, Icon, ToastHost, type IconName } from "./components/ui";
import { I18nProvider, useI18n, type DictKey } from "./i18n";
import { AppStoreProvider, useApp, type View } from "./store";
import { AboutView } from "./views/About";
import { AiView } from "./views/AiView";
import { ChangesView } from "./views/Changes";
import { DashboardView } from "./views/Dashboard";
import { FindingsView } from "./views/Findings";
import { HistoryView } from "./views/History";
import { SettingsView } from "./views/SettingsView";

const NAV: { view: View; icon: IconName; key: DictKey }[] = [
  { view: "dashboard", icon: "scan", key: "nav.dashboard" },
  { view: "findings", icon: "alert", key: "nav.findings" },
  { view: "changes", icon: "diff", key: "nav.changes" },
  { view: "history", icon: "clock", key: "nav.history" },
  { view: "ai", icon: "sparkles", key: "nav.ai" },
  { view: "settings", icon: "gear", key: "nav.settings" },
  { view: "about", icon: "info", key: "nav.about" },
];

function Shell() {
  const app = useApp();
  const { t } = useI18n();
  const scanning = app.scan.status === "running";

  const counts: Partial<Record<View, number>> = {
    findings: app.report?.findings.length ?? 0,
    history: app.history.length,
  };

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="mark">
            <Icon name="shield" size={21} />
          </span>
          <div>
            <h1>{t("app.name")}</h1>
            <p>{t("app.tagline")}</p>
          </div>
        </div>
        {NAV.map((n) => (
          <button
            key={n.view}
            className={`nav-item ${app.view === n.view ? "active" : ""}`}
            onClick={() => app.setView(n.view)}
          >
            <Icon name={n.icon} />
            <span>{t(n.key)}</span>
            {counts[n.view] ? <span className="count">{counts[n.view]}</span> : null}
          </button>
        ))}
        <div className="sidebar-foot">
          v{app.appInfo?.version ?? "0.0.0"} · {app.appInfo?.rules ?? 0} {t("dash.rules")}
        </div>
      </aside>

      <div className="main">
        <div className="topbar">
          <div className="path">
            <Icon name="folder" size={15} />
            <span className="dir" title={app.projectPath ?? ""}>
              {app.projectPath ?? t("topbar.noRepo")}
            </span>
            {app.repo?.isRepo && app.repo.branch ? (
              <span className="chip">
                <span className="dot" />
                {app.repo.branch}
              </span>
            ) : null}
          </div>
          <span className="spacer" />
          {scanning ? (
            <button className="btn danger sm" onClick={() => void app.cancelScan()}>
              <Icon name="stop" size={13} /> {t("topbar.cancel")}
            </button>
          ) : (
            <button
              className="btn primary sm"
              disabled={!app.repo?.isRepo}
              onClick={() => void app.startScan()}
            >
              <Icon name="play" size={13} /> {t("topbar.scan")}
            </button>
          )}
          <div className="row" style={{ gap: 4 }}>
            <button
              className={`icon-btn ${app.settings.language === "en" ? "active" : ""}`}
              title="English"
              onClick={() => app.updateSettings({ language: "en" })}
            >
              <span style={{ fontSize: 11, fontWeight: 700 }}>EN</span>
            </button>
            <button
              className={`icon-btn ${app.settings.language === "fa" ? "active" : ""}`}
              title="فارسی"
              onClick={() => app.updateSettings({ language: "fa" })}
            >
              <span style={{ fontSize: 11, fontWeight: 700 }}>فا</span>
            </button>
            <button
              className="icon-btn"
              title={t("settings.theme")}
              onClick={() =>
                app.updateSettings({ theme: app.settings.theme === "dark" ? "light" : "dark" })
              }
            >
              <Icon name="eye" size={15} />
            </button>
          </div>
        </div>

        <div className="content">
          {app.view === "dashboard" ? <DashboardView /> : null}
          {app.view === "findings" ? <FindingsView /> : null}
          {app.view === "changes" ? <ChangesView /> : null}
          {app.view === "history" ? <HistoryView /> : null}
          {app.view === "ai" ? <AiView /> : null}
          {app.view === "settings" ? <SettingsView /> : null}
          {app.view === "about" ? <AboutView /> : null}
        </div>
      </div>

      <ToastHost />
      <ConfirmHost />
    </div>
  );
}

function Localized() {
  const app = useApp();
  return (
    <I18nProvider lang={app.settings.language}>
      <Shell />
    </I18nProvider>
  );
}

export default function App() {
  return (
    <AppStoreProvider>
      <Localized />
    </AppStoreProvider>
  );
}
