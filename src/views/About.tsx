import { openUrl } from "@tauri-apps/plugin-opener";
import { Icon } from "../components/ui";
import { useI18n } from "../i18n";
import { useApp } from "../store";

const REPO = "https://github.com/Manixpcshot/agentguard-desktop";

export function AboutView() {
  const app = useApp();
  const { t, lang } = useI18n();
  const info = app.appInfo;

  const rows: [string, string][] = [
    [t("about.version"), info?.version ?? "—"],
    [t("about.rules"), String(info?.rules ?? 0)],
    [t("about.catalog"), `v${info?.catalogVersion ?? 1}`],
    [t("about.license"), "MIT"],
    ["OS", `${info?.os ?? "—"} / ${info?.arch ?? "—"}`],
  ];

  return (
    <div className="content-grid">
      <div>
        <div className="card hero">
          <h2>{t("about.title")}</h2>
          <p>{t("app.tagline")}</p>
        </div>
        <div className="card">
          <div className="card-body" style={{ padding: 0 }}>
            <table className="tbl">
              <tbody>
                {rows.map(([k, v]) => (
                  <tr key={k}>
                    <td className="muted" style={{ width: "40%" }}>{k}</td>
                    <td className="mono">{v}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
        <div className="card">
          <div className="card-body">
            <div className="row">
              <button className="btn sm" onClick={() => void openUrl(REPO)}>
                <Icon name="external" size={13} /> {t("about.repo")}
              </button>
              <button className="btn sm" onClick={() => void openUrl(`${REPO}/blob/main/README.md`)}>
                <Icon name="file" size={13} /> {t("about.docs")}
              </button>
              <button className="btn sm" onClick={() => void openUrl(`${REPO}/issues`)}>
                <Icon name="alert" size={13} /> {t("about.issues")}
              </button>
            </div>
          </div>
        </div>
      </div>
      <div>
        <div className="card">
          <div className="card-head">
            <Icon name="lock" />
            <h3>{t("about.safetyTitle")}</h3>
          </div>
          <div className="card-body">
            <p className="small" style={{ color: "var(--ink-2)" }}>{t("about.safetyBody")}</p>
          </div>
        </div>
        <div className="card">
          <div className="card-head">
            <Icon name="cpu" />
            <h3>{t("about.localTitle")}</h3>
          </div>
          <div className="card-body">
            <p className="small" style={{ color: "var(--ink-2)" }}>{t("about.localBody")}</p>
          </div>
        </div>
        <div className="card">
          <div className="card-head">
            <Icon name="info" />
            <h3>{t("about.bilingualTitle")}</h3>
          </div>
          <div className="card-body">
            <p className="small" style={{ color: "var(--ink-2)" }}>{t("about.bilingualBody")}</p>
            <p className="small muted">
              {lang === "fa"
                ? "زبان پیش‌فرض برنامه انگلیسی است و فارسی به‌صورت کامل پشتیبانی می‌شود."
                : "English is the default language; Persian (فارسی) is fully supported, including RTL layout."}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
