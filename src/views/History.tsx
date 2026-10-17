import { EmptyState, Icon } from "../components/ui";
import { useI18n, type DictKey } from "../i18n";
import { useApp } from "../store";

export function HistoryView() {
  const app = useApp();
  const { t } = useI18n();

  if (app.history.length === 0) {
    return (
      <div className="card">
        <EmptyState icon="clock" title={t("history.empty")} />
      </div>
    );
  }

  return (
    <div className="card">
      <div className="card-head">
        <Icon name="clock" />
        <h3>{t("history.title")}</h3>
        <span className="spacer" />
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
      <div className="card-body" style={{ padding: 0 }}>
        <table className="tbl">
          <thead>
            <tr>
              <th>{t("history.when")}</th>
              <th>{t("history.project")}</th>
              <th>{t("history.base")}</th>
              <th>{t("history.score")}</th>
              <th>{t("history.findings")}</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {app.history.map((h) => (
              <tr key={h.id} className="clickable" onClick={() => void app.openHistory(h.id)}>
                <td className="nowrap muted">{new Date(h.startedAt).toLocaleString()}</td>
                <td>
                  <span className="mono small">{h.projectName}</span>
                  {h.branch ? <span className="chip" style={{ marginInlineStart: 8 }}>{h.branch}</span> : null}
                </td>
                <td className="mono small muted">{h.base}</td>
                <td>
                  <span className={`band-${h.riskBand}`} style={{ fontWeight: 700 }}>
                    {h.riskScore}
                  </span>
                  <span className="muted small" style={{ marginInlineStart: 6 }}>
                    {t(`band.${h.riskBand}` as DictKey)}
                  </span>
                </td>
                <td>
                  {h.critical > 0 ? <span className="badge sev-critical">{h.critical}</span> : null}{" "}
                  {h.high > 0 ? <span className="badge sev-high">{h.high}</span> : null}{" "}
                  <span className="muted small">{h.findings}</span>
                </td>
                <td style={{ textAlign: "end" }}>
                  <button
                    className="icon-btn"
                    style={{ width: 28, height: 28 }}
                    onClick={(e) => {
                      e.stopPropagation();
                      void app.deleteHistory(h.id);
                    }}
                    title={t("history.delete")}
                  >
                    <Icon name="trash" size={13} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
