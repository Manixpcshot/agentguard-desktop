import { useState } from "react";
import { CategoryBars, RiskGauge, SeverityDonut } from "../components/charts";
import { EmptyState, Icon, Toggle } from "../components/ui";
import { useI18n, type DictKey } from "../i18n";
import { useApp } from "../store";
import type { ScanBase } from "../types";

import { ALL_ENGINES, ENGINE_DESC, ENGINE_LABEL, ENGINE_TOGGLE_KEY } from "../labels";

function PhaseText({ phase }: { phase: string }) {
  const { t } = useI18n();
  const key = `scan.phase.${phase}` as DictKey;
  return <span>{t(key) ?? phase}</span>;
}

export function DashboardView() {
  const app = useApp();
  const { t } = useI18n();
  const [lastN, setLastN] = useState(5);
  const [commitRef, setCommitRef] = useState("HEAD");
  const [branchRef, setBranchRef] = useState("");

  const repo = app.repo;
  const scanning = app.scan.status === "running";

  const setBase = (base: ScanBase) => app.setScanConfig({ base });

  return (
    <>
      <div className="card hero">
        <h2>{t("dash.title")}</h2>
        <p>{t("dash.subtitle")}</p>
      </div>

      {!app.projectPath ? (
        <>
          <div className="card">
            <div className="card-body center" style={{ padding: 34 }}>
              <button className="btn primary" onClick={() => void app.chooseProject()}>
                <Icon name="folder" /> {t("dash.chooseFolder")}
              </button>
              <p className="muted small mt">{t("dash.chooseFolderHint")}</p>
            </div>
          </div>
          <RecentProjects />
        </>
      ) : (
        <div className="content-grid">
          <div>
            <div className="card">
              <div className="card-head">
                <Icon name="branch" />
                <h3>{repo?.isRepo ? repo.branch ?? "—" : t("dash.repoNotGit")}</h3>
                <span className="spacer" />
                <button className="btn ghost sm" onClick={() => void app.chooseProject()}>
                  <Icon name="folder" size={14} /> {t("topbar.chooseProject")}
                </button>
              </div>
              <div className="card-body">
                {repo && !repo.isRepo ? (
                  <p className="muted">{t("dash.repoNotGitHint")}</p>
                ) : (
                  <div className="stat-grid">
                    <Stat k={t("dash.commits")} v={String(repo?.commitCount ?? 0)} />
                    <Stat k={t("dash.dirty")} v={String(repo?.dirtyFiles ?? 0)} />
                    <Stat k={t("dash.untracked")} v={String(repo?.untrackedFiles ?? 0)} />
                    <Stat
                      k={t("dash.rules")}
                      v={String(app.appInfo?.rules ?? 0)}
                      s={`catalog v${app.appInfo?.catalogVersion ?? 1}`}
                    />
                  </div>
                )}
              </div>
            </div>

            <div className="card">
              <div className="card-head">
                <Icon name="scan" />
                <h3>{t("dash.base")}</h3>
              </div>
              <div className="card-body">
                <label className="field">
                  <span>{t("dash.base")}</span>
                  <select
                    value={app.scanConfig.base.kind}
                    onChange={(e) => {
                      const kind = e.target.value;
                      if (kind === "workingTree") setBase({ kind: "workingTree" });
                      else if (kind === "staged") setBase({ kind: "staged" });
                      else if (kind === "branch") setBase({ kind: "branch", value: branchRef || "main" });
                      else if (kind === "commit") setBase({ kind: "commit", value: commitRef });
                      else setBase({ kind: "lastCommits", value: lastN });
                    }}
                  >
                    <option value="workingTree">{t("dash.baseWorking")}</option>
                    <option value="staged">{t("dash.baseStaged")}</option>
                    <option value="branch">{t("dash.baseBranch")}</option>
                    <option value="commit">{t("dash.baseCommit")}</option>
                    <option value="lastCommits">{t("dash.baseLast")}</option>
                  </select>
                </label>
                {app.scanConfig.base.kind === "branch" ? (
                  <label className="field">
                    <span>{t("dash.pickBranch")}</span>
                    <select
                      value={branchRef}
                      onChange={(e) => {
                        setBranchRef(e.target.value);
                        setBase({ kind: "branch", value: e.target.value });
                      }}
                    >
                      <option value="">…</option>
                      {(repo?.branches ?? [])
                        .filter((b) => !b.isRemote)
                        .map((b) => (
                          <option key={b.name} value={b.name}>
                            {b.name}
                          </option>
                        ))}
                    </select>
                  </label>
                ) : null}
                {app.scanConfig.base.kind === "commit" ? (
                  <label className="field">
                    <span>{t("dash.pickCommit")}</span>
                    <input
                      type="text"
                      className="mono"
                      value={commitRef}
                      placeholder="HEAD"
                      onChange={(e) => {
                        setCommitRef(e.target.value);
                        setBase({ kind: "commit", value: e.target.value });
                      }}
                    />
                  </label>
                ) : null}
                {app.scanConfig.base.kind === "lastCommits" ? (
                  <label className="field">
                    <span>{t("dash.lastN")}</span>
                    <input
                      type="number"
                      min={1}
                      max={200}
                      value={lastN}
                      onChange={(e) => {
                        const n = Number(e.target.value || 1);
                        setLastN(n);
                        setBase({ kind: "lastCommits", value: n });
                      }}
                    />
                  </label>
                ) : null}
                <Toggle
                  checked={app.scanConfig.includeUntracked}
                  onChange={(v) => app.setScanConfig({ includeUntracked: v })}
                  label={t("dash.includeUntracked")}
                />
              </div>
            </div>

            <div className="card">
              <div className="card-head">
                <Icon name="cpu" />
                <h3>{t("dash.engines")}</h3>
              </div>
              <div className="card-body">
                <div className="grid-2">
                  {ALL_ENGINES.map((e) => (
                    <div className="engine-row" key={e}>
                      <Toggle
                        checked={app.scanConfig.engines[ENGINE_TOGGLE_KEY[e]]}
                        onChange={(v) =>
                          app.setScanConfig({
                            engines: { ...app.scanConfig.engines, [ENGINE_TOGGLE_KEY[e]]: v },
                          })
                        }
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
              <div className="card-body">
                {scanning ? (
                  <>
                    <div className="progress">
                      <div className="fill" style={{ width: `${app.scan.percent}%` }} />
                    </div>
                    <div className="scan-line">
                      <span className="spin" />
                      <PhaseText phase={app.scan.phase} />
                      <span className="mono grow">{app.scan.detail ?? ""}</span>
                      <button className="btn ghost sm" onClick={() => void app.cancelScan()}>
                        <Icon name="stop" size={13} /> {t("topbar.cancel")}
                      </button>
                    </div>
                  </>
                ) : (
                  <button
                    className="btn primary block"
                    disabled={!repo?.isRepo}
                    onClick={() => void app.startScan()}
                  >
                    <Icon name="play" /> {app.report ? t("dash.rescan") : t("dash.startScan")}
                  </button>
                )}
                {app.scan.status === "error" && app.scan.error ? (
                  <p className="small" style={{ color: "var(--critical)", marginTop: 10 }}>
                    {app.scan.error}
                  </p>
                ) : null}
              </div>
            </div>

            {app.report ? (
              <div className="card">
                <div className="card-head">
                  <Icon name="shield" />
                  <h3>{t("summary.risk")}</h3>
                  <span className="spacer" />
                  <span className={`badge sev-${verdictSev(app.report.summary.verdict)}`}>
                    {t(`verdict.${app.report.summary.verdict}` as DictKey)}
                  </span>
                </div>
                <div className="card-body">
                  <div className="gauge-wrap">
                    <RiskGauge score={app.report.summary.riskScore} band={app.report.summary.riskBand} />
                    <div className="stat-grid" style={{ gridTemplateColumns: "1fr 1fr" }}>
                      <Stat k={t("summary.findings")} v={String(app.report.findings.length)} />
                      <Stat k={t("summary.files")} v={String(app.report.summary.stats.filesChanged)} />
                      <Stat k={t("summary.additions")} v={`+${app.report.summary.stats.additions}`} />
                      <Stat k={t("summary.deletions")} v={`−${app.report.summary.stats.deletions}`} />
                    </div>
                  </div>
                  <div className="mt">
                    <SeverityDonut summary={app.report.summary} />
                  </div>
                  <h4 className="muted" style={{ margin: "16px 0 8px", fontSize: 12 }}>
                    {t("summary.byCategory")}
                  </h4>
                  <CategoryBars summary={app.report.summary} />
                  <div className="row mt">
                    <button className="btn sm" onClick={() => app.setView("findings")}>
                      <Icon name="alert" size={14} /> {t("nav.findings")}
                    </button>
                    <button className="btn sm" onClick={() => app.setView("changes")}>
                      <Icon name="diff" size={14} /> {t("nav.changes")}
                    </button>
                  </div>
                </div>
              </div>
            ) : null}

            <RecentProjects compact />
          </div>
        </div>
      )}
    </>
  );
}

function verdictSev(v: string): string {
  return v === "block" ? "critical" : v === "review" ? "medium" : "low";
}

function Stat({ k, v, s }: { k: string; v: string; s?: string }) {
  return (
    <div className="stat">
      <div className="k">{k}</div>
      <div className="v">{v}</div>
      {s ? <div className="s">{s}</div> : null}
    </div>
  );
}

function RecentProjects({ compact }: { compact?: boolean }) {
  const app = useApp();
  const { t } = useI18n();
  if (app.recent.length === 0) {
    if (compact) return null;
    return (
      <div className="card">
        <div className="card-body">
          <EmptyState icon="clock" title={t("dash.noRecent")} />
        </div>
      </div>
    );
  }
  return (
    <div className="card">
      <div className="card-head">
        <Icon name="clock" />
        <h3>{t("dash.recent")}</h3>
      </div>
      <div className="card-body" style={{ padding: 8 }}>
        {app.recent.slice(0, compact ? 4 : 8).map((p) => (
          <div className="file-item" key={p.path} onClick={() => void app.openProject(p.path)}>
            <Icon name="folder" size={15} />
            <span className="p" title={p.path}>
              {p.path}
            </span>
            <span className="nums">{p.scanCount}×</span>
            <button
              className="icon-btn"
              style={{ width: 26, height: 26 }}
              title={t("common.delete")}
              onClick={(e) => {
                e.stopPropagation();
                void app.forgetProject(p.path);
              }}
            >
              <Icon name="x" size={13} />
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
