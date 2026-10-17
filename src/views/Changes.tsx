import { useMemo } from "react";
import { EmptyState, Icon } from "../components/ui";
import { useI18n } from "../i18n";
import { useApp } from "../store";
import type { ChangeStatus, FileChange } from "../types";

const STATUS_LETTER: Record<ChangeStatus, string> = {
  added: "+",
  untracked: "+",
  modified: "~",
  deleted: "−",
  renamed: "→",
  copied: "=",
  typechange: "t",
};

export function ChangesView() {
  const app = useApp();
  const { t } = useI18n();
  const files = app.report?.files ?? [];
  const selectedPath = app.selectedFile && files.some((f) => f.path === app.selectedFile)
    ? app.selectedFile
    : files[0]?.path ?? null;
  const fc = files.find((f) => f.path === selectedPath) ?? null;

  const marks = useMemo(() => {
    const m = new Map<string, Set<number>>();
    for (const f of app.report?.findings ?? []) {
      let set = m.get(f.file);
      if (!set) {
        set = new Set();
        m.set(f.file, set);
      }
      if (f.line) set.add(f.line);
    }
    return m;
  }, [app.report]);

  if (files.length === 0) {
    return (
      <div className="card">
        <EmptyState icon="diff" title={t("changes.empty")} />
      </div>
    );
  }

  return (
    <div className="diff-shell">
      <div className="card file-list">
        {files.map((f) => (
          <button
            key={f.path}
            className={`file-item ${f.path === selectedPath ? "sel" : ""}`}
            onClick={() => app.selectFile(f.path)}
            title={f.path}
          >
            <span className={`st ${f.status}`}>{STATUS_LETTER[f.status]}</span>
            <span className="p">{f.path}</span>
            <span className="nums">
              <span className="a">+{f.additions}</span> <span className="d">−{f.deletions}</span>
            </span>
            {(marks.get(f.path)?.size ?? 0) > 0 ? (
              <span className="badge sev-high">{marks.get(f.path)?.size}</span>
            ) : null}
          </button>
        ))}
      </div>
      <div>{fc ? <DiffPane fc={fc} marked={marks.get(fc.path)} /> : null}</div>
    </div>
  );
}

function DiffPane({ fc, marked }: { fc: FileChange; marked?: Set<number> }) {
  const { t } = useI18n();
  if (fc.isBinary) {
    return (
      <div className="card">
        <EmptyState icon="file" title={t("changes.binary")} hint={fc.path} />
      </div>
    );
  }
  if (fc.tooLarge) {
    return (
      <div className="card">
        <EmptyState icon="file" title={t("changes.tooLarge")} hint={fc.path} />
      </div>
    );
  }
  if (fc.hunks.length === 0) {
    return (
      <div className="card">
        <EmptyState icon="diff" title={fc.path} hint={t("changes.empty")} />
      </div>
    );
  }
  return (
    <div className="diff">
      <div className="dline header">
        <span style={{ padding: "6px 12px" }}>
          {fc.oldPath && fc.oldPath !== fc.path ? `${fc.oldPath} → ${fc.path}` : fc.path}
        </span>
      </div>
      {fc.hunks.map((h, hi) => (
        <div key={hi}>
          <div className="dline header">
            <span style={{ padding: "4px 12px" }}>{h.header}</span>
          </div>
          {h.lines.map((l, li) => {
            const lineNo = l.kind === "removed" ? l.oldNo : l.newNo;
            const isMarked = !!lineNo && !!marked?.has(lineNo);
            return (
              <div key={li} className={`dline ${l.kind} ${isMarked ? "mark" : ""}`}>
                <span className="no">{l.oldNo ?? ""}</span>
                <span className="no">{l.newNo ?? ""}</span>
                <span className="sg">{l.kind === "added" ? "+" : l.kind === "removed" ? "-" : " "}</span>
                <span className="tx">{l.text || " "}</span>
              </div>
            );
          })}
        </div>
      ))}
      <div className="dline header">
        <span style={{ padding: "6px 12px", display: "flex", gap: 8, alignItems: "center" }}>
          <Icon name="alert" size={13} />
          {marked?.size ?? 0}
        </span>
      </div>
    </div>
  );
}
