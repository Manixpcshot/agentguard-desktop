import type { Category, ScanSummary, Severity } from "../types";
import { useI18n, type DictKey } from "../i18n";

export const SEV_COLORS: Record<Severity, string> = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
  info: "var(--info)",
};

const SEVS: Severity[] = ["critical", "high", "medium", "low", "info"];
const CATS: Category[] = [
  "secret_leak",
  "dangerous_operation",
  "vulnerability",
  "test_integrity",
  "suspicious_change",
  "supply_chain",
  "ci_cd",
];

export function RiskGauge({ score, band }: { score: number; band: string }) {
  const { t } = useI18n();
  const r = 62;
  const c = 2 * Math.PI * r;
  const frac = Math.max(0, Math.min(100, score)) / 100;
  const color =
    band === "critical"
      ? "var(--critical)"
      : band === "high"
        ? "var(--high)"
        : band === "elevated"
          ? "var(--medium)"
          : band === "low"
            ? "var(--low)"
            : "var(--ok)";
  return (
    <div className="gauge">
      <svg width={148} height={148} viewBox="0 0 148 148">
        <circle cx={74} cy={74} r={r} fill="none" stroke="var(--panel-3)" strokeWidth={11} />
        <circle
          cx={74}
          cy={74}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={11}
          strokeLinecap="round"
          strokeDasharray={`${c * frac} ${c}`}
          transform="rotate(-90 74 74)"
          style={{ transition: "stroke-dasharray .5s ease" }}
        />
      </svg>
      <div className="num">
        <div>
          {score}
          <small className={`band-${band}`}>{t(`band.${band}` as DictKey)}</small>
        </div>
      </div>
    </div>
  );
}

export function SeverityDonut({ summary }: { summary: ScanSummary }) {
  const { t } = useI18n();
  const counts = SEVS.map((s) => summary.bySeverity[s] ?? 0);
  const total = counts.reduce((a, b) => a + b, 0);
  const r = 46;
  const c = 2 * Math.PI * r;
  let offset = 0;
  const segments = SEVS.map((s, i) => {
    const frac = total ? counts[i] / total : 0;
    const seg = (
      <circle
        key={s}
        cx={60}
        cy={60}
        r={r}
        fill="none"
        stroke={SEV_COLORS[s]}
        strokeWidth={14}
        strokeDasharray={`${c * frac} ${c}`}
        strokeDashoffset={-offset * c}
        transform="rotate(-90 60 60)"
      />
    );
    offset += frac;
    return seg;
  });
  return (
    <div className="gauge-wrap">
      <svg width={120} height={120} viewBox="0 0 120 120" style={{ flex: "none" }}>
        <circle cx={60} cy={60} r={r} fill="none" stroke="var(--panel-3)" strokeWidth={14} />
        {total > 0 ? segments : null}
        <text
          x={60}
          y={66}
          textAnchor="middle"
          fill="var(--ink)"
          fontSize={24}
          fontWeight={700}
          fontFamily="inherit"
        >
          {total}
        </text>
      </svg>
      <div className="donut-legend">
        {SEVS.map((s, i) => (
          <div className="li" key={s}>
            <span className="sw" style={{ background: SEV_COLORS[s] }} />
            <span>{t(`severity.${s}` as DictKey)}</span>
            <span className="n">{counts[i]}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function CategoryBars({ summary }: { summary: ScanSummary }) {
  const { t } = useI18n();
  const counts = CATS.map((c) => summary.byCategory[c] ?? 0);
  const max = Math.max(1, ...counts);
  const visible = CATS.map((c, i) => [c, counts[i]] as const).filter(([, n]) => n > 0);
  if (visible.length === 0) {
    return <div className="muted small">{t("findings.empty")}</div>;
  }
  return (
    <div>
      {visible.map(([cat, n]) => (
        <div className="bar-row" key={cat}>
          <span className="nowrap">{t(`category.${cat}` as DictKey)}</span>
          <span className="track">
            <span className="fill" style={{ width: `${(n / max) * 100}%` }} />
          </span>
          <span className="n">{n}</span>
        </div>
      ))}
    </div>
  );
}
