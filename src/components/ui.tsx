import { useEffect, type ReactNode } from "react";
import { useApp } from "../store";
import { useI18n } from "../i18n";

export type IconName =
  | "shield" | "scan" | "alert" | "diff" | "clock" | "sparkles" | "gear" | "info"
  | "folder" | "branch" | "play" | "stop" | "check" | "download" | "copy" | "trash"
  | "refresh" | "external" | "search" | "lock" | "cpu" | "file" | "terminal" | "eye"
  | "x" | "chevron";

const PATHS: Record<IconName, ReactNode> = {
  shield: <path d="M12 3l7 3v5.2c0 4.4-2.9 7.6-7 9.3-4.1-1.7-7-4.9-7-9.3V6l7-3z" />,
  scan: (
    <>
      <path d="M4 9V6a2 2 0 0 1 2-2h3M15 4h3a2 2 0 0 1 2 2v3M20 15v3a2 2 0 0 1-2 2h-3M9 20H6a2 2 0 0 1-2-2v-3" />
      <path d="M7.5 12h9" />
    </>
  ),
  alert: (
    <>
      <path d="M12 4.5l8.5 15h-17l8.5-15z" />
      <path d="M12 10.5v4M12 17.4h.01" />
    </>
  ),
  diff: (
    <>
      <circle cx="6.5" cy="6.5" r="2.4" />
      <circle cx="17.5" cy="17.5" r="2.4" />
      <path d="M6.5 9v6a3 3 0 0 0 3 3h5.5M17.5 15V9a3 3 0 0 0-3-3H9" />
    </>
  ),
  clock: (
    <>
      <circle cx="12" cy="12" r="8" />
      <path d="M12 7.8v4.4l3 2" />
    </>
  ),
  sparkles: (
    <>
      <path d="M12 4l1.6 4.1L17.8 9.7l-4.2 1.6L12 15.5l-1.6-4.2-4.2-1.6 4.2-1.6L12 4z" />
      <path d="M18.6 15.4l.7 1.8 1.8.7-1.8.7-.7 1.8-.7-1.8-1.8-.7 1.8-.7.7-1.8z" />
    </>
  ),
  gear: (
    <>
      <circle cx="12" cy="12" r="3.1" />
      <path d="M12 2.8v2.6M12 18.6v2.6M2.8 12h2.6M18.6 12h2.6M5.2 5.2l1.9 1.9M16.9 16.9l1.9 1.9M18.8 5.2l-1.9 1.9M7.1 16.9l-1.9 1.9" />
    </>
  ),
  info: (
    <>
      <circle cx="12" cy="12" r="8.2" />
      <path d="M12 11v5.2M12 7.6h.01" />
    </>
  ),
  folder: <path d="M3.5 7a2 2 0 0 1 2-2h4l2 2.2h7a2 2 0 0 1 2 2V17a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2V7z" />,
  branch: (
    <>
      <circle cx="6.5" cy="6" r="2.3" />
      <circle cx="6.5" cy="18" r="2.3" />
      <circle cx="17.5" cy="8" r="2.3" />
      <path d="M6.5 8.4v7.2M17.5 10.4c0 4-4.2 4.6-8.6 4.6" />
    </>
  ),
  play: <path d="M8.5 5.5l10 6.5-10 6.5v-13z" />,
  stop: <path d="M6.5 6.5l11 11M17.5 6.5l-11 11" />,
  check: <path d="M5 12.8l4.2 4.2L19 7.4" />,
  download: <path d="M12 4v10.5M8 11l4 4 4-4M4.5 19.5h15" />,
  copy: (
    <>
      <rect x="9" y="9" width="11" height="11" rx="2" />
      <path d="M5.5 14.5V6a2 2 0 0 1 2-2H16" />
    </>
  ),
  trash: <path d="M4.5 7h15M9.5 7V5.2a1.2 1.2 0 0 1 1.2-1.2h2.6a1.2 1.2 0 0 1 1.2 1.2V7M6.5 7l1 12.5h9l1-12.5M10 11v5M14 11v5" />,
  refresh: <path d="M19.5 12a7.5 7.5 0 1 1-2.2-5.3M19.8 4.2v4.2h-4.2" />,
  external: <path d="M14 4.5h5.5V10M19.5 4.5L11 13M17.5 13.5v4a2 2 0 0 1-2 2h-9a2 2 0 0 1-2-2v-9a2 2 0 0 1 2-2h4" />,
  search: (
    <>
      <circle cx="11" cy="11" r="6" />
      <path d="M19.8 19.8l-4.3-4.3" />
    </>
  ),
  lock: (
    <>
      <rect x="5" y="10.8" width="14" height="9" rx="2" />
      <path d="M8.2 10.8V8a3.8 3.8 0 0 1 7.6 0v2.8" />
    </>
  ),
  cpu: (
    <>
      <rect x="7" y="7" width="10" height="10" rx="2" />
      <path d="M10 2.8v2.6M14 2.8v2.6M10 18.6v2.6M14 18.6v2.6M2.8 10h2.6M2.8 14h2.6M18.6 10h2.6M18.6 14h2.6" />
    </>
  ),
  file: <path d="M6.5 3.5h7l4 4v13h-11v-17zM13.5 3.5v4h4" />,
  terminal: <path d="M5 16.5l5.5-4.5L5 7.5M12.5 18.5h7" />,
  eye: (
    <>
      <path d="M2.5 12S6 6.2 12 6.2 21.5 12 21.5 12 18 17.8 12 17.8 2.5 12 2.5 12z" />
      <circle cx="12" cy="12" r="2.6" />
    </>
  ),
  x: <path d="M6.5 6.5l11 11M17.5 6.5l-11 11" />,
  chevron: <path d="M8 10l4 4 4-4" />,
};

export function Icon({ name, size = 17 }: { name: IconName; size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.7}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {PATHS[name]}
    </svg>
  );
}

export function Toggle({
  checked,
  onChange,
  label,
  disabled,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label?: ReactNode;
  disabled?: boolean;
}) {
  return (
    <label className="switch" style={disabled ? { opacity: 0.5 } : undefined}>
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span className="track" />
      {label ? <span>{label}</span> : null}
    </label>
  );
}

export function Modal({
  title,
  children,
  footer,
  onClose,
  wide,
}: {
  title: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  onClose: () => void;
  wide?: boolean;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="overlay" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" style={wide ? { width: "min(860px, calc(100vw - 40px))" } : undefined}>
        <div className="mhead">{title}</div>
        <div className="mbody">{children}</div>
        {footer ? <div className="mfoot">{footer}</div> : null}
      </div>
    </div>
  );
}

export function ToastHost() {
  const { toasts, dismissToast } = useApp();
  return (
    <div className="toasts">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`toast ${t.kind}`}
          role="status"
          onClick={() => dismissToast(t.id)}
        >
          {t.text}
        </div>
      ))}
    </div>
  );
}

export function ConfirmHost() {
  const { confirm, closeConfirm } = useApp();
  const { t } = useI18n();
  if (!confirm) return null;
  return (
    <Modal
      title={confirm.title}
      onClose={closeConfirm}
      footer={
        <>
          <button className="btn ghost" onClick={closeConfirm}>
            {t("common.cancel")}
          </button>
          <button
            className={`btn ${confirm.danger ? "danger" : "primary"}`}
            onClick={() => {
              const fn = confirm.onConfirm;
              closeConfirm();
              void Promise.resolve(fn());
            }}
          >
            {confirm.confirmLabel}
          </button>
        </>
      }
    >
      <div style={{ whiteSpace: "pre-wrap" }}>{confirm.body}</div>
    </Modal>
  );
}

export function EmptyState({
  icon,
  title,
  hint,
  action,
}: {
  icon: IconName;
  title: string;
  hint?: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty">
      <div className="big">
        <Icon name={icon} size={40} />
      </div>
      <h3>{title}</h3>
      {hint ? <p>{hint}</p> : null}
      {action ? <div className="row" style={{ justifyContent: "center", marginTop: 16 }}>{action}</div> : null}
    </div>
  );
}
