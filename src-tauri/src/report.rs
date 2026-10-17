//! Report exporters: JSON, Markdown and standalone HTML (bilingual).

use crate::models::*;
use std::path::Path;

pub fn export(report: &ScanReport, format: &str) -> String {
    match format {
        "json" => serde_json::to_string_pretty(report).unwrap_or_default(),
        "html" => html(report),
        _ => markdown(report),
    }
}

pub fn extension_for(format: &str) -> &'static str {
    match format {
        "json" => "json",
        "html" => "html",
        _ => "md",
    }
}

fn lang(report: &ScanReport) -> Language {
    report.options.language
}

fn severity_label(s: Severity, lang: Language) -> &'static str {
    match (s, lang) {
        (Severity::Critical, Language::En) => "CRITICAL",
        (Severity::Critical, Language::Fa) => "بحرانی",
        (Severity::High, Language::En) => "HIGH",
        (Severity::High, Language::Fa) => "زیاد",
        (Severity::Medium, Language::En) => "MEDIUM",
        (Severity::Medium, Language::Fa) => "متوسط",
        (Severity::Low, Language::En) => "LOW",
        (Severity::Low, Language::Fa) => "کم",
        (Severity::Info, Language::En) => "INFO",
        (Severity::Info, Language::Fa) => "اطلاعاتی",
    }
}

fn t(en: &str, fa: &str, lang: Language) -> &str {
    match lang {
        Language::En => en,
        Language::Fa => fa,
    }
}

pub fn markdown(report: &ScanReport) -> String {
    let lang = lang(report);
    let mut s = String::new();
    let dir = if lang == Language::Fa { " (RTL)" } else { "" };
    s.push_str(&format!(
        "# AgentGuard — {}{dir}\n\n",
        t("Security review report", "گزارش بازبینی امنیتی", lang)
    ));
    s.push_str(&format!(
        "- {}: `{}`\n",
        t("Project", "پروژه", lang),
        report.project_path
    ));
    if let Some(b) = &report.repo.branch {
        s.push_str(&format!("- {}: `{b}`\n", t("Branch", "شاخه", lang)));
    }
    s.push_str(&format!(
        "- {}: {} → {}\n",
        t("Window", "بازه", lang),
        report.started_at,
        report.finished_at
    ));
    s.push_str(&format!(
        "- {}: **{}** ({})\n",
        t("Risk score", "امتیاز ریسک", lang),
        report.summary.risk_score,
        match (report.summary.risk_band, lang) {
            (RiskBand::Safe, Language::En) => "Safe",
            (RiskBand::Safe, Language::Fa) => "امن",
            (RiskBand::Low, Language::En) => "Low",
            (RiskBand::Low, Language::Fa) => "کم",
            (RiskBand::Elevated, Language::En) => "Elevated",
            (RiskBand::Elevated, Language::Fa) => "بالا",
            (RiskBand::High, Language::En) => "High",
            (RiskBand::High, Language::Fa) => "زیاد",
            (RiskBand::Critical, Language::En) => "Critical",
            (RiskBand::Critical, Language::Fa) => "بحرانی",
        }
    ));
    s.push_str(&format!(
        "- {}: {}\n",
        t("Verdict", "حکم", lang),
        match (report.summary.verdict, lang) {
            (Verdict::Pass, Language::En) => "PASS",
            (Verdict::Pass, Language::Fa) => "قبول",
            (Verdict::Review, Language::En) => "REVIEW REQUIRED",
            (Verdict::Review, Language::Fa) => "نیازمند بازبینی",
            (Verdict::Block, Language::En) => "BLOCK",
            (Verdict::Block, Language::Fa) => "مسدود",
        }
    ));
    s.push_str(&format!(
        "- {}: {} {} / {} {} ({} {})\n",
        t("Changes", "تغییرات", lang),
        report.summary.stats.files_changed,
        t("files", "فایل", lang),
        report.summary.stats.additions,
        t("added lines", "سطر افزوده", lang),
        report.summary.stats.deletions,
        t("removed", "حذف‌شده", lang)
    ));
    s.push_str(&format!(
        "- {}: {}\n\n",
        t("Findings", "یافته‌ها", lang),
        report.findings.len()
    ));

    // severity table
    s.push_str(&format!("## {}\n\n", t("Findings by severity", "یافته‌ها بر اساس شدت", lang)));
    s.push_str(&format!(
        "| {} | {} |\n|---|---|\n",
        t("Severity", "شدت", lang),
        t("Count", "تعداد", lang)
    ));
    for sev in Severity::all() {
        let n = report.summary.by_severity.get(&sev).copied().unwrap_or(0);
        s.push_str(&format!("| {} | {n} |\n", severity_label(sev, lang)));
    }
    s.push('\n');

    if !report.findings.is_empty() {
        s.push_str(&format!("## {}\n\n", t("Detailed findings", "یافته‌های با جزئیات", lang)));
        for (i, f) in report.findings.iter().enumerate() {
            let loc = if f.line > 0 {
                format!(":{} ", f.line)
            } else {
                String::new()
            };
            s.push_str(&format!(
                "### {}. [{}] {} — `{}`{loc}\n\n",
                i + 1,
                severity_label(f.severity, lang),
                f.text.title.pick(lang),
                f.file
            ));
            s.push_str(&format!("{}\n\n", f.text.description.pick(lang)));
            if !f.snippet.is_empty() {
                s.push_str(&format!("```\n{}\n```\n\n", f.snippet));
            }
            s.push_str(&format!(
                "**{}:** {}\n\n",
                t("Remediation", "اصلاح", lang),
                f.text.remediation.pick(lang)
            ));
            let mut meta = Vec::new();
            meta.push(format!("`{}`", f.rule_id));
            if !f.cwe.is_empty() {
                meta.push(f.cwe.join(", "));
            }
            meta.push(format!(
                "{} {:.0}%",
                t("confidence", "اطمینان", lang),
                f.confidence * 100.0
            ));
            s.push_str(&format!("> {}\n\n", meta.join(" · ")));
            for r in &f.references {
                s.push_str(&format!("> <{r}>\n"));
            }
            if !f.references.is_empty() {
                s.push('\n');
            }
        }
    } else {
        s.push_str(&format!(
            "_{}_\n\n",
            t(
                "No findings. The reviewed changes look clean.",
                "یافته‌ای نیست. تغییرات بازبینی‌شده پاک به نظر می‌رسند.",
                lang
            )
        ));
    }

    if let Some(ai) = &report.ai {
        s.push_str(&format!("## {}\n\n", t("Local AI review (Ollama)", "بازبینی هوش مصنوعی محلی (Ollama)", lang)));
        if let Some(err) = &ai.error {
            s.push_str(&format!(
                "_{}:_ `{err}`\n\n",
                t("AI unavailable", "هوش مصنوعی در دسترس نیست", lang)
            ));
        } else {
            s.push_str(&format!("{}\n\n", ai.summary));
            for ins in &ai.insights {
                s.push_str(&format!(
                    "- **[{}] {}**{}\n  {}\n",
                    severity_label(ins.severity, lang),
                    ins.title,
                    ai.file_ref(ins),
                    ins.detail
                ));
            }
        }
    }

    s.push_str(&format!(
        "\n---\n_AgentGuard v{} · {} {} · {} {}_\n",
        env!("CARGO_PKG_VERSION"),
        t("rules", "قانون", lang),
        report.catalog_version,
        t("generated", "تولیدشده در", lang),
        report.finished_at
    ));
    s
}

trait FileRef {
    fn file_ref(&self, ins: &AiInsight) -> String;
}
impl FileRef for AiAnalysis {
    fn file_ref(&self, ins: &AiInsight) -> String {
        match &ins.file {
            Some(f) if !f.is_empty() => format!(" — `{f}`"),
            _ => String::new(),
        }
    }
}

pub fn html(report: &ScanReport) -> String {
    let lang = lang(report);
    let dir = if lang == Language::Fa { "rtl" } else { "ltr" };
    let mut body = String::new();

    body.push_str(&format!(
        "<header><div class=\"brand\"><span class=\"logo\">🛡</span><div><h1>AgentGuard</h1><p>{}</p></div></div>\
        <div class=\"score {}\"><span class=\"num\">{}</span><span class=\"lbl\">{}</span></div></header>",
        t("Security review report", "گزارش بازبینی امنیتی", lang),
        band_class(report.summary.risk_band),
        report.summary.risk_score,
        t("risk score", "امتیاز ریسک", lang)
    ));

    body.push_str("<section class=\"meta\"><table><tbody>");
    body.push_str(&format!(
        "<tr><th>{}</th><td><code>{}</code></td><th>{}</th><td>{}</td></tr>",
        t("Project", "پروژه", lang),
        esc(&report.project_path),
        t("Branch", "شاخه", lang),
        esc(report.repo.branch.as_deref().unwrap_or("—"))
    ));
    body.push_str(&format!(
        "<tr><th>{}</th><td>{}</td><th>{}</th><td>{} {} / {} {}</td></tr>",
        t("Scanned", "اسکن‌شده", lang),
        report.finished_at,
        t("Changes", "تغییرات", lang),
        report.summary.stats.files_changed,
        t("files", "فایل", lang),
        report.summary.stats.additions,
        t("added", "افزوده", lang)
    ));
    body.push_str("</tbody></table></section>");

    body.push_str(&format!("<h2>{}</h2><div class=\"chips\">", t("Findings by severity", "یافته‌ها بر اساس شدت", lang)));
    for sev in Severity::all() {
        let n = report.summary.by_severity.get(&sev).copied().unwrap_or(0);
        body.push_str(&format!(
            "<span class=\"chip sev-{}\">{} <b>{n}</b></span>",
            sev.as_str(),
            severity_label(sev, lang)
        ));
    }
    body.push_str("</div>");

    if report.findings.is_empty() {
        body.push_str(&format!(
            "<p class=\"clean\">✅ {}</p>",
            t(
                "No findings. The reviewed changes look clean.",
                "یافته‌ای نیست. تغییرات بازبینی‌شده پاک به نظر می‌رسند.",
                lang
            )
        ));
    } else {
        body.push_str(&format!("<h2>{}</h2>", t("Detailed findings", "یافته‌های با جزئیات", lang)));
        for f in &report.findings {
            let loc = if f.line > 0 { format!(":{}", f.line) } else { String::new() };
            body.push_str(&format!(
                "<article class=\"finding sev-{}\"><div class=\"fhead\"><span class=\"badge\">{}</span>\
                <span class=\"ftitle\">{}</span><code class=\"fpath\">{}{}</code></div>\
                <p class=\"fdesc\">{}</p>",
                f.severity.as_str(),
                severity_label(f.severity, lang),
                esc(f.text.title.pick(lang)),
                esc(&f.file),
                loc,
                esc(f.text.description.pick(lang))
            ));
            if !f.snippet.is_empty() {
                body.push_str(&format!("<pre>{}</pre>", esc(&f.snippet)));
            }
            body.push_str(&format!(
                "<p class=\"fix\"><b>{}:</b> {}</p>",
                t("Remediation", "اصلاح", lang),
                esc(f.text.remediation.pick(lang))
            ));
            body.push_str(&format!(
                "<p class=\"meta-line\"><code>{}</code> · {} {:.0}%{}</p></article>",
                f.rule_id,
                t("confidence", "اطمینان", lang),
                f.confidence * 100.0,
                if f.cwe.is_empty() {
                    String::new()
                } else {
                    format!(" · {}", f.cwe.join(", "))
                }
            ));
        }
    }

    if let Some(ai) = &report.ai {
        body.push_str(&format!(
            "<h2>{}</h2>",
            t("Local AI review (Ollama)", "بازبینی هوش مصنوعی محلی (Ollama)", lang)
        ));
        match &ai.error {
            Some(e) => body.push_str(&format!("<p class=\"warn\">{}: <code>{}</code></p>", t("AI unavailable", "هوش مصنوعی در دسترس نیست", lang), esc(e))),
            None => {
                body.push_str(&format!("<p>{}</p>", esc(&ai.summary)));
                body.push_str("<ul>");
                for ins in &ai.insights {
                    body.push_str(&format!(
                        "<li><b>[{}]</b> {}{}<br><span class=\"fdesc\">{}</span></li>",
                        severity_label(ins.severity, lang),
                        esc(&ins.title),
                        ai.file_ref(ins),
                        esc(&ins.detail)
                    ));
                }
                body.push_str("</ul>");
            }
        }
    }

    body.push_str(&format!(
        "<footer>AgentGuard v{} · {} {} · {} {}</footer>",
        env!("CARGO_PKG_VERSION"),
        t("rules catalog", "فهرست قوانین", lang),
        report.catalog_version,
        t("generated", "تولیدشده در", lang),
        report.finished_at
    ));

    format!(
        "<!doctype html><html lang=\"{}\" dir=\"{dir}\"><head><meta charset=\"utf-8\">\
        <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
        <title>AgentGuard report</title><style>{CSS}</style></head><body>{body}</body></html>",
        lang.as_str()
    )
}

fn band_class(b: RiskBand) -> &'static str {
    match b {
        RiskBand::Safe => "band-safe",
        RiskBand::Low => "band-low",
        RiskBand::Elevated => "band-elevated",
        RiskBand::High => "band-high",
        RiskBand::Critical => "band-critical",
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '-',
            _ => c,
        })
        .collect()
}

pub fn default_file_name(report: &ScanReport, format: &str) -> String {
    let name = report
        .project_path
        .replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or("project")
        .to_string();
    format!(
        "agentguard-{}-{}.{}",
        sanitize_filename(&name),
        &report.id[..8.min(report.id.len())],
        extension_for(format)
    )
}

pub fn validate_dest(dest: &str) -> bool {
    let p = Path::new(dest);
    p.is_absolute() && dest.contains('.')
}

const CSS: &str = r#"
:root{--bg:#0b1020;--panel:#131a30;--ink:#e8ecf8;--mut:#93a0bd;--line:#243052;
--critical:#ff4d6d;--high:#ff9f43;--medium:#ffd166;--low:#4cc9f0;--info:#8d99ae;--ok:#2dd4a7}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.65 "Segoe UI",Vazirmatn,Tahoma,system-ui,sans-serif;padding:32px 40px 60px}
h1{font-size:22px;margin:0}h2{font-size:17px;margin:34px 0 12px;border-bottom:1px solid var(--line);padding-bottom:8px}
header{display:flex;justify-content:space-between;align-items:center;gap:24px}
.brand{display:flex;gap:14px;align-items:center}.logo{font-size:34px}
.brand p{margin:2px 0 0;color:var(--mut)}
.score{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:14px 22px;text-align:center}
.score .num{display:block;font-size:34px;font-weight:700}
.score .lbl{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.08em}
.band-safe .num{color:var(--ok)}.band-low .num{color:var(--low)}.band-elevated .num{color:var(--medium)}
.band-high .num{color:var(--high)}.band-critical .num{color:var(--critical)}
.meta table{width:100%;border-collapse:collapse;margin-top:22px;background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
.meta th,.meta td{padding:10px 14px;text-align:start;border-bottom:1px solid var(--line);font-size:14px}
.meta th{color:var(--mut);font-weight:600;white-space:nowrap;width:1%}
code{background:#0e1428;border:1px solid var(--line);border-radius:6px;padding:1px 6px;font-size:12.5px}
.chips{display:flex;gap:10px;flex-wrap:wrap}
.chip{border-radius:999px;padding:6px 14px;font-size:13px;background:var(--panel);border:1px solid var(--line)}
.chip b{margin-inline-start:6px}
.sev-critical .badge,.chip.sev-critical{border-color:var(--critical);color:var(--critical)}
.sev-high .badge,.chip.sev-high{border-color:var(--high);color:var(--high)}
.sev-medium .badge,.chip.sev-medium{border-color:var(--medium);color:var(--medium)}
.sev-low .badge,.chip.sev-low{border-color:var(--low);color:var(--low)}
.sev-info .badge,.chip.sev-info{border-color:var(--info);color:var(--info)}
.finding{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin:12px 0}
.fhead{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.badge{border:1px solid;border-radius:6px;padding:2px 8px;font-size:11px;font-weight:700;letter-spacing:.06em}
.ftitle{font-weight:600}.fpath{color:var(--mut)}
.fdesc{color:#c6cfe4;margin:10px 0 6px}
pre{background:#0a0f1f;border:1px solid var(--line);border-radius:8px;padding:10px 12px;overflow:auto;font-size:12.5px}
.fix{margin:8px 0 4px}.meta-line{color:var(--mut);font-size:12.5px;margin:6px 0 0}
.clean{background:rgba(45,212,167,.08);border:1px solid var(--ok);border-radius:12px;padding:14px 18px}
.warn{background:rgba(255,159,67,.08);border:1px solid var(--high);border-radius:12px;padding:12px 16px}
footer{margin-top:40px;color:var(--mut);font-size:12.5px;border-top:1px solid var(--line);padding-top:14px}
"#;
