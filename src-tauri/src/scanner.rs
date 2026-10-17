//! Scan orchestration: diff → engines → scoring → optional local AI → history.

use crate::catalog::Catalog;
use crate::engines::{self, ScanCtx};
use crate::error::{AppError, AppResult};
use crate::{gitmod, history, ollama, util};
use crate::models::*;
use globset::{GlobBuilder, GlobSetBuilder};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tauri::{AppHandle, Emitter};

pub const EVENT_PROGRESS: &str = "scan-progress";
pub const EVENT_FINISHED: &str = "scan-finished";
pub const EVENT_FAILED: &str = "scan-failed";

pub fn emit_progress(
    app: &AppHandle,
    scan_id: &str,
    phase: &str,
    percent: u32,
    en: &str,
    fa: &str,
    detail: Option<String>,
) {
    let _ = app.emit(
        EVENT_PROGRESS,
        ScanProgress {
            scan_id: scan_id.to_string(),
            phase: phase.to_string(),
            percent: percent.min(100),
            message_en: en.to_string(),
            message_fa: fa.to_string(),
            detail,
        },
    );
}

/// Runs a full scan. `scan_id` is minted by the caller (`commands::start_scan`)
/// so that progress events, the finished event and the stored report all share
/// one identifier that the frontend can correlate.
pub fn run_scan(
    app: &AppHandle,
    catalog: &Catalog,
    cancel: &AtomicBool,
    scan_id: String,
    options: ScanOptions,
) -> AppResult<ScanReport> {
    let started = Instant::now();
    let started_at = util::now_rfc3339();

    emit_progress(app, &scan_id, "opening", 4, "Opening repository…", "در حال باز کردن مخزن…", None);
    let repo = gitmod::open(&options.project_path)?;
    let repo_info = gitmod::repo_info(&repo, &options.project_path);

    emit_progress(app, &scan_id, "diffing", 12, "Reading Git changes…", "در حال خواندن تغییرات Git…", None);
    let raw = gitmod::build_changes(
        &repo,
        &options.base,
        options.include_untracked,
        options.context_lines,
        options.max_file_bytes,
        None,
    )?;

    emit_progress(app, &scan_id, "filtering", 18, "Filtering files…", "در حال پالایش فایل‌ها…", None);
    let ignore = build_ignore_set(&options.ignore_globs);
    let mut changes: Vec<FileChange> = raw
        .into_iter()
        .filter(|c| !util::is_noise_path(&c.path))
        .filter(|c| match &ignore {
            Some(g) => !g.is_match(&c.path) && !g.is_match(&format!("root/{}", c.path)),
            None => true,
        })
        .collect();
    changes.sort_by(|a, b| a.path.cmp(&b.path));

    let changed_paths: HashSet<String> = changes.iter().map(|c| c.path.clone()).collect();
    let mut ctx = ScanCtx {
        catalog,
        options: &options,
        repo: &repo,
        cancelled: cancel,
        changed_paths,
        file_cache: Default::default(),
        files_scanned: 0,
        bytes_scanned: 0,
        warnings: Vec::new(),
    };

    let enabled: Vec<Engine> = Engine::all()
        .into_iter()
        .filter(|e| options.engines.enabled(*e))
        .collect();

    let mut findings: Vec<Finding> = Vec::new();
    let total = changes.len().max(1);
    for (i, fc) in changes.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            return Err(AppError::Cancelled);
        }
        if i % 25 == 0 {
            let pct = 20 + (60 * i as u32 / total as u32);
            emit_progress(
                app,
                &scan_id,
                "analyzing",
                pct,
                "Analyzing changes…",
                "در حال تحلیل تغییرات…",
                Some(fc.path.clone()),
            );
        }
        ctx.files_scanned += 1;
        for engine in &enabled {
            engines::run_rules(&mut ctx, fc, *engine, &mut findings)?;
        }
    }

    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal))
            .then(a.file.cmp(&b.file))
            .then(a.line.cmp(&b.line))
    });

    // Final privacy pass: whatever engine or heuristic produced a finding, a
    // credential must not reach the UI, the JSON history or an exported report
    // in clear text. `mask_secrets_in` only touches secret-shaped tokens, so
    // ordinary snippets are unchanged and already-masked values stay as they are.
    for f in &mut findings {
        f.snippet = catalog.mask_secrets_in(&f.snippet);
        if let Some(m) = f.matched.take() {
            f.matched = Some(catalog.mask_secrets_in(&m));
        }
    }

    emit_progress(app, &scan_id, "scoring", 84, "Scoring risk…", "در حال امتیازدهی ریسک…", None);
    let summary = summarize(&findings, &ctx, &changes, &enabled, catalog);

    let ai = if options.ai.enabled && !options.ai.model.trim().is_empty() {
        emit_progress(app, &scan_id, "ai", 90, "Consulting local AI model…", "در حال مشورت با مدل هوش مصنوعی محلی…", None);
        Some(ollama::analyze(&options, &changes, &findings, catalog))
    } else {
        None
    };

    let finished_at = util::now_rfc3339();
    // End the ctx borrow of `options` before moving `options` into the report.
    let warnings = std::mem::take(&mut ctx.warnings);
    drop(ctx);
    let report = ScanReport {
        id: scan_id.clone(),
        started_at,
        finished_at,
        duration_ms: started.elapsed().as_millis() as u64,
        project_path: repo_info.path.clone(),
        repo: repo_info,
        options,
        summary,
        files: changes,
        findings,
        ai,
        warnings,
        catalog_version: catalog.version,
    };

    emit_progress(app, &scan_id, "saving", 97, "Saving report…", "در حال ذخیره گزارش…", None);
    if let Err(e) = history::save_report(app, &report) {
        log::warn!("history save failed: {e}");
    }
    emit_progress(app, &scan_id, "done", 100, "Scan complete", "اسکن کامل شد", None);
    Ok(report)
}

fn build_ignore_set(globs: &[String]) -> Option<globset::GlobSet> {
    if globs.is_empty() {
        return None;
    }
    let mut b = GlobSetBuilder::new();
    let mut any = false;
    for g in globs {
        if let Ok(glob) = GlobBuilder::new(g)
            .literal_separator(false)
            .case_insensitive(true)
            .build()
        {
            b.add(glob);
            any = true;
        }
    }
    if !any {
        return None;
    }
    b.build().ok()
}

fn summarize(
    findings: &[Finding],
    ctx: &ScanCtx<'_>,
    changes: &[FileChange],
    enabled: &[Engine],
    catalog: &Catalog,
) -> ScanSummary {
    let mut by_severity: std::collections::BTreeMap<Severity, u32> = Default::default();
    let mut by_category: std::collections::BTreeMap<Category, u32> = Default::default();
    let mut by_engine: std::collections::BTreeMap<Engine, u32> = Default::default();
    for s in Severity::all() {
        by_severity.insert(s, 0);
    }
    for c in Category::all() {
        by_category.insert(c, 0);
    }
    for e in Engine::all() {
        by_engine.insert(e, 0);
    }

    let mut weighted = 0.0f64;
    for f in findings {
        *by_severity.entry(f.severity).or_insert(0) += 1;
        *by_category.entry(f.category).or_insert(0) += 1;
        *by_engine.entry(f.engine).or_insert(0) += 1;
        weighted += f.severity.weight() as f64 * (0.5 + 0.5 * f.confidence.clamp(0.0, 1.0));
    }
    let risk_score = weighted.min(100.0).round() as u32;
    let risk_band = if findings.is_empty() || risk_score == 0 {
        RiskBand::Safe
    } else if risk_score < 15 {
        RiskBand::Low
    } else if risk_score < 40 {
        RiskBand::Elevated
    } else if risk_score < 70 {
        RiskBand::High
    } else {
        RiskBand::Critical
    };
    let verdict = if by_severity[&Severity::Critical] > 0 || risk_score >= 70 {
        Verdict::Block
    } else if by_severity[&Severity::High] > 0 || by_severity[&Severity::Medium] > 0 || risk_score >= 15 {
        Verdict::Review
    } else {
        Verdict::Pass
    };

    let additions: u32 = changes.iter().map(|c| c.additions).sum();
    let deletions: u32 = changes.iter().map(|c| c.deletions).sum();

    ScanSummary {
        stats: ScanStats {
            files_changed: changes.len() as u32,
            files_scanned: ctx.files_scanned,
            files_skipped: changes.iter().filter(|c| c.is_binary || c.too_large).count() as u32,
            additions,
            deletions,
            bytes_scanned: ctx.bytes_scanned,
            rules_active: catalog.len() as u32,
            engines_enabled: enabled.len() as u32,
        },
        by_severity,
        by_category,
        by_engine,
        risk_score,
        risk_band,
        verdict,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};

    /// A throwaway repository under the system temp directory.
    fn temp_repo(tag: &str) -> (PathBuf, git2::Repository) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "agentguard-{tag}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create temp dir");
        let repo = git2::Repository::init(&dir).expect("init repo");
        (dir, repo)
    }

    fn commit(repo: &git2::Repository, files: &[&str], msg: &str) {
        let mut index = repo.index().expect("index");
        for f in files {
            index.add_path(Path::new(f)).expect("add_path");
        }
        index.write().expect("write index");
        let tree_id = index.write_tree().expect("write tree");
        let tree = repo.find_tree(tree_id).expect("find tree");
        let sig =
            git2::Signature::now("AgentGuard Test", "test@agentguard.local").expect("signature");
        let parent = repo
            .head()
            .ok()
            .and_then(|h| h.target())
            .and_then(|id| repo.find_commit(id).ok());
        match parent {
            Some(p) => {
                repo.commit(Some("HEAD"), &sig, &sig, msg, &tree, &[&p])
                    .expect("commit");
            }
            None => {
                repo.commit(Some("HEAD"), &sig, &sig, msg, &tree, &[])
                    .expect("first commit");
            }
        }
    }

    fn options(path: &str) -> ScanOptions {
        ScanOptions {
            project_path: path.to_string(),
            base: ScanBase::WorkingTree,
            include_untracked: true,
            engines: EngineToggles::default(),
            max_file_bytes: 1_000_000,
            ignore_globs: Vec::new(),
            language: Language::En,
            ai: AiOptions::default(),
            context_lines: 3,
        }
    }

    /// The real pipeline (diff -> engines -> scoring) without events or history.
    fn pipeline(
        repo: &git2::Repository,
        dir: &Path,
    ) -> (Vec<FileChange>, Vec<Finding>, ScanSummary) {
        let catalog = Catalog::load().expect("catalog loads");
        let opts = options(&dir.to_string_lossy());
        let changes =
            gitmod::build_changes(repo, &opts.base, true, 3, 1_000_000, None).expect("diff");
        let cancel = AtomicBool::new(false);
        let changed_paths: HashSet<String> = changes.iter().map(|c| c.path.clone()).collect();
        let mut ctx = ScanCtx {
            catalog: &catalog,
            options: &opts,
            repo,
            cancelled: &cancel,
            changed_paths,
            file_cache: Default::default(),
            files_scanned: 0,
            bytes_scanned: 0,
            warnings: Vec::new(),
        };
        let mut findings: Vec<Finding> = Vec::new();
        for fc in &changes {
            ctx.files_scanned += 1;
            for engine in Engine::all() {
                engines::run_rules(&mut ctx, fc, engine, &mut findings).expect("engine run");
            }
        }
        let enabled = Engine::all().to_vec();
        let summary = summarize(&findings, &ctx, &changes, &enabled, &catalog);
        (changes, findings, summary)
    }

    fn rule_ids(findings: &[Finding]) -> Vec<String> {
        findings.iter().map(|f| f.rule_id.clone()).collect()
    }

    /// A realistic (but fake) AWS access key id: matches the AKIA + 16 shape and
    /// is not one of the documented placeholders the catalog filters out.
    const FAKE_AWS_KEY: &str = "AKIAQ7Z3M9P2W8XRT4VB";

    #[test]
    fn flags_leaked_key_and_piped_installer_then_blocks() {
        let (dir, repo) = temp_repo("dirty");
        fs::write(dir.join("app.js"), "console.log('hello');\n").expect("write");
        commit(&repo, &["app.js"], "baseline");

        // An AI-style edit: hardcoded credential + a remote script piped to a shell.
        fs::write(
            dir.join("deploy.js"),
            format!(
                "const AWS_ACCESS_KEY = \"{FAKE_AWS_KEY}\";\nmodule.exports = {{ AWS_ACCESS_KEY }};\n"
            ),
        )
        .expect("write");
        fs::write(
            dir.join("setup.sh"),
            "#!/bin/sh\ncurl -fsSL https://install.getagent.dev/bootstrap | bash\n",
        )
        .expect("write");

        let (changes, findings, summary) = pipeline(&repo, &dir);
        let paths: Vec<&str> = changes.iter().map(|c| c.path.as_str()).collect();
        assert!(
            paths.contains(&"deploy.js") && paths.contains(&"setup.sh"),
            "new files missing from the diff: {paths:?}"
        );

        let aws = findings
            .iter()
            .find(|f| f.rule_id == "SEC-SECRET-AWS-ACCESS-KEY")
            .unwrap_or_else(|| panic!("AWS key rule did not fire; got {:?}", rule_ids(&findings)));
        assert_eq!(aws.severity, Severity::Critical);
        assert!(aws.redactable, "a leaked key must offer redaction");
        assert_eq!(aws.file, "deploy.js");

        // The credential must never appear verbatim in anything we show or store.
        for f in &findings {
            assert!(
                !f.snippet.contains(FAKE_AWS_KEY),
                "rule {} leaked the secret in its snippet: {}",
                f.rule_id,
                f.snippet
            );
            if let Some(m) = &f.matched {
                assert!(
                    !m.contains(FAKE_AWS_KEY),
                    "rule {} leaked the secret in its matched fragment: {m}",
                    f.rule_id
                );
            }
        }
        assert!(
            aws.matched.as_deref().unwrap_or_default().starts_with("AKIA"),
            "the mask should keep a recognizable prefix: {:?}",
            aws.matched
        );

        assert!(
            findings
                .iter()
                .any(|f| f.file == "setup.sh" && f.engine == Engine::Dangerous),
            "curl | bash was not flagged; got {:?}",
            rule_ids(&findings)
        );

        assert_eq!(summary.verdict, Verdict::Block);
        assert!(summary.risk_score >= 40, "risk score too low: {}", summary.risk_score);
        assert!(summary.stats.additions > 0);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn passes_a_clean_documentation_change() {
        let (dir, repo) = temp_repo("clean");
        fs::write(dir.join("README.md"), "# Demo\n\nHello.\n").expect("write");
        commit(&repo, &["README.md"], "baseline");
        fs::write(
            dir.join("README.md"),
            "# Demo\n\nHello world.\n\n## Usage\n\nRun the app.\n",
        )
        .expect("write");

        let (changes, findings, summary) = pipeline(&repo, &dir);
        assert_eq!(changes.len(), 1, "only README.md should be in the diff");
        assert!(
            findings.is_empty(),
            "a clean docs change produced findings: {:?}",
            rule_ids(&findings)
        );
        assert_eq!(summary.verdict, Verdict::Pass);
        assert_eq!(summary.risk_band, RiskBand::Safe);
        assert_eq!(summary.risk_score, 0);

        let _ = fs::remove_dir_all(&dir);
    }
}
