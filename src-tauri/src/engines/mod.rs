//! Analysis engines: a shared regex runner plus specialized heuristics.

pub mod heuristics;

use crate::catalog::{Catalog, CompiledRule};
use crate::error::AppResult;
use crate::gitmod;
use crate::models::*;
use crate::util;
use git2::Repository;
use regex::Regex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

/// Mutable context shared by all engines during one scan.
pub struct ScanCtx<'a> {
    pub catalog: &'a Catalog,
    pub options: &'a ScanOptions,
    pub repo: &'a Repository,
    pub cancelled: &'a AtomicBool,
    pub changed_paths: std::collections::HashSet<String>,
    pub file_cache: HashMap<String, Option<String>>,
    pub files_scanned: u32,
    pub bytes_scanned: u64,
    pub warnings: Vec<String>,
}

impl<'a> ScanCtx<'a> {
    pub fn check_cancel(&self) -> AppResult<()> {
        if self.cancelled.load(Ordering::Relaxed) {
            Err(crate::error::AppError::Cancelled)
        } else {
            Ok(())
        }
    }

    /// Resulting content of a changed file (workdir, or old blob for deletes).
    pub fn file_content(&mut self, fc: &FileChange) -> Option<String> {
        if let Some(c) = self.file_cache.get(&fc.path) {
            return c.clone();
        }
        let content = if fc.status == ChangeStatus::Deleted {
            gitmod::read_old_content(self.repo, fc)
        } else {
            gitmod::read_workdir_file(self.repo, &fc.path)
        };
        if let Some(c) = &content {
            self.bytes_scanned += c.len() as u64;
        }
        self.file_cache.insert(fc.path.clone(), content.clone());
        content
    }
}

/// Runs every active rule of one engine over one changed file.
pub fn run_rules(
    ctx: &mut ScanCtx<'_>,
    fc: &FileChange,
    engine: Engine,
    out: &mut Vec<Finding>,
) -> AppResult<()> {
    if util::is_noise_path(&fc.path) {
        return Ok(());
    }
    let rules: Vec<&CompiledRule> = ctx.catalog.for_engine(engine).collect();
    for cr in rules {
        ctx.check_cancel()?;
        if !cr.path_matches(&fc.path) {
            continue;
        }
        if cr.rule.patterns.is_empty() {
            if let Some(handler) = cr.rule.heuristic.as_deref() {
                heuristics::run(handler, ctx, fc, cr, out)?;
            }
            continue;
        }
        run_regex_rule(ctx, fc, cr, out)?;
    }
    Ok(())
}

fn run_regex_rule(
    ctx: &mut ScanCtx<'_>,
    fc: &FileChange,
    cr: &CompiledRule,
    out: &mut Vec<Finding>,
) -> AppResult<()> {
    if fc.is_binary || fc.too_large {
        return Ok(());
    }
    let candidates: Vec<(u32, String, &'static str)> = match cr.rule.target {
        RuleTarget::Added => fc
            .added_lines()
            .into_iter()
            .map(|(n, t)| (n, t.to_string(), "added"))
            .collect(),
        RuleTarget::Removed => fc
            .removed_lines()
            .into_iter()
            .map(|(n, t)| (n, t.to_string(), "removed"))
            .collect(),
        RuleTarget::Both => fc
            .added_lines()
            .into_iter()
            .map(|(n, t)| (n, t.to_string(), "added"))
            .chain(
                fc.removed_lines()
                    .into_iter()
                    .map(|(n, t)| (n, t.to_string(), "removed")),
            )
            .collect(),
        RuleTarget::File => match ctx.file_content(fc) {
            Some(content) => content
                .lines()
                .enumerate()
                .map(|(i, l)| ((i + 1) as u32, l.to_string(), "file"))
                .collect(),
            None => Vec::new(),
        },
    };

    let mut emitted = 0u32;
    for (line_no, text, side) in candidates {
        if emitted >= 30 {
            break;
        }
        let trimmed = text.trim();
        if trimmed.is_empty() {
            continue;
        }
        if cr.negatives_match(&text) {
            continue;
        }
        let hit = if cr.rule.require_all {
            cr.regexes.iter().all(|r| r.is_match(&text))
        } else {
            cr.regexes.iter().any(|r| r.is_match(&text))
        };
        if !hit {
            continue;
        }
        let matched_text = cr
            .regexes
            .iter()
            .find_map(|r| r.find(&text).map(|m| m.as_str().to_string()))
            .unwrap_or_default();
        let shown = if cr.rule.engine == Engine::Secrets || cr.rule.redactable {
            util::mask_secret(&matched_text)
        } else {
            truncate(&matched_text, 160)
        };
        push_finding(cr, fc, line_no, side, trimmed, Some(shown), None, None, out);
        emitted += 1;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn push_finding(
    cr: &CompiledRule,
    fc: &FileChange,
    line: u32,
    side: &str,
    snippet: &str,
    matched: Option<String>,
    confidence: Option<f64>,
    severity: Option<Severity>,
    out: &mut Vec<Finding>,
) {
    if out.len() >= 2500 {
        return;
    }
    let matched_str = matched.clone().unwrap_or_default();
    let rule = &cr.rule;
    out.push(Finding {
        id: util::finding_id(&rule.id, &fc.path, line, &matched_str),
        rule_id: rule.id.clone(),
        engine: rule.engine,
        category: rule.category,
        severity: severity.unwrap_or(rule.severity),
        confidence: confidence.unwrap_or(rule.confidence),
        file: fc.path.clone(),
        line,
        end_line: None,
        snippet: truncate(snippet, 300),
        matched,
        side: side.to_string(),
        text: rule.text.clone(),
        cwe: rule.cwe.clone(),
        references: rule.references.clone(),
        tags: rule.tags.clone(),
        redactable: rule.redactable,
    });
}

pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

/// Convenience accessor for lazily compiled heuristic regexes.
pub fn rx(pattern: &'static str, slot: &'static std::sync::OnceLock<Regex>) -> &'static Regex {
    slot.get_or_init(|| Regex::new(pattern).expect("static heuristic regex must compile"))
}
