//! Persistent scan history stored as JSON under the app data directory.

use crate::error::{AppError, AppResult};
use crate::models::*;
use std::fs;
use std::path::PathBuf;
use tauri::{AppHandle, Manager};

const MAX_ENTRIES: usize = 100;

pub fn data_dir(app: &AppHandle) -> AppResult<PathBuf> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| AppError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn history_dir(app: &AppHandle) -> AppResult<PathBuf> {
    let dir = data_dir(app)?.join("history");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn index_path(app: &AppHandle) -> AppResult<PathBuf> {
    Ok(history_dir(app)?.join("index.json"))
}

fn entry_from(report: &ScanReport) -> HistoryEntry {
    HistoryEntry {
        id: report.id.clone(),
        started_at: report.started_at.clone(),
        project_path: report.project_path.clone(),
        project_name: report
            .project_path
            .replace('\\', "/")
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or("project")
            .to_string(),
        branch: report.repo.branch.clone(),
        base: base_label(&report.options.base),
        risk_score: report.summary.risk_score,
        risk_band: report.summary.risk_band,
        verdict: report.summary.verdict,
        findings: report.findings.len() as u32,
        critical: report
            .summary
            .by_severity
            .get(&Severity::Critical)
            .copied()
            .unwrap_or(0),
        high: report
            .summary
            .by_severity
            .get(&Severity::High)
            .copied()
            .unwrap_or(0),
        files_changed: report.summary.stats.files_changed,
        duration_ms: report.duration_ms,
        language: report.options.language,
    }
}

pub fn base_label(base: &ScanBase) -> String {
    match base {
        ScanBase::WorkingTree => "working-tree".into(),
        ScanBase::Staged => "staged".into(),
        ScanBase::Branch(b) => format!("branch:{b}"),
        ScanBase::Commit(c) => format!("commit:{c}"),
        ScanBase::Range { from, to } => format!("{from}..{to}"),
        ScanBase::LastCommits(n) => format!("last:{n}"),
    }
}

pub fn save_report(app: &AppHandle, report: &ScanReport) -> AppResult<()> {
    let dir = history_dir(app)?;
    let file = dir.join(format!("{}.json", report.id));
    fs::write(&file, serde_json::to_string_pretty(report)?)?;

    let mut index = load_index(app);
    index.retain(|e| e.id != report.id);
    index.insert(0, entry_from(report));
    index.truncate(MAX_ENTRIES);
    fs::write(index_path(app)?, serde_json::to_string_pretty(&index)?)?;

    // prune orphaned report files
    for entry in fs::read_dir(&dir)?.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".json") || name == "index.json" {
            continue;
        }
        let id = name.trim_end_matches(".json");
        if !index.iter().any(|e| e.id == id) {
            let _ = fs::remove_file(entry.path());
        }
    }
    Ok(())
}

pub fn load_index(app: &AppHandle) -> Vec<HistoryEntry> {
    match index_path(app) {
        Ok(p) => fs::read_to_string(p)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

pub fn list(app: &AppHandle) -> Vec<HistoryEntry> {
    load_index(app)
}

pub fn get(app: &AppHandle, id: &str) -> AppResult<ScanReport> {
    if !id.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        return Err(AppError::User("invalid history id".into()));
    }
    let path = history_dir(app)?.join(format!("{id}.json"));
    let raw = fs::read_to_string(&path)
        .map_err(|_| AppError::User(format!("history entry not found: {id}")))?;
    Ok(serde_json::from_str(&raw)?)
}

pub fn delete(app: &AppHandle, id: &str) -> AppResult<()> {
    let dir = history_dir(app)?;
    let _ = fs::remove_file(dir.join(format!("{id}.json")));
    let mut index = load_index(app);
    index.retain(|e| e.id != id);
    fs::write(index_path(app)?, serde_json::to_string_pretty(&index)?)?;
    Ok(())
}

pub fn clear(app: &AppHandle) -> AppResult<()> {
    let dir = history_dir(app)?;
    for entry in fs::read_dir(&dir)?.flatten() {
        if entry.file_name().to_string_lossy().ends_with(".json") {
            let _ = fs::remove_file(entry.path());
        }
    }
    Ok(())
}
