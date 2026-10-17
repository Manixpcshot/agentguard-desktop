//! Tauri command surface (the API used by the React frontend).

use crate::catalog::Catalog;
use crate::error::{AppError, AppResult};
use crate::models::*;
use crate::safety::{self, Confirmation, ACTION_REDACT, ACTION_RUN_TESTS};
use crate::settings::Settings;
use crate::tests_runner::TestRunnerInfo;
use crate::{gitmod, history, ollama, projects, report, safety as gate, scanner, settings, tests_runner, util};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;

pub struct AppState {
    pub catalog: Arc<Catalog>,
    pub scans: Mutex<HashMap<String, Arc<AtomicBool>>>,
    pub confirmations: Mutex<HashMap<String, Confirmation>>,
}

#[tauri::command]
pub fn app_info(state: State<'_, AppState>) -> AppInfo {
    AppInfo {
        name: "AgentGuard".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        data_dir: String::new(),
        catalog_version: state.catalog.version,
        rules: state.catalog.len() as u32,
    }
}

#[tauri::command]
pub fn app_data_dir(app: AppHandle) -> String {
    history::data_dir(&app)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default()
}

#[tauri::command]
pub fn inspect_repository(path: String) -> RepoInfo {
    match gitmod::open(&path) {
        Ok(repo) => gitmod::repo_info(&repo, &path),
        Err(e) => RepoInfo {
            path,
            is_repo: false,
            branch: None,
            head_sha: None,
            head_subject: None,
            commit_count: 0,
            dirty_files: 0,
            untracked_files: 0,
            branches: Vec::new(),
            remotes: Vec::new(),
            error: Some(e.to_string()),
        },
    }
}

#[tauri::command]
pub fn list_commits(path: String, refname: Option<String>, limit: usize) -> AppResult<Vec<CommitInfo>> {
    let repo = gitmod::open(&path)?;
    gitmod::list_commits(&repo, refname.as_deref(), limit.clamp(1, 500))
}

#[tauri::command]
pub fn get_file_diff(path: String, base: ScanBase, file: String) -> AppResult<Option<FileChange>> {
    let repo = gitmod::open(&path)?;
    let mut changes = gitmod::build_changes(&repo, &base, true, 6, 4_000_000, Some(&file))?;
    Ok(changes.drain(..).next())
}

#[tauri::command]
pub fn start_scan(
    app: AppHandle,
    state: State<'_, AppState>,
    options: ScanOptions,
) -> Result<String, AppError> {
    let scan_id = uuid::Uuid::new_v4().to_string();
    let cancel = Arc::new(AtomicBool::new(false));
    state
        .scans
        .lock()
        .unwrap()
        .insert(scan_id.clone(), cancel.clone());

    let catalog = state.catalog.clone();
    let sid = scan_id.clone();
    let project = options.project_path.clone();

    tauri::async_runtime::spawn(async move {
        let app_inner = app.clone();
        let outcome = tauri::async_runtime::spawn_blocking(move || {
            scanner::run_scan(&app_inner, &catalog, &cancel, options)
        })
        .await;

        match outcome {
            Ok(Ok(mut report)) => {
                report.id = sid.clone();
                let _ = projects::remember(&app, &project, true);
                let _ = app.emit(
                    scanner::EVENT_FINISHED,
                    serde_json::json!({ "scanId": sid, "report": report }),
                );
            }
            Ok(Err(e)) => {
                let _ = app.emit(
                    scanner::EVENT_FAILED,
                    serde_json::json!({ "scanId": sid, "error": e }),
                );
            }
            Err(e) => {
                let _ = app.emit(
                    scanner::EVENT_FAILED,
                    serde_json::json!({
                        "scanId": sid,
                        "error": { "code": "internal", "message": e.to_string() }
                    }),
                );
            }
        }
    });

    Ok(scan_id)
}

#[tauri::command]
pub fn cancel_scan(state: State<'_, AppState>, scan_id: String) -> bool {
    if let Some(flag) = state.scans.lock().unwrap().get(&scan_id) {
        flag.store(true, std::sync::atomic::Ordering::Relaxed);
        true
    } else {
        false
    }
}

#[tauri::command]
pub fn ollama_status(host: String) -> OllamaStatus {
    match ollama::OllamaClient::new(&host, std::time::Duration::from_secs(5)) {
        Ok(client) => client.status(),
        Err(e) => OllamaStatus {
            host,
            available: false,
            version: None,
            models: Vec::new(),
            error: Some(e),
        },
    }
}

#[tauri::command]
pub fn run_ai_review(options: ScanOptions, findings: Vec<Finding>) -> AiAnalysis {
    let project = options.project_path.clone();
    let repo = match gitmod::open(&project) {
        Ok(r) => r,
        Err(e) => {
            return AiAnalysis {
                enabled: true,
                available: false,
                model: options.ai.model.clone(),
                host: options.ai.host.clone(),
                error: Some(e.to_string()),
                ..Default::default()
            }
        }
    };
    let changes = gitmod::build_changes(&repo, &options.base, false, 1, options.max_file_bytes, None)
        .unwrap_or_default();
    ollama::analyze(&options, &changes, &findings)
}

#[tauri::command]
pub fn export_report(report: ScanReport, format: String, dest: String) -> AppResult<String> {
    if !report::validate_dest(&dest) {
        return Err(AppError::User("invalid destination path".into()));
    }
    let content = report::export(&report, &format);
    fs::write(&dest, content)?;
    Ok(dest)
}

#[tauri::command]
pub fn save_report_dialog(app: AppHandle, report: ScanReport, format: String) -> AppResult<Option<String>> {
    let ext = report::extension_for(&format);
    let default_name = report::default_file_name(&report, &format);
    let picked = app
        .dialog()
        .file()
        .set_title("Save AgentGuard report")
        .set_file_name(default_name)
        .add_filter("report", &[ext])
        .blocking_save_file();
    match picked {
        Some(file_path) => {
            let path = file_path
                .into_path()
                .map_err(|e| AppError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
            let content = report::export(&report, &format);
            fs::write(&path, content)?;
            Ok(Some(path.to_string_lossy().to_string()))
        }
        None => Ok(None),
    }
}

#[tauri::command]
pub fn list_history(app: AppHandle) -> Vec<HistoryEntry> {
    history::list(&app)
}

#[tauri::command]
pub fn get_history(app: AppHandle, id: String) -> AppResult<ScanReport> {
    history::get(&app, &id)
}

#[tauri::command]
pub fn delete_history(app: AppHandle, id: String) -> AppResult<()> {
    history::delete(&app, &id)
}

#[tauri::command]
pub fn clear_history(app: AppHandle) -> AppResult<()> {
    history::clear(&app)
}

#[tauri::command]
pub fn get_settings(app: AppHandle) -> Settings {
    settings::load(&app)
}

#[tauri::command]
pub fn save_settings(app: AppHandle, settings: Settings) -> AppResult<()> {
    settings::save(&app, &settings)
}

#[tauri::command]
pub fn list_recent_projects(app: AppHandle) -> Vec<RecentProject> {
    projects::load(&app)
}

#[tauri::command]
pub fn remember_project(app: AppHandle, path: String) -> AppResult<Vec<RecentProject>> {
    projects::remember(&app, &path, false)
}

#[tauri::command]
pub fn forget_project(app: AppHandle, path: String) -> AppResult<Vec<RecentProject>> {
    projects::forget(&app, &path)
}

#[tauri::command]
pub fn issue_confirmation(state: State<'_, AppState>, action: String, detail: String) -> Confirmation {
    let conf = gate::issue(&action, &detail, 300);
    state
        .confirmations
        .lock()
        .unwrap()
        .insert(conf.token.clone(), conf.clone());
    conf
}

#[tauri::command]
pub fn detect_test_runner(path: String) -> Option<TestRunnerInfo> {
    tests_runner::detect(&path)
}

#[tauri::command]
pub async fn run_tests(state: State<'_, AppState>, request: TestRunRequest) -> AppResult<TestRunResult> {
    safety::consume(
        &mut state.confirmations.lock().unwrap(),
        &request.confirmation,
        ACTION_RUN_TESTS,
    )?;
    let info = tests_runner::detect(&request.project_path)
        .ok_or_else(|| AppError::User("no supported test runner detected".into()))?;
    Ok(tests_runner::run(&request.project_path, &info, request.timeout_secs).await)
}

#[tauri::command]
pub fn redact_secret(state: State<'_, AppState>, request: RedactRequest) -> AppResult<RedactResult> {
    safety::consume(
        &mut state.confirmations.lock().unwrap(),
        &request.confirmation,
        ACTION_REDACT,
    )?;
    gate::validate_relative_path(&request.file)?;
    let full = Path::new(&request.project_path).join(&request.file);
    if !full.is_file() {
        return Err(AppError::User(format!("file not found: {}", request.file)));
    }
    let content = fs::read_to_string(&full)
        .map_err(|_| AppError::User("file is not valid UTF-8 text; cannot redact safely".into()))?;

    let mut lines: Vec<String> = content.split('\n').map(|s| s.to_string()).collect();
    let idx = (request.line as usize).saturating_sub(1);
    if idx >= lines.len() {
        return Err(AppError::User("line number out of range".into()));
    }

    let rule = state
        .catalog
        .find(&request.rule_id)
        .ok_or_else(|| AppError::User(format!("unknown rule: {}", request.rule_id)))?;
    let fallback = regex::Regex::new(r"[A-Za-z0-9+/=_\-]{16,}").unwrap();
    let line = lines[idx].clone();
    let span = rule
        .regexes
        .iter()
        .find_map(|r| r.find(&line))
        .or_else(|| fallback.find(&line));
    let m = span.ok_or_else(|| AppError::User("no secret-like match on that line anymore".into()))?;

    let placeholder = "<redacted-by-AgentGuard>";
    let replaced_line = format!("{}{placeholder}{}", &line[..m.start()], &line[m.end()..]);
    lines[idx] = replaced_line;

    let backup = if request.create_backup {
        let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        let name = util::file_name(&request.file);
        let backup_path = full.with_file_name(format!("{name}.agentguard-backup-{stamp}"));
        fs::write(&backup_path, &content)?;
        Some(backup_path.to_string_lossy().to_string())
    } else {
        None
    };

    fs::write(&full, lines.join("\n"))?;
    Ok(RedactResult {
        file: request.file,
        backup,
        replaced: 1,
    })
}
