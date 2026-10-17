//! AgentGuard desktop application entry.

pub mod catalog;
pub mod commands;
pub mod engines;
pub mod error;
pub mod gitmod;
pub mod history;
pub mod models;
pub mod ollama;
pub mod projects;
pub mod report;
pub mod safety;
pub mod scanner;
pub mod settings;
pub mod tests_runner;
pub mod util;

use commands::AppState;
use std::sync::Arc;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let catalog = match catalog::Catalog::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("fatal: rule catalog failed to load: {e}");
            std::process::exit(1);
        }
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(
            tauri_plugin_log::Builder::new()
                .level(log::LevelFilter::Info)
                .max_file_size(2_000_000)
                .build(),
        )
        .manage(AppState {
            catalog: Arc::new(catalog),
            scans: Default::default(),
            confirmations: Default::default(),
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::app_data_dir,
            commands::inspect_repository,
            commands::list_commits,
            commands::get_file_diff,
            commands::start_scan,
            commands::cancel_scan,
            commands::ollama_status,
            commands::run_ai_review,
            commands::export_report,
            commands::save_report_dialog,
            commands::list_history,
            commands::get_history,
            commands::delete_history,
            commands::clear_history,
            commands::get_settings,
            commands::save_settings,
            commands::list_recent_projects,
            commands::remember_project,
            commands::forget_project,
            commands::issue_confirmation,
            commands::detect_test_runner,
            commands::run_tests,
            commands::redact_secret,
        ])
        .run(tauri::generate_context!())
        .expect("error while running AgentGuard");
}
