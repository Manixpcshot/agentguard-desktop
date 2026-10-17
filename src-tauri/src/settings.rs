//! User settings persisted as JSON in the app data directory.

use crate::error::AppResult;
use crate::history;
use crate::models::*;
use serde::{Deserialize, Serialize};
use std::fs;
use tauri::AppHandle;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub language: Language,
    /// "dark" | "light" | "system"
    pub theme: String,
    pub engines: EngineToggles,
    pub include_untracked: bool,
    pub max_file_bytes: u64,
    pub ignore_globs: Vec<String>,
    pub context_lines: u32,
    pub ai: AiOptions,
    pub confirm_ttl_secs: u64,
    pub auto_scan_on_open: bool,
    pub last_project: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            language: Language::En,
            theme: "dark".to_string(),
            engines: EngineToggles::default(),
            include_untracked: true,
            max_file_bytes: 1_500_000,
            ignore_globs: Vec::new(),
            context_lines: 3,
            ai: AiOptions::default(),
            confirm_ttl_secs: 300,
            auto_scan_on_open: false,
            last_project: None,
        }
    }
}

fn path(app: &AppHandle) -> AppResult<std::path::PathBuf> {
    Ok(history::data_dir(app)?.join("settings.json"))
}

pub fn load(app: &AppHandle) -> Settings {
    match path(app) {
        Ok(p) => fs::read_to_string(p)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default(),
        Err(_) => Settings::default(),
    }
}

pub fn save(app: &AppHandle, settings: &Settings) -> AppResult<()> {
    let p = path(app)?;
    fs::write(p, serde_json::to_string_pretty(settings)?)?;
    Ok(())
}
