//! Recently opened projects.

use crate::error::AppResult;
use crate::history;
use crate::models::*;
use crate::util;
use std::fs;
use tauri::AppHandle;

const MAX_RECENT: usize = 12;

fn path(app: &AppHandle) -> AppResult<std::path::PathBuf> {
    Ok(history::data_dir(app)?.join("projects.json"))
}

pub fn load(app: &AppHandle) -> Vec<RecentProject> {
    match path(app) {
        Ok(p) => fs::read_to_string(p)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

fn store(app: &AppHandle, list: &Vec<RecentProject>) -> AppResult<()> {
    fs::write(path(app)?, serde_json::to_string_pretty(list)?)?;
    Ok(())
}

fn project_name(path: &str) -> String {
    path.replace('\\', "/")
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or("project")
        .to_string()
}

pub fn remember(app: &AppHandle, path: &str, bump_scans: bool) -> AppResult<Vec<RecentProject>> {
    let mut list = load(app);
    let now = util::now_rfc3339();
    if let Some(entry) = list.iter_mut().find(|p| p.path == path) {
        entry.last_opened = now;
        if bump_scans {
            entry.scan_count += 1;
        }
        // move to front
        let idx = list.iter().position(|p| p.path == path).unwrap();
        let item = list.remove(idx);
        list.insert(0, item);
    } else {
        list.insert(
            0,
            RecentProject {
                path: path.to_string(),
                name: project_name(path),
                last_opened: now,
                scan_count: u32::from(bump_scans),
            },
        );
    }
    list.truncate(MAX_RECENT);
    store(app, &list)?;
    Ok(list)
}

pub fn forget(app: &AppHandle, path: &str) -> AppResult<Vec<RecentProject>> {
    let mut list = load(app);
    list.retain(|p| p.path != path);
    store(app, &list)?;
    Ok(list)
}
