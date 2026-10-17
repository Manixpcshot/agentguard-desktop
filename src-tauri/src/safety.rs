//! Safety gate.
//!
//! AgentGuard never modifies user files or runs commands unless the user
//! explicitly confirmed the exact action in the UI. Confirmation works as a
//! short-lived nonce: the UI asks for one (`issue_confirmation`), shows what
//! will happen, and only then calls the mutating command with the nonce. The
//! backend verifies action name and expiry, so a stray or replayed call is
//! rejected.

use crate::error::{AppError, AppResult};
use crate::util;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub const ACTION_REDACT: &str = "redact-secret";
pub const ACTION_RUN_TESTS: &str = "run-tests";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Confirmation {
    pub token: String,
    pub action: String,
    pub detail: String,
    pub issued_at: String,
    pub expires_at: i64,
}

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn issue(action: &str, detail: &str, ttl_secs: u64) -> Confirmation {
    Confirmation {
        token: uuid::Uuid::new_v4().to_string(),
        action: action.to_string(),
        detail: detail.to_string(),
        issued_at: util::now_rfc3339(),
        expires_at: now_epoch() + ttl_secs.max(15) as i64,
    }
}

/// Validates and consumes a confirmation nonce.
pub fn consume(
    store: &mut HashMap<String, Confirmation>,
    token: &str,
    action: &str,
) -> AppResult<()> {
    let conf = store
        .remove(token)
        .ok_or_else(|| AppError::ConfirmationRequired("no confirmation issued for this action".into()))?;
    if conf.action != action {
        return Err(AppError::ConfirmationRequired(format!(
            "confirmation was issued for {:?}, not {action:?}",
            conf.action
        )));
    }
    if now_epoch() > conf.expires_at {
        return Err(AppError::ConfirmationRequired("confirmation expired".into()));
    }
    Ok(())
}

/// Rejects path arguments that could escape the project directory.
pub fn validate_relative_path(rel: &str) -> AppResult<()> {
    let p = std::path::Path::new(rel);
    if p.is_absolute() {
        return Err(AppError::User("path must be relative to the project".into()));
    }
    for comp in p.components() {
        if matches!(comp, std::path::Component::ParentDir) {
            return Err(AppError::User("path must not contain '..'".into()));
        }
    }
    Ok(())
}
