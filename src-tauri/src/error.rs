//! Error type shared by all commands. Serialized as `{ code, message }` so the
//! frontend can show a localized, actionable message.

use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("git error: {0}")]
    Git(#[from] git2::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("not a git repository: {0}")]
    NotARepo(String),

    #[error("rule catalog error: {0}")]
    Catalog(String),

    #[error("invalid input: {0}")]
    User(String),

    #[error("scan cancelled")]
    Cancelled,

    #[error("network error: {0}")]
    Http(String),

    #[error("confirmation required: {0}")]
    ConfirmationRequired(String),
}

impl AppError {
    pub fn code(&self) -> &'static str {
        match self {
            AppError::Git(_) => "git",
            AppError::Io(_) => "io",
            AppError::Json(_) => "json",
            AppError::NotARepo(_) => "not_a_repo",
            AppError::Catalog(_) => "catalog",
            AppError::User(_) => "user",
            AppError::Cancelled => "cancelled",
            AppError::Http(_) => "http",
            AppError::ConfirmationRequired(_) => "confirmation_required",
        }
    }
}

impl Serialize for AppError {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("AppError", 2)?;
        s.serialize_field("code", self.code())?;
        s.serialize_field("message", &self.to_string())?;
        s.end()
    }
}

pub type AppResult<T> = Result<T, AppError>;
