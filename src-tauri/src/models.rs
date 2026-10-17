//! Shared data model for AgentGuard.
//!
//! Every type in this module crosses the FFI boundary between the Rust core and
//! the TypeScript frontend, so all of them are serialized with stable,
//! camelCase field names and lowercase enum tags.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Severity of a finding, ordered from least to most dangerous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Contribution of a single finding of this severity to the risk score.
    pub fn weight(&self) -> u32 {
        match self {
            Severity::Info => 1,
            Severity::Low => 3,
            Severity::Medium => 8,
            Severity::High => 22,
            Severity::Critical => 48,
        }
    }

    pub fn all() -> [Severity; 5] {
        [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ]
    }
}

/// High level grouping of findings used for filters and charts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    SecretLeak,
    DangerousOperation,
    Vulnerability,
    TestIntegrity,
    SuspiciousChange,
    SupplyChain,
    CiCd,
}

impl Category {
    pub fn as_str(&self) -> &'static str {
        match self {
            Category::SecretLeak => "secret_leak",
            Category::DangerousOperation => "dangerous_operation",
            Category::Vulnerability => "vulnerability",
            Category::TestIntegrity => "test_integrity",
            Category::SuspiciousChange => "suspicious_change",
            Category::SupplyChain => "supply_chain",
            Category::CiCd => "ci_cd",
        }
    }

    pub fn all() -> [Category; 7] {
        [
            Category::SecretLeak,
            Category::DangerousOperation,
            Category::Vulnerability,
            Category::TestIntegrity,
            Category::SuspiciousChange,
            Category::SupplyChain,
            Category::CiCd,
        ]
    }
}

/// Analysis engines that can be toggled independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Engine {
    Secrets,
    Dangerous,
    Security,
    Tests,
    Suspicious,
    SupplyChain,
    Cicd,
}

impl Engine {
    pub fn as_str(&self) -> &'static str {
        match self {
            Engine::Secrets => "secrets",
            Engine::Dangerous => "dangerous",
            Engine::Security => "security",
            Engine::Tests => "tests",
            Engine::Suspicious => "suspicious",
            Engine::SupplyChain => "supply_chain",
            Engine::Cicd => "ci_cd",
        }
    }

    pub fn all() -> [Engine; 7] {
        [
            Engine::Secrets,
            Engine::Dangerous,
            Engine::Security,
            Engine::Tests,
            Engine::Suspicious,
            Engine::SupplyChain,
            Engine::Cicd,
        ]
    }
}

/// UI / report language. English is the default and primary language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    #[default]
    En,
    Fa,
}

impl Language {
    pub fn as_str(&self) -> &'static str {
        match self {
            Language::En => "en",
            Language::Fa => "fa",
        }
    }

    pub fn parse(s: &str) -> Language {
        if s.eq_ignore_ascii_case("fa") || s.starts_with("fa-") {
            Language::Fa
        } else {
            Language::En
        }
    }
}

/// Localized pair of strings (English primary, Persian secondary).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct L10n {
    pub en: String,
    pub fa: String,
}

impl L10n {
    pub fn pick(&self, lang: Language) -> &str {
        match lang {
            Language::En => &self.en,
            Language::Fa => &self.fa,
        }
    }
}

/// Fully localized text of a rule/finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleText {
    pub title: L10n,
    pub description: L10n,
    pub remediation: L10n,
}

/// Which side of a diff a regex rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleTarget {
    /// Lines added (or modified into) by the change.
    Added,
    /// Lines removed by the change.
    Removed,
    /// The complete resulting file content.
    File,
    /// Both added and removed lines.
    Both,
}

/// What kind of change happened to a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeStatus {
    Added,
    Modified,
    Deleted,
    Renamed,
    Copied,
    Typechange,
    Untracked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LineKind {
    Added,
    Removed,
    Context,
    Header,
}

/// A single line inside a unified diff hunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffLine {
    pub kind: LineKind,
    pub old_no: Option<u32>,
    pub new_no: Option<u32>,
    pub text: String,
}

/// One `@@ ... @@` block of a unified diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffHunk {
    pub header: String,
    pub lines: Vec<DiffLine>,
}

/// A changed file together with its diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileChange {
    pub path: String,
    pub old_path: Option<String>,
    pub status: ChangeStatus,
    pub is_binary: bool,
    pub too_large: bool,
    pub additions: u32,
    pub deletions: u32,
    /// Executable-bit transitions (used by suspicious-change heuristics).
    pub old_exec: bool,
    pub new_exec: bool,
    pub hunks: Vec<DiffHunk>,
}

impl FileChange {
    pub fn added_lines(&self) -> Vec<(u32, &str)> {
        let mut out = Vec::new();
        for h in &self.hunks {
            for l in &h.lines {
                if l.kind == LineKind::Added {
                    out.push((l.new_no.unwrap_or(0), l.text.as_str()));
                }
            }
        }
        out
    }

    pub fn removed_lines(&self) -> Vec<(u32, &str)> {
        let mut out = Vec::new();
        for h in &self.hunks {
            for l in &h.lines {
                if l.kind == LineKind::Removed {
                    out.push((l.old_no.unwrap_or(0), l.text.as_str()));
                }
            }
        }
        out
    }

    pub fn is_test_file(&self) -> bool {
        let p = self.path.to_lowercase();
        p.contains("/test/")
            || p.contains("/tests/")
            || p.contains("__tests__")
            || p.starts_with("test/")
            || p.starts_with("tests/")
            || p.contains("/spec/")
            || p.ends_with("_test.go")
            || p.ends_with("_test.py")
            || p.ends_with(".test.js")
            || p.ends_with(".test.ts")
            || p.ends_with(".test.jsx")
            || p.ends_with(".test.tsx")
            || p.ends_with(".spec.js")
            || p.ends_with(".spec.ts")
            || p.ends_with(".spec.jsx")
            || p.ends_with(".spec.tsx")
            || p.ends_with("test_.py")
            || p.contains("/testing/")
            || p.ends_with("tests.rs")
            || p.contains("/test_")
    }
}

/// Where the diff is taken from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "camelCase")]
pub enum ScanBase {
    /// HEAD vs working directory (staged + unstaged + optionally untracked).
    WorkingTree,
    /// HEAD vs index (staged changes only).
    Staged,
    /// merge-base(HEAD, branch) vs working directory.
    Branch(String),
    /// A single commit vs its first parent.
    Commit(String),
    /// Arbitrary revision range `from..to`.
    Range { from: String, to: String },
    /// Last N commits vs working directory.
    LastCommits(u32),
}

impl Default for ScanBase {
    fn default() -> Self {
        ScanBase::WorkingTree
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineToggles {
    pub secrets: bool,
    pub dangerous: bool,
    pub security: bool,
    pub tests: bool,
    pub suspicious: bool,
    pub supply_chain: bool,
    pub ci_cd: bool,
}

impl Default for EngineToggles {
    fn default() -> Self {
        Self {
            secrets: true,
            dangerous: true,
            security: true,
            tests: true,
            suspicious: true,
            supply_chain: true,
            ci_cd: true,
        }
    }
}

impl EngineToggles {
    pub fn enabled(&self, e: Engine) -> bool {
        match e {
            Engine::Secrets => self.secrets,
            Engine::Dangerous => self.dangerous,
            Engine::Security => self.security,
            Engine::Tests => self.tests,
            Engine::Suspicious => self.suspicious,
            Engine::SupplyChain => self.supply_chain,
            Engine::Cicd => self.ci_cd,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiOptions {
    pub enabled: bool,
    pub host: String,
    pub model: String,
    /// Maximum number of diff characters sent to the local model.
    pub max_diff_chars: usize,
    pub timeout_secs: u64,
}

impl Default for AiOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            host: "http://127.0.0.1:11434".to_string(),
            model: String::new(),
            max_diff_chars: 24_000,
            timeout_secs: 180,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanOptions {
    pub project_path: String,
    #[serde(default)]
    pub base: ScanBase,
    #[serde(default = "default_true")]
    pub include_untracked: bool,
    #[serde(default)]
    pub engines: EngineToggles,
    #[serde(default = "default_max_file_bytes")]
    pub max_file_bytes: u64,
    #[serde(default)]
    pub ignore_globs: Vec<String>,
    #[serde(default)]
    pub language: Language,
    #[serde(default)]
    pub ai: AiOptions,
    #[serde(default = "default_context_lines")]
    pub context_lines: u32,
}

fn default_true() -> bool {
    true
}
fn default_max_file_bytes() -> u64 {
    1_500_000
}
fn default_context_lines() -> u32 {
    3
}

/// A concrete detection produced by an engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: String,
    pub rule_id: String,
    pub engine: Engine,
    pub category: Category,
    pub severity: Severity,
    /// 0.0 .. 1.0
    pub confidence: f64,
    pub file: String,
    pub line: u32,
    pub end_line: Option<u32>,
    /// The diff line text (secrets masked).
    pub snippet: String,
    /// The matched fragment (secrets masked), if any.
    pub matched: Option<String>,
    /// "added" | "removed" | "file" | "meta"
    pub side: String,
    pub text: RuleText,
    pub cwe: Vec<String>,
    pub references: Vec<String>,
    pub tags: Vec<String>,
    /// Whether the finding supports an automatic, backup-protected redaction.
    pub redactable: bool,
}

impl Finding {
    pub fn title(&self, lang: Language) -> &str {
        self.text.title.pick(lang)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskBand {
    Safe,
    Low,
    Elevated,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Pass,
    Review,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ScanStats {
    pub files_changed: u32,
    pub files_scanned: u32,
    pub files_skipped: u32,
    pub additions: u32,
    pub deletions: u32,
    pub bytes_scanned: u64,
    pub rules_active: u32,
    pub engines_enabled: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ScanSummary {
    pub stats: ScanStats,
    pub by_severity: BTreeMap<Severity, u32>,
    pub by_category: BTreeMap<Category, u32>,
    pub by_engine: BTreeMap<Engine, u32>,
    pub risk_score: u32,
    pub risk_band: RiskBand,
    pub verdict: Verdict,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoInfo {
    pub path: String,
    pub is_repo: bool,
    pub branch: Option<String>,
    pub head_sha: Option<String>,
    pub head_subject: Option<String>,
    pub commit_count: u32,
    pub dirty_files: u32,
    pub untracked_files: u32,
    pub branches: Vec<BranchInfo>,
    pub remotes: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BranchInfo {
    pub name: String,
    pub is_head: bool,
    pub is_remote: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommitInfo {
    pub sha: String,
    pub short_sha: String,
    pub subject: String,
    pub author: String,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AiInsight {
    pub title: String,
    pub detail: String,
    pub severity: Severity,
    pub file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AiAnalysis {
    pub enabled: bool,
    pub available: bool,
    pub model: String,
    pub host: String,
    pub summary: String,
    pub insights: Vec<AiInsight>,
    pub raw: String,
    pub error: Option<String>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanReport {
    pub id: String,
    pub started_at: String,
    pub finished_at: String,
    pub duration_ms: u64,
    pub project_path: String,
    pub repo: RepoInfo,
    pub options: ScanOptions,
    pub summary: ScanSummary,
    pub files: Vec<FileChange>,
    pub findings: Vec<Finding>,
    pub ai: Option<AiAnalysis>,
    pub warnings: Vec<String>,
    pub catalog_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanProgress {
    pub scan_id: String,
    pub phase: String,
    pub percent: u32,
    pub message_en: String,
    pub message_fa: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OllamaModel {
    pub name: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OllamaStatus {
    pub host: String,
    pub available: bool,
    pub version: Option<String>,
    pub models: Vec<OllamaModel>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecentProject {
    pub path: String,
    pub name: String,
    pub last_opened: String,
    pub scan_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryEntry {
    pub id: String,
    pub started_at: String,
    pub project_path: String,
    pub project_name: String,
    pub branch: Option<String>,
    pub base: String,
    pub risk_score: u32,
    pub risk_band: RiskBand,
    pub verdict: Verdict,
    pub findings: u32,
    pub critical: u32,
    pub high: u32,
    pub files_changed: u32,
    pub duration_ms: u64,
    pub language: Language,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestRunRequest {
    pub project_path: String,
    /// Confirmation nonce previously issued by `issue_confirmation`.
    pub confirmation: String,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestRunResult {
    pub runner: String,
    pub command: Vec<String>,
    pub exit_code: Option<i32>,
    pub passed: bool,
    pub output: String,
    pub summary: String,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub name: String,
    pub version: String,
    pub os: String,
    pub arch: String,
    pub data_dir: String,
    pub catalog_version: u32,
    pub rules: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactRequest {
    pub project_path: String,
    pub file: String,
    pub line: u32,
    pub rule_id: String,
    pub finding_id: String,
    pub confirmation: String,
    pub create_backup: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactResult {
    pub file: String,
    pub backup: Option<String>,
    pub replaced: u32,
}
