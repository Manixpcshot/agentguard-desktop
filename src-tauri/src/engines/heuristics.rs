//! Heuristic detections that need more context than a single regex line match.

use super::{push_finding, rx, truncate, ScanCtx};
use crate::catalog::CompiledRule;
use crate::error::AppResult;
use crate::models::*;
use crate::util;
use regex::Regex;
use std::collections::HashSet;
use std::sync::OnceLock;

static RE_ASSIGN_TOKEN: OnceLock<Regex> = OnceLock::new();
static RE_BARE_TOKEN: OnceLock<Regex> = OnceLock::new();
static RE_KEYWORD: OnceLock<Regex> = OnceLock::new();
static RE_BASE64_BLOB: OnceLock<Regex> = OnceLock::new();
static RE_HEX_BLOB: OnceLock<Regex> = OnceLock::new();
static RE_ASSERT: OnceLock<Regex> = OnceLock::new();
static RE_PKG_DEP: OnceLock<Regex> = OnceLock::new();
static RE_REQ_DEP: OnceLock<Regex> = OnceLock::new();
static RE_TOML_DEP: OnceLock<Regex> = OnceLock::new();
static RE_INSTALL_SCRIPT: OnceLock<Regex> = OnceLock::new();
static RE_CI_TEST: OnceLock<Regex> = OnceLock::new();
static RE_COVERAGE: OnceLock<Regex> = OnceLock::new();
static RE_GITIGNORE_SENSITIVE: OnceLock<Regex> = OnceLock::new();
static RE_SECRETS_REF: OnceLock<Regex> = OnceLock::new();

const ZERO_WIDTH: [char; 16] = [
    '\u{200b}', '\u{200c}', '\u{200d}', '\u{200e}', '\u{200f}', '\u{2060}', '\u{2061}', '\u{2062}',
    '\u{2063}', '\u{2064}', '\u{feff}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}',
];

const SUSPICIOUS_BINARY_EXT: &[&str] = &[
    "exe", "dll", "so", "dylib", "com", "scr", "bin", "msi", "msix", "jar", "war", "pyc", "pyd",
    "class", "wasm", "zip", "tar", "gz", "bz2", "7z", "rar", "iso", "img", "vhd", "psd", "pdb",
];

const MEDIA_EXT: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "svg", "ico", "bmp", "avif", "mp3", "wav", "ogg", "mp4",
    "webm", "mov", "woff", "woff2", "ttf", "otf", "eot", "pdf",
];

const ALLOWED_HIDDEN: &[&str] = &[
    ".gitignore",
    ".gitattributes",
    ".gitkeep",
    ".gitmodules",
    ".editorconfig",
    ".dockerignore",
    ".npmignore",
    ".nvmrc",
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.dist",
    ".prettierrc",
    ".prettierrc.json",
    ".prettierrc.js",
    ".prettierignore",
    ".eslintrc",
    ".eslintrc.js",
    ".eslintrc.cjs",
    ".eslintrc.json",
    ".eslintrc.yml",
    ".eslintignore",
    ".babelrc",
    ".mailmap",
    ".watchmanconfig",
    ".tool-versions",
    ".python-version",
    ".node-version",
    ".ruby-version",
    ".git-blame-ignore-revs",
    ".codespellrc",
    ".vscode",
    ".github",
];

const GUARD_PATH_MARKERS: &[&str] = &[
    ".pre-commit-config.yaml",
    ".gitleaks.toml",
    ".gitleaksignore",
    ".secretlintrc.json",
    ".trivyignore",
    ".bandit",
    ".semgrep.yaml",
    ".semgrepignore",
    ".safety-policy.yml",
];

const MANIFESTS: &[&str] = &[
    "package.json",
    "Cargo.toml",
    "requirements.txt",
    "pyproject.toml",
    "go.mod",
    "composer.json",
    "Gemfile",
];

const NON_DEP_KEYS: &[&str] = &[
    "name", "version", "description", "keywords", "homepage", "bugs", "license", "author",
    "main", "module", "types", "typings", "type", "private", "sideEffects", "engines", "os",
    "cpu", "workspaces", "packageManager", "volta", "publishConfig", "repository", "funding",
    "files", "man", "directories", "config", "browserslist",
];

const POPULAR_NPM: &[&str] = &[
    "react", "react-dom", "vue", "angular", "svelte", "express", "fastify", "koa", "next", "nuxt",
    "vite", "webpack", "rollup", "esbuild", "typescript", "eslint", "prettier", "jest", "vitest",
    "mocha", "chai", "axios", "lodash", "underscore", "ramda", "moment", "dayjs", "date-fns",
    "uuid", "nanoid", "dotenv", "commander", "yargs", "chalk", "inquirer", "ora", "socket.io",
    "jquery", "bootstrap", "tailwindcss", "postcss", "autoprefixer", "rxjs", "zustand", "redux",
];

const POPULAR_PY: &[&str] = &[
    "requests", "urllib3", "numpy", "pandas", "scipy", "django", "flask", "fastapi", "pydantic",
    "sqlalchemy", "celery", "redis", "pytest", "setuptools", "six", "pyyaml", "cryptography",
    "boto3", "botocore", "torch", "tensorflow", "scikit-learn", "matplotlib", "seaborn", "black",
    "mypy", "flake8", "pylint", "httpx", "aiohttp", "tqdm", "rich", "pillow", "opencv-python",
    "python-dotenv", "jinja2", "werkzeug", "gunicorn", "uvicorn", "starlette", "marshmallow",
    "attrs", "click", "pytz", "certifi", "idna", "charset-normalizer",
];

/// Dispatch table for catalog `heuristic` handlers.
pub fn run(
    name: &str,
    ctx: &mut ScanCtx<'_>,
    fc: &FileChange,
    cr: &CompiledRule,
    out: &mut Vec<Finding>,
) -> AppResult<()> {
    match name {
        "high_entropy_assignment" => high_entropy(fc, cr, out),
        "credential_file_added" => credential_file_added(fc, cr, out),
        "encoded_blob" => encoded_blob(fc, cr, out),
        "minified_line" => minified_line(fc, cr, out),
        "zero_width_chars" => zero_width_chars(fc, cr, out),
        "homoglyph_identifier" => homoglyph_identifier(fc, cr, out),
        "mass_deletion" => mass_deletion(fc, cr, out),
        "binary_added" => binary_added(fc, cr, out),
        "gitignore_tamper" => gitignore_tamper(fc, cr, out),
        "guards_removed" => guards_removed(fc, cr, out),
        "auth_file_added" => auth_file_added(fc, cr, out),
        "hidden_file_added" => hidden_file_added(fc, cr, out),
        "exec_bit_added" => exec_bit_added(fc, cr, out),
        "install_script_added" => install_script_added(fc, cr, out),
        "typosquat" => typosquat(fc, cr, out),
        "lockfile_drift" => lockfile_drift(ctx, fc, cr, out),
        "assertions_removed" => assertions_removed(fc, cr, out),
        "test_file_deleted" => test_file_deleted(fc, cr, out),
        "ci_test_step_removed" => ci_test_step_removed(fc, cr, out),
        "coverage_gate_removed" => coverage_gate_removed(fc, cr, out),
        "pr_target_checkout" => pr_target_checkout(ctx, fc, cr, out),
        "secrets_in_pr_target" => secrets_in_pr_target(ctx, fc, cr, out),
        other => {
            ctx.warnings
                .push(format!("unknown heuristic handler: {other}"));
            Ok(())
        }
    }
}

fn is_workflow(fc: &FileChange) -> bool {
    fc.path.contains(".github/workflows/")
}

// ------------------------------------------------------------------ secrets

fn high_entropy(fc: &FileChange, cr: &CompiledRule, out: &mut Vec<Finding>) -> AppResult<()> {
    if util::is_lock_file(&fc.path) || fc.is_binary || fc.too_large || fc.path.contains(".min.") {
        return Ok(());
    }
    let re_token = rx(r#"["']([A-Za-z0-9+/=_\-]{20,})["']"#, &RE_ASSIGN_TOKEN);
    let re_bare = rx(r#"(?:=|:)\s*([A-Za-z0-9+/=_\-]{24,})\s*(?:$|[,;)])"#, &RE_BARE_TOKEN);
    let re_kw = rx(r"(?i)(key|secret|token|passw|pwd|auth|credential|signature|apikey|api)", &RE_KEYWORD);

    for (line_no, text) in fc.added_lines() {
        let trimmed = text.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("/*") {
            continue;
        }
        if trimmed.contains("integrity") || trimmed.contains("sha512-") || trimmed.contains("sha384-")
            || trimmed.contains("data:") || trimmed.contains("xmlns")
        {
            continue;
        }
        let token = re_token
            .captures(trimmed)
            .or_else(|| re_bare.captures(trimmed))
            .and_then(|c| c.get(1).map(|m| m.as_str().to_string()));
        let token = match token {
            Some(t) => t,
            None => continue,
        };
        if token.contains("http") || token.contains('/') && token.contains('.') && !re_kw.is_match(trimmed) {
            continue;
        }
        let distinct: HashSet<char> = token.chars().collect();
        if distinct.len() < 8 {
            continue;
        }
        let entropy = util::shannon_entropy(&token);
        let keyword = re_kw.is_match(trimmed);
        let (severity, confidence) = if keyword && entropy >= 3.8 && token.len() >= 20 {
            (Severity::High, 0.7)
        } else if entropy >= 4.5 && token.len() >= 32 {
            (Severity::Medium, 0.5)
        } else {
            continue;
        };
        push_finding(
            cr,
            fc,
            line_no,
            "added",
            trimmed,
            Some(util::mask_secret(&token)),
            Some(confidence),
            Some(severity),
            out,
        );
    }
    Ok(())
}

fn credential_file_added(fc: &FileChange, cr: &CompiledRule, out: &mut Vec<Finding>) -> AppResult<()> {
    if !matches!(fc.status, ChangeStatus::Added | ChangeStatus::Untracked) {
        return Ok(());
    }
    let name = util::file_name(&fc.path).to_lowercase();
    let ext = util::file_ext(&fc.path);
    let names = [
        "credentials", "credentials.json", "credentials.xml", ".netrc", "_netrc", ".pypirc",
        "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".htpasswd", "secrets.yml", "secrets.yaml",
        "secrets.json",
    ];
    let exts = ["pem", "p12", "pfx", "jks", "keystore", "kdbx", "key"];
    if names.contains(&name.as_str()) || exts.contains(&ext.as_str()) {
        push_finding(cr, fc, 0, "meta", &fc.path, None, None, None, out);
    }
    Ok(())
}

// --------------------------------------------------------------- suspicious

fn encoded_blob(fc: &FileChange, cr: &CompiledRule, out: &mut Vec<Finding>) -> AppResult<()> {
    if util::is_lock_file(&fc.path) || fc.path.contains(".min.") {
        return Ok(());
    }
    let re_b64 = rx(r"[A-Za-z0-9+/]{80,}={0,2}", &RE_BASE64_BLOB);
    let re_hex = rx(r"\b[0-9a-f]{96,}\b", &RE_HEX_BLOB);
    for (line_no, text) in fc.added_lines() {
        if text.contains("sha512-") || text.contains("sha384-") || text.contains("integrity=") {
            continue;
        }
        let hit = re_b64
            .find(&text)
            .or_else(|| re_hex.find(&text))
            .map(|m| m.as_str().to_string());
        if let Some(blob) = hit {
            let preview = truncate(&blob, 32);
            push_finding(
                cr,
                fc,
                line_no,
                "added",
                text.trim(),
                Some(format!("{preview}…")),
                None,
                None,
                out,
            );
        }
    }
    Ok(())
}

fn minified_line(fc: &FileChange, cr: &CompiledRule, out: &mut Vec<Finding>) -> AppResult<()> {
    let ext = util::file_ext(&fc.path);
    if !["js", "ts", "jsx", "tsx", "mjs", "cjs", "css", "html"].contains(&ext.as_str()) {
        return Ok(());
    }
    if util::is_lock_file(&fc.path) || fc.path.contains(".min.") {
        return Ok(());
    }
    for (line_no, text) in fc.added_lines() {
        if text.chars().count() > 700 {
            push_finding(
                cr,
                fc,
                line_no,
                "added",
                &truncate(text.trim(), 120),
                Some(format!("{} chars", text.chars().count())),
                None,
                None,
                out,
            );
            break;
        }
    }
    Ok(())
}

fn zero_width_chars(fc: &FileChange, cr: &CompiledRule, out: &mut Vec<Finding>) -> AppResult<()> {
    for (line_no, text) in fc.added_lines() {
        for (idx, ch) in text.char_indices() {
            if !ZERO_WIDTH.contains(&ch) {
                continue;
            }
            if ch == '\u{feff}' && idx == 0 && line_no <= 1 {
                continue; // legitimate BOM at file start
            }
            push_finding(
                cr,
                fc,
                line_no,
                "added",
                &truncate(text.trim(), 160),
                Some(format!("U+{:04X}", ch as u32)),
                None,
                None,
                out,
            );
            break;
        }
    }
    Ok(())
}

fn homoglyph_identifier(fc: &FileChange, cr: &CompiledRule, out: &mut Vec<Finding>) -> AppResult<()> {
    for (line_no, text) in fc.added_lines() {
        let trimmed = text.trim();
        if trimmed.starts_with("//")
            || trimmed.starts_with('#')
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
            || trimmed.starts_with("--")
        {
            continue;
        }
        let mut token = String::new();
        let mut reported = false;
        for ch in text.chars() {
            if ch.is_alphanumeric() || ch == '_' {
                token.push(ch);
                continue;
            }
            if token.chars().count() >= 4 && is_mixed_script(&token) {
                push_finding(
                    cr,
                    fc,
                    line_no,
                    "added",
                    trimmed,
                    Some(token.clone()),
                    None,
                    None,
                    out,
                );
                reported = true;
                break;
            }
            token.clear();
        }
        if !reported && token.chars().count() >= 4 && is_mixed_script(&token) {
            push_finding(cr, fc, line_no, "added", trimmed, Some(token), None, None, out);
        }
    }
    Ok(())
}

fn is_mixed_script(token: &str) -> bool {
    let mut latin = false;
    let mut lookalike = false;
    for ch in token.chars() {
        if ch.is_ascii_alphabetic() {
            latin = true;
        } else if ('\u{0400}'..='\u{04FF}').contains(&ch) || ('\u{0370}'..='\u{03FF}').contains(&ch) {
            lookalike = true;
        }
    }
    latin && lookalike
}

fn mass_deletion(fc: &FileChange, cr: &CompiledRule, out: &mut Vec<Finding>) -> AppResult<()> {
    if fc.deletions >= 100 && fc.deletions > 4 * fc.additions + 5 {
        push_finding(
            cr,
            fc,
            0,
            "meta",
            &format!("+{} −{}", fc.additions, fc.deletions),
            Some(format!("-{} lines", fc.deletions)),
            None,
            None,
            out,
        );
    }
    Ok(())
}

fn binary_added(fc: &FileChange, cr: &CompiledRule, out: &mut Vec<Finding>) -> AppResult<()> {
    if !matches!(
        fc.status,
        ChangeStatus::Added | ChangeStatus::Untracked | ChangeStatus::Renamed | ChangeStatus::Copied
    ) {
        return Ok(());
    }
    let ext = util::file_ext(&fc.path);
    if MEDIA_EXT.contains(&ext.as_str()) {
        return Ok(());
    }
    if fc.is_binary || SUSPICIOUS_BINARY_EXT.contains(&ext.as_str()) {
        push_finding(cr, fc, 0, "meta", &fc.path, Some(ext), None, None, out);
    }
    Ok(())
}

fn gitignore_tamper(fc: &FileChange, cr: &CompiledRule, out: &mut Vec<Finding>) -> AppResult<()> {
    if util::file_name(&fc.path) != ".gitignore" {
        return Ok(());
    }
    let re = rx(
        r"(?i)^\s*!?\s*(?:\.env\b|\.env\..*|.*\.pem\b|.*\.key\b|id_rsa.*|id_ed25519.*|.*secret.*|.*credential.*|.*token.*|.*\.pfx\b|.*\.p12\b)\s*$",
        &RE_GITIGNORE_SENSITIVE,
    );
    for (line_no, text) in fc.added_lines() {
        let t = text.trim();
        if let Some(rest) = t.strip_prefix('!') {
            if re.is_match(rest.trim()) {
                push_finding(cr, fc, line_no, "added", t, Some(t.to_string()), None, None, out);
            }
        }
    }
    for (line_no, text) in fc.removed_lines() {
        let t = text.trim().trim_start_matches('!').trim();
        if re.is_match(t) {
            push_finding(cr, fc, line_no, "removed", t, Some(t.to_string()), None, None, out);
        }
    }
    Ok(())
}

fn is_guard_path(path: &str) -> bool {
    let name = util::file_name(path).to_lowercase();
    GUARD_PATH_MARKERS.contains(&name.as_str())
        || path.starts_with(".husky/")
        || name.starts_with(".eslintrc")
        || name == "eslint.config.js"
        || name == "eslint.config.mjs"
        || name == "eslint.config.ts"
        || name == ".pre-commit-config.yaml"
}

fn guards_removed(fc: &FileChange, cr: &CompiledRule, out: &mut Vec<Finding>) -> AppResult<()> {
    if !is_guard_path(&fc.path) {
        return Ok(());
    }
    if fc.status == ChangeStatus::Deleted {
        push_finding(cr, fc, 0, "meta", &fc.path, None, None, None, out);
        return Ok(());
    }
    let marker = |t: &str| {
        t.contains("- id:")
            || t.contains("[[rules]]")
            || t.contains("rules:")
            || t.contains("deny(")
            || t.contains("plugins:")
    };
    let removed_markers = fc.removed_lines().iter().filter(|(_, t)| marker(t)).count();
    let added_markers = fc.added_lines().iter().filter(|(_, t)| marker(t)).count();
    if removed_markers >= 1 && added_markers == 0 {
        push_finding(cr, fc, 0, "meta", &fc.path, None, None, None, out);
    }
    Ok(())
}

fn auth_file_added(fc: &FileChange, cr: &CompiledRule, out: &mut Vec<Finding>) -> AppResult<()> {
    if !matches!(fc.status, ChangeStatus::Added | ChangeStatus::Untracked) {
        return Ok(());
    }
    let name = util::file_name(&fc.path).to_lowercase();
    if [".npmrc", ".pypirc", ".netrc", "_netrc"].contains(&name.as_str()) {
        push_finding(cr, fc, 0, "meta", &fc.path, None, None, None, out);
    }
    Ok(())
}

fn hidden_file_added(fc: &FileChange, cr: &CompiledRule, out: &mut Vec<Finding>) -> AppResult<()> {
    if !matches!(fc.status, ChangeStatus::Added | ChangeStatus::Untracked) {
        return Ok(());
    }
    let name = util::file_name(&fc.path).to_lowercase();
    if name.starts_with('.') && !ALLOWED_HIDDEN.contains(&name.as_str()) {
        push_finding(cr, fc, 0, "meta", &fc.path, Some(name), None, None, out);
    }
    Ok(())
}

fn exec_bit_added(fc: &FileChange, cr: &CompiledRule, out: &mut Vec<Finding>) -> AppResult<()> {
    if matches!(fc.status, ChangeStatus::Modified | ChangeStatus::Renamed)
        && !fc.old_exec
        && fc.new_exec
    {
        push_finding(cr, fc, 0, "meta", &fc.path, Some("+x".into()), None, None, out);
    }
    Ok(())
}

// ------------------------------------------------------------- supply chain

fn install_script_added(fc: &FileChange, cr: &CompiledRule, out: &mut Vec<Finding>) -> AppResult<()> {
    if util::file_name(&fc.path) != "package.json" {
        return Ok(());
    }
    let re = rx(
        r#""(?:preinstall|postinstall|install|prepare|prepublish|prepublishOnly)"\s*:\s*""#,
        &RE_INSTALL_SCRIPT,
    );
    let mut emitted = 0;
    for (line_no, text) in fc.added_lines() {
        if emitted >= 5 {
            break;
        }
        if re.is_match(&text) {
            push_finding(cr, fc, line_no, "added", text.trim(), None, None, None, out);
            emitted += 1;
        }
    }
    Ok(())
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr = vec![0usize; b.len() + 1];
    for i in 1..=a.len() {
        curr[0] = i;
        for j in 1..=b.len() {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
}

fn typosquat(fc: &FileChange, cr: &CompiledRule, out: &mut Vec<Finding>) -> AppResult<()> {
    let name = util::file_name(&fc.path).to_lowercase();
    let re_pkg = rx(r#"^\s*"([^"]+)"\s*:\s*"[^"]*"\s*,?\s*$"#, &RE_PKG_DEP);
    let re_req = rx(r"^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(?:[=<>~!].*)?$", &RE_REQ_DEP);
    let re_toml = rx(r#"^\s*"([A-Za-z0-9_.\-]+)"\s*,?\s*$"#, &RE_TOML_DEP);

    let mut seen = HashSet::new();
    for (line_no, text) in fc.added_lines() {
        let candidate: Option<String> = if name == "package.json" {
            re_pkg.captures(&text).and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
        } else if name.starts_with("requirements") && name.ends_with(".txt") {
            re_req.captures(&text).and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
        } else if name == "pyproject.toml" {
            re_toml.captures(&text).and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
        } else {
            None
        };
        let candidate = match candidate {
            Some(c) => c.to_lowercase(),
            None => continue,
        };
        if candidate.len() < 4 || NON_DEP_KEYS.contains(&candidate.as_str()) || seen.contains(&candidate)
        {
            continue;
        }
        let pool: &[&str] = if name == "package.json" { POPULAR_NPM } else { POPULAR_PY };
        if pool.contains(&candidate.as_str()) {
            continue;
        }
        let near = pool
            .iter()
            .find(|p| p.len().abs_diff(candidate.len()) <= 1 && levenshtein(&candidate, p) == 1);
        if let Some(similar) = near {
            seen.insert(candidate.clone());
            push_finding(
                cr,
                fc,
                line_no,
                "added",
                text.trim(),
                Some(format!("{candidate} ≈ {similar}")),
                None,
                None,
                out,
            );
        }
    }
    Ok(())
}

fn lockfile_drift(
    ctx: &ScanCtx<'_>,
    fc: &FileChange,
    cr: &CompiledRule,
    out: &mut Vec<Finding>,
) -> AppResult<()> {
    let name = util::file_name(&fc.path).to_lowercase();
    if !MANIFESTS.contains(&name.as_str()) {
        return Ok(());
    }
    if !matches!(fc.status, ChangeStatus::Added | ChangeStatus::Modified) {
        return Ok(());
    }
    let has_lock = ctx.changed_paths.iter().any(|p| util::is_lock_file(p));
    if !has_lock {
        push_finding(cr, fc, 0, "meta", &fc.path, None, None, None, out);
    }
    Ok(())
}

// -------------------------------------------------------------------- tests

fn count_matches(re: &Regex, lines: &[(u32, &str)]) -> usize {
    lines.iter().filter(|(_, t)| re.is_match(t)).count()
}

fn assertions_removed(fc: &FileChange, cr: &CompiledRule, out: &mut Vec<Finding>) -> AppResult<()> {
    if !fc.is_test_file() {
        return Ok(());
    }
    let re = rx(
        r"(?i)(\bassert\b|\bexpect\s*\(|assertEqual|assertTrue|assert_eq!|assert!|should\s*\(|assertThat|require\.Equal|t\.Fatal|t\.Error|assertRaises|pytest\.raises|toEqual|toBe\()",
        &RE_ASSERT,
    );
    let removed = count_matches(re, &fc.removed_lines());
    let added = count_matches(re, &fc.added_lines());
    if removed >= 2 && added == 0 {
        push_finding(
            cr,
            fc,
            0,
            "meta",
            &fc.path,
            Some(format!("-{removed} assertions")),
            None,
            None,
            out,
        );
    }
    Ok(())
}

fn test_file_deleted(fc: &FileChange, cr: &CompiledRule, out: &mut Vec<Finding>) -> AppResult<()> {
    if fc.is_test_file() && fc.status == ChangeStatus::Deleted {
        push_finding(cr, fc, 0, "meta", &fc.path, None, None, None, out);
    }
    Ok(())
}

fn ci_test_step_removed(fc: &FileChange, cr: &CompiledRule, out: &mut Vec<Finding>) -> AppResult<()> {
    if !is_workflow(fc) {
        return Ok(());
    }
    let re = rx(
        r"(?i)run:\s*.*\b(npm test|npm run test|pnpm test|yarn test|pytest|python -m pytest|cargo test|go test|mvn test|gradle test|dotnet test|jest|vitest)\b",
        &RE_CI_TEST,
    );
    if count_matches(re, &fc.removed_lines()) >= 1 {
        push_finding(cr, fc, 0, "meta", &fc.path, None, None, None, out);
    }
    Ok(())
}

fn coverage_gate_removed(fc: &FileChange, cr: &CompiledRule, out: &mut Vec<Finding>) -> AppResult<()> {
    let re = rx(
        r"(?i)(coverageThreshold|fail_under|--cov\b|fail-on-low-coverage|min_coverage|coverage\s*=\s*true)",
        &RE_COVERAGE,
    );
    let removed = count_matches(re, &fc.removed_lines());
    let added = count_matches(re, &fc.added_lines());
    if removed >= 1 && added == 0 {
        push_finding(cr, fc, 0, "meta", &fc.path, None, None, None, out);
    }
    Ok(())
}

// -------------------------------------------------------------------- ci/cd

fn pr_target_checkout(
    ctx: &mut ScanCtx<'_>,
    fc: &FileChange,
    cr: &CompiledRule,
    out: &mut Vec<Finding>,
) -> AppResult<()> {
    if !is_workflow(fc) || fc.status == ChangeStatus::Deleted {
        return Ok(());
    }
    let content = match ctx.file_content(fc) {
        Some(c) => c,
        None => return Ok(()),
    };
    if content.contains("pull_request_target") && content.contains("actions/checkout") {
        push_finding(cr, fc, 0, "meta", &fc.path, None, None, None, out);
    }
    Ok(())
}

fn secrets_in_pr_target(
    ctx: &mut ScanCtx<'_>,
    fc: &FileChange,
    cr: &CompiledRule,
    out: &mut Vec<Finding>,
) -> AppResult<()> {
    if !is_workflow(fc) || fc.status == ChangeStatus::Deleted {
        return Ok(());
    }
    let re = rx(r"secrets\.[A-Za-z0-9_]+", &RE_SECRETS_REF);
    let content = match ctx.file_content(fc) {
        Some(c) => c,
        None => return Ok(()),
    };
    if content.contains("pull_request_target") && re.is_match(&content) {
        push_finding(cr, fc, 0, "meta", &fc.path, None, None, None, out);
    }
    Ok(())
}
