//! Small shared helpers: masking, entropy, hashing, path predicates.

use sha2::{Digest, Sha256};

/// Paths that never carry hand-written code and would drown the report in
/// false positives. Content engines skip them entirely.
pub const NOISE_PATHS: &[&str] = &[
    "node_modules/",
    ".git/",
    "dist/",
    "build/",
    "out/",
    "target/",
    ".venv/",
    "venv/",
    "__pycache__/",
    ".next/",
    ".nuxt/",
    "coverage/",
    ".idea/",
    ".vscode/",
    "vendor/",
    "third_party/",
    "Pods/",
    ".terraform/",
];

pub const LOCK_FILES: &[&str] = &[
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Cargo.lock",
    "poetry.lock",
    "Pipfile.lock",
    "uv.lock",
    "go.sum",
    "composer.lock",
    "Gemfile.lock",
    "packages.lock.json",
];

/// True when the path lives inside a dependency/vendor/build directory.
pub fn is_noise_path(path: &str) -> bool {
    let p = path.replace('\\', "/");
    NOISE_PATHS.iter().any(|n| p.contains(n))
}

pub fn is_lock_file(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    LOCK_FILES.iter().any(|l| l.eq_ignore_ascii_case(name))
}

pub fn is_likely_binary(bytes: &[u8]) -> bool {
    let window = &bytes[..bytes.len().min(8000)];
    window.contains(&0)
}

/// Shannon entropy in bits per character.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    let mut h = 0.0f64;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        h -= p * p.log2();
    }
    h
}

/// Masks a secret so it is safe to show in the UI, logs and reports.
/// `AKIAIOSFODNN7EXAMPLE` -> `AKIA••••••••••••MPLE`
pub fn mask_secret(secret: &str) -> String {
    let trimmed = secret.trim();
    let chars: Vec<char> = trimmed.chars().collect();
    let n = chars.len();
    if n <= 8 {
        return format!("{}••••", chars.iter().take(2).collect::<String>());
    }
    let head: String = chars.iter().take(4).collect();
    let tail: String = chars.iter().skip(n.saturating_sub(4)).collect();
    let hidden = (n - 8).clamp(4, 12);
    format!("{head}{}{tail}", "•".repeat(hidden))
}

/// Stable finding id: hash of rule + file + line + matched text.
pub fn finding_id(rule_id: &str, file: &str, line: u32, matched: &str) -> String {
    let mut h = Sha256::new();
    h.update(rule_id.as_bytes());
    h.update(b"\x00");
    h.update(file.as_bytes());
    h.update(b"\x00");
    h.update(line.to_string().as_bytes());
    h.update(b"\x00");
    h.update(matched.as_bytes());
    let digest = h.finalize();
    digest
        .iter()
        .take(10)
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub fn timestamp_to_rfc3339(secs: i64) -> String {
    chrono::DateTime::from_timestamp(secs, 0)
        .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default()
}

/// Trims trailing whitespace/newlines from diff line content.
pub fn clean_line(s: &str) -> String {
    s.trim_end_matches(['\n', '\r']).to_string()
}

pub fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

pub fn file_ext(path: &str) -> String {
    let name = file_name(path).to_lowercase();
    match name.rsplit_once('.') {
        Some((_, ext)) => ext.to_string(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_secrets_safely() {
        let m = mask_secret("AKIAIOSFODNN7EXAMPLE");
        assert!(!m.contains("IOSFODNN"));
        assert!(m.starts_with("AKIA"));
        assert!(m.ends_with("MPLE"));
        let short = mask_secret("abc");
        assert!(short.contains("••••"));
    }

    #[test]
    fn entropy_detects_random_strings() {
        assert!(shannon_entropy("aK3$zQ9!xL7@wR5#tY1&uI4^oP8*eN2(mJ6)") > 4.5);
        assert!(shannon_entropy("aaaaaaaaaaaaaaaaaaaa") < 0.1);
    }

    #[test]
    fn noise_paths() {
        assert!(is_noise_path("node_modules/foo/index.js"));
        assert!(is_noise_path("src/node_modules/x.ts"));
        assert!(!is_noise_path("src/components/App.tsx"));
        assert!(is_lock_file("frontend/package-lock.json"));
        assert!(!is_lock_file("package.json"));
    }

    #[test]
    fn finding_ids_are_stable() {
        let a = finding_id("R1", "f.rs", 3, "x");
        let b = finding_id("R1", "f.rs", 3, "x");
        let c = finding_id("R1", "f.rs", 4, "x");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
