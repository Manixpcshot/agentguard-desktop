//! Optional real test execution (only after explicit user confirmation).

use crate::models::TestRunResult;
use serde::Serialize;
use serde_json::Value;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::process::Command;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestRunnerInfo {
    pub runner: String,
    pub command: Vec<String>,
    pub description_en: String,
    pub description_fa: String,
}

/// On Windows npm/pnpm/yarn are .cmd shims and need cmd.exe.
fn shell_wrap(bin: &str, args: &[&str]) -> Vec<String> {
    if cfg!(windows) {
        let mut v = vec!["cmd".to_string(), "/C".to_string(), bin.to_string()];
        v.extend(args.iter().map(|s| s.to_string()));
        v
    } else {
        let mut v = vec![bin.to_string()];
        v.extend(args.iter().map(|s| s.to_string()));
        v
    }
}

pub fn detect(project: &str) -> Option<TestRunnerInfo> {
    let root = Path::new(project);
    let has = |n: &str| root.join(n).exists();

    if has("package.json") {
        let raw = std::fs::read_to_string(root.join("package.json")).ok()?;
        let v: Value = serde_json::from_str(&raw).ok()?;
        let test = v
            .pointer("/scripts/test")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        if test.is_empty() || test.contains("no test specified") {
            return None;
        }
        let bin = if has("pnpm-lock.yaml") {
            "pnpm"
        } else if has("yarn.lock") {
            "yarn"
        } else {
            "npm"
        };
        return Some(TestRunnerInfo {
            runner: bin.to_string(),
            command: shell_wrap(bin, &["test"]),
            description_en: format!("Run the project's `{bin} test` script (read-only test run)."),
            description_fa: format!("اجرای اسکریپت `{bin} test` پروژه (اجرای فقط-خواندنی تست‌ها)."),
        });
    }
    if has("Cargo.toml") {
        return Some(TestRunnerInfo {
            runner: "cargo".to_string(),
            command: vec!["cargo".into(), "test".into(), "--quiet".into()],
            description_en: "Run `cargo test` for the Rust workspace.".into(),
            description_fa: "اجرای `cargo test` برای فضای کاری Rust.".into(),
        });
    }
    if has("go.mod") {
        return Some(TestRunnerInfo {
            runner: "go".to_string(),
            command: vec!["go".into(), "test".into(), "./...".into()],
            description_en: "Run `go test ./...`.".into(),
            description_fa: "اجرای `go test ./...`.".into(),
        });
    }
    if has("pom.xml") {
        return Some(TestRunnerInfo {
            runner: "maven".to_string(),
            command: shell_wrap("mvn", &["-q", "test"]),
            description_en: "Run `mvn test`.".into(),
            description_fa: "اجرای `mvn test`.".into(),
        });
    }
    if has("build.gradle") || has("build.gradle.kts") {
        return Some(TestRunnerInfo {
            runner: "gradle".to_string(),
            command: shell_wrap("gradle", &["test", "--quiet"]),
            description_en: "Run `gradle test`.".into(),
            description_fa: "اجرای `gradle test`.".into(),
        });
    }
    if let Ok(entries) = std::fs::read_dir(root) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.ends_with(".sln") || name.ends_with(".csproj") {
                return Some(TestRunnerInfo {
                    runner: "dotnet".to_string(),
                    command: vec!["dotnet".into(), "test".into(), "--nologo".into()],
                    description_en: "Run `dotnet test`.".into(),
                    description_fa: "اجرای `dotnet test`.".into(),
                });
            }
        }
    }
    if has("pytest.ini")
        || has("pyproject.toml")
        || has("setup.py")
        || has("requirements.txt")
        || has("tests")
        || has("test")
    {
        return Some(TestRunnerInfo {
            runner: "pytest".to_string(),
            command: shell_wrap("python", &["-m", "pytest", "-q"]),
            description_en: "Run `python -m pytest -q`.".into(),
            description_fa: "اجرای `python -m pytest -q`.".into(),
        });
    }
    None
}

fn tail_summary(output: &str) -> String {
    let lines: Vec<&str> = output
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    let start = lines.len().saturating_sub(8);
    lines[start..].join("\n")
}

fn truncate_tail(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let from = s.len() - max;
    format!("…(truncated)...\n{}", &s[from..])
}

pub async fn run(project: &str, info: &TestRunnerInfo, timeout_secs: u64) -> TestRunResult {
    let started = Instant::now();
    let mut cmd = Command::new(&info.command[0]);
    cmd.args(&info.command[1..])
        .current_dir(project)
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let waited = tokio::time::timeout(Duration::from_secs(timeout_secs.clamp(5, 1800)), cmd.output()).await;

    let (exit_code, passed, output) = match waited {
        Ok(Ok(out)) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            (
                out.status.code(),
                out.status.success(),
                truncate_tail(&format!("{stdout}\n{stderr}"), 200_000),
            )
        }
        Ok(Err(e)) => (None, false, format!("failed to start test runner: {e}")),
        Err(_) => (None, false, format!("test run timed out after {timeout_secs}s")),
    };

    TestRunResult {
        runner: info.runner.clone(),
        command: info.command.clone(),
        exit_code,
        passed,
        summary: tail_summary(&output),
        output,
        duration_ms: started.elapsed().as_millis() as u64,
    }
}
