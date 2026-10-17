//! Optional local AI review through Ollama (http://127.0.0.1:11434 by default).
//!
//! Everything stays on the user's machine: the blocking HTTP client only talks
//! to the configured Ollama host, and secrets are masked before they are sent.

use crate::models::*;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

const SYSTEM_PROMPT: &str = "You are AgentGuard, a meticulous security code reviewer. \
You receive a Git diff (already filtered; secrets are masked) produced by an AI coding assistant. \
Identify real problems only: leaked credentials, insecure code, destructive commands, sabotaged or \
skipped tests, obfuscation, supply-chain risks and CI/CD weaknesses. Respond with STRICT JSON only, \
no markdown fences, in this exact shape: \
{\"summary\": \"<2-3 sentence overall assessment>\", \
\"insights\": [{\"title\": \"<short>\", \"detail\": \"<why it matters and how to fix>\", \
\"severity\": \"critical|high|medium|low|info\", \"file\": \"<path or null>\"}]}";

pub struct OllamaClient {
    pub host: String,
    client: reqwest::blocking::Client,
}

impl OllamaClient {
    pub fn new(host: &str, timeout: Duration) -> Result<Self, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(4))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            host: host.trim_end_matches('/').to_string(),
            client,
        })
    }

    pub fn status(&self) -> OllamaStatus {
        let mut st = OllamaStatus {
            host: self.host.clone(),
            available: false,
            version: None,
            models: Vec::new(),
            error: None,
        };
        let resp = match self
            .client
            .get(format!("{}/api/version", self.host))
            .send()
        {
            Ok(r) => r,
            Err(e) => {
                st.error = Some(pretty_http_error(&e));
                return st;
            }
        };
        if !resp.status().is_success() {
            st.error = Some(format!("HTTP {}", resp.status()));
            return st;
        }
        if let Ok(v) = resp.json::<Value>() {
            st.version = v
                .get("version")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
        }
        st.available = true;

        if let Ok(resp) = self.client.get(format!("{}/api/tags", self.host)).send() {
            if let Ok(v) = resp.json::<Value>() {
                if let Some(arr) = v.get("models").and_then(|m| m.as_array()) {
                    for m in arr {
                        st.models.push(OllamaModel {
                            name: m
                                .get("name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("unknown")
                                .to_string(),
                            size_bytes: m.get("size").and_then(|s| s.as_u64()).unwrap_or(0),
                        });
                    }
                }
            }
        }
        st
    }

    pub fn chat(&self, model: &str, prompt: &str) -> Result<String, String> {
        let body = json!({
            "model": model,
            "stream": false,
            "options": { "temperature": 0.2 },
            "messages": [
                { "role": "system", "content": SYSTEM_PROMPT },
                { "role": "user", "content": prompt }
            ]
        });
        let resp = self
            .client
            .post(format!("{}/api/chat", self.host))
            .json(&body)
            .send()
            .map_err(|e| pretty_http_error(&e))?;
        if resp.status().is_success() {
            if let Ok(v) = resp.json::<Value>() {
                if let Some(content) = v.pointer("/message/content").and_then(|c| c.as_str()) {
                    return Ok(content.to_string());
                }
            }
        }
        // Fall back to the legacy generate endpoint.
        let body = json!({
            "model": model,
            "stream": false,
            "system": SYSTEM_PROMPT,
            "prompt": prompt
        });
        let resp = self
            .client
            .post(format!("{}/api/generate", self.host))
            .json(&body)
            .send()
            .map_err(|e| pretty_http_error(&e))?;
        let v: Value = resp.json().map_err(|e| e.to_string())?;
        v.get("response")
            .and_then(|r| r.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| "unexpected Ollama response shape".to_string())
    }
}

fn pretty_http_error(e: &reqwest::Error) -> String {
    if e.is_connect() {
        "cannot connect to Ollama (is it running?)".to_string()
    } else if e.is_timeout() {
        "Ollama request timed out".to_string()
    } else {
        e.to_string()
    }
}

fn severity_from(s: &str) -> Severity {
    match s.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

/// Lenient JSON extraction: strips code fences and finds the outer object.
pub fn parse_analysis(raw: &str) -> (String, Vec<AiInsight>) {
    let cleaned = raw.replace("```json", "```");
    let body = if let Some(start) = cleaned.find("```") {
        let rest = &cleaned[start + 3..];
        rest.strip_suffix("```").unwrap_or(rest).trim().to_string()
    } else {
        cleaned.clone()
    };
    let candidate = match (body.find('{'), body.rfind('}')) {
        (Some(a), Some(b)) if b > a => &body[a..=b],
        _ => return (truncate_str(raw.trim(), 1200), Vec::new()),
    };
    match serde_json::from_str::<Value>(candidate) {
        Ok(v) => {
            let summary = v
                .get("summary")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            let mut insights = Vec::new();
            if let Some(arr) = v.get("insights").and_then(|i| i.as_array()) {
                for item in arr.iter().take(40) {
                    insights.push(AiInsight {
                        title: item
                            .get("title")
                            .and_then(|t| t.as_str())
                            .unwrap_or("Insight")
                            .to_string(),
                        detail: item
                            .get("detail")
                            .and_then(|t| t.as_str())
                            .unwrap_or("")
                            .to_string(),
                        severity: severity_from(
                            item.get("severity").and_then(|s| s.as_str()).unwrap_or("info"),
                        ),
                        file: item
                            .get("file")
                            .and_then(|f| f.as_str())
                            .map(|s| s.to_string()),
                    });
                }
            }
            (if summary.is_empty() {
                truncate_str(raw.trim(), 1200)
            } else {
                summary
            }, insights)
        }
        Err(_) => (truncate_str(raw.trim(), 1200), Vec::new()),
    }
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max - 1).collect();
        format!("{cut}…")
    }
}

/// Builds the review prompt: rule findings first (cheap, precise), then a
/// masked diff excerpt bounded by `max_diff_chars`.
fn build_prompt(options: &ScanOptions, changes: &[FileChange], findings: &[Finding]) -> String {
    let mut prompt = String::from("Rule-based findings already detected:\n");
    if findings.is_empty() {
        prompt.push_str("(none)\n");
    }
    for f in findings.iter().take(60) {
        prompt.push_str(&format!(
            "- [{}|{}] {} @ {}:{}\n",
            f.severity.as_str(),
            f.rule_id,
            f.text.title.en,
            f.file,
            f.line
        ));
    }
    prompt.push_str("\nDiff excerpt (secrets masked, additions/removals only):\n");
    let budget = options.ai.max_diff_chars.max(2000);
    for fc in changes.iter().take(80) {
        if fc.is_binary || fc.too_large {
            continue;
        }
        let header = format!("--- a/{}\n+++ b/{}\n", fc.path, fc.path);
        if prompt.len() + header.len() > budget {
            break;
        }
        prompt.push_str(&header);
        for h in &fc.hunks {
            for l in &h.lines {
                match l.kind {
                    LineKind::Added => {
                        let line = format!("+{}\n", l.text);
                        if prompt.len() + line.len() > budget {
                            return prompt;
                        }
                        prompt.push_str(&line);
                    }
                    LineKind::Removed => {
                        let line = format!("-{}\n", l.text);
                        if prompt.len() + line.len() > budget {
                            return prompt;
                        }
                        prompt.push_str(&line);
                    }
                    _ => {}
                }
            }
        }
    }
    prompt
}

/// Synchronous analysis used from the blocking scan task.
pub fn analyze(options: &ScanOptions, changes: &[FileChange], findings: &[Finding]) -> AiAnalysis {
    let started = Instant::now();
    let host = options.ai.host.clone();
    let model = options.ai.model.clone();
    let mut analysis = AiAnalysis {
        enabled: true,
        available: false,
        model: model.clone(),
        host: host.clone(),
        summary: String::new(),
        insights: Vec::new(),
        raw: String::new(),
        error: None,
        duration_ms: 0,
    };
    let result = (|| -> Result<(), String> {
        let client = OllamaClient::new(
            &host,
            Duration::from_secs(options.ai.timeout_secs.clamp(10, 1800)),
        )?;
        let st = client.status();
        if !st.available {
            return Err(st.error.unwrap_or_else(|| "Ollama unreachable".to_string()));
        }
        analysis.available = true;
        let prompt = build_prompt(options, changes, findings);
        let raw = client.chat(&model, &prompt)?;
        let (summary, insights) = parse_analysis(&raw);
        analysis.summary = summary;
        analysis.insights = insights;
        analysis.raw = truncate_str(&raw, 20_000);
        Ok(())
    })();
    if let Err(e) = result {
        analysis.error = Some(e);
    }
    analysis.duration_ms = started.elapsed().as_millis() as u64;
    analysis
}
