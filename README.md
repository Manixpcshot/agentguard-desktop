<div align="center">

# 🛡 AgentGuard

**Review what your AI wrote — before it ships.**

AgentGuard is a free, open-source Windows desktop app that inspects the Git
changes produced by AI coding assistants and flags **leaked API keys and
secrets**, **security regressions**, **sabotaged or broken tests**,
**destructive commands** and **suspicious edits** — with severity levels,
explanations and concrete remediation advice.

[English](README.md) · [فارسی](README.fa.md)

[![CI](https://github.com/Manixpcshot/agentguard-desktop/actions/workflows/ci.yml/badge.svg)](https://github.com/Manixpcshot/agentguard-desktop/actions/workflows/ci.yml)
[![Release](https://github.com/Manixpcshot/agentguard-desktop/actions/workflows/release.yml/badge.svg)](https://github.com/Manixpcshot/agentguard-desktop/actions/workflows/release.yml)
[![Latest release](https://img.shields.io/github/v/release/Manixpcshot/agentguard-desktop?label=download&color=2E86FF)](https://github.com/Manixpcshot/agentguard-desktop/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-0FBFA8)](LICENSE)
![Platform](https://img.shields.io/badge/platform-Windows%20x64-0A0F1E)

[Download the latest release](https://github.com/Manixpcshot/agentguard-desktop/releases/latest) ·
[Documentation](docs/en/installation.md) · [Report an issue](https://github.com/Manixpcshot/agentguard-desktop/issues)

Built with [Tauri 2](https://tauri.app) · React · TypeScript · Rust — no paid APIs, no telemetry.

</div>

---

## Why

AI coding tools are fast, but they sometimes "fix" a failing suite by deleting
assertions, hardcode the API key they were given, pipe a remote script into a
shell, or silently weaken TLS verification. AgentGuard gives every AI-produced
diff the same scrutiny a careful security reviewer would — instantly, locally,
and for free.

## Features

- **Real Git analysis** — review the working tree, staged changes, a branch
  merge-base, a single commit, a revision range or the last N commits, with a
  full unified-diff viewer.
- **140+ detection rules in 7 engines**, all running locally:
  | Engine | Catches |
  |---|---|
  | Secrets & API keys | AWS/GCP/Azure/GitHub/GitLab/Slack/Stripe/OpenAI/Anthropic tokens, private keys, `.env` files, DB connection strings, high-entropy literals |
  | Dangerous commands | `rm -rf /`, fork bombs, `curl \| sh`, Defender/firewall disabling, force-push, history rewriting |
  | Security regressions | SQL injection, command injection, XSS, unsafe deserialization, weak crypto, disabled TLS verification, CORS/cookie/JWT mistakes |
  | Test integrity | skipped/gutted/deleted tests, `.only`, tautologies, removed assertions, removed CI test steps and coverage gates |
  | Suspicious changes | base64/hex blobs, minified lines, zero-width & homoglyph (Trojan Source) characters, `.gitignore` tampering, removed hooks/guards, persistence |
  | Supply chain | new `postinstall` scripts, typosquatted package names, unpinned or foreign-registry dependencies, lockfile drift |
  | CI/CD hardening | `pull_request_target` + checkout, `${{ }}` expression injection, `write-all` permissions, secret leakage into logs/artifacts |
- **Risk scoring & verdict** — weighted 0–100 score with Safe→Critical bands and
  a PASS / REVIEW / BLOCK verdict you can gate on.
- **Actionable reports** — every finding carries a description, remediation,
  CWE references and confidence; export to **Markdown, HTML or JSON**,
  in English or Persian.
- **Optional local AI second opinion** — connect to [Ollama](https://ollama.com)
  on your machine (e.g. `qwen2.5-coder`) for a model-written assessment. The app
  works fully without it.
- **Bilingual** — English (default) and Persian (فارسی) with full RTL layout,
  including rule explanations and exported reports.
- **Safety by design** — AgentGuard is read-only. It never stages, commits,
  pushes or edits your files. The two mutating actions (redacting a detected
  secret *with backup*, and running your test suite) require an explicit,
  time-limited confirmation issued from the UI.
- **History** — every scan is stored locally as JSON so you can revisit and
  compare past reviews.

## Download

Grab the installer from the
[Releases page](https://github.com/Manixpcshot/agentguard-desktop/releases/latest):

| File | What it is |
|---|---|
| `AgentGuard_<version>_x64-setup.exe` | NSIS installer (recommended) |
| `AgentGuard_<version>_x64_en-US.msi` | Windows Installer package |
| `AgentGuard-portable.exe` | Standalone executable, no installation |

See [docs/en/installation.md](docs/en/installation.md) for requirements,
silent installs and uninstall steps.

## Quick start

1. Install and launch AgentGuard.
2. Click **Choose project folder** and pick any local Git repository.
3. Pick what to compare (working tree by default) and which engines to run.
4. Press **Start scan** — review findings, open the diff, export a report.

Optional: install [Ollama](https://ollama.com), `ollama pull qwen2.5-coder:7b`,
then enable *AI Review* in the app for a local model assessment.

## Build from source

Requirements: Node.js ≥ 20, Rust ≥ 1.77, and on Windows the
[WebView2 runtime](https://developer.microsoft.com/microsoft-edge/webview2/)
(preinstalled on Windows 11).

```bash
git clone https://github.com/Manixpcshot/agentguard-desktop.git
cd agentguard-desktop
npm install
npm run tauri dev        # development
npm run tauri build      # installers in src-tauri/target/release/bundle
```

Linux (development only) needs `libwebkit2gtk-4.1-dev`, `libgtk-3-dev` and
`librsvg2-dev`.

## Project layout

```
src/                  React + TypeScript frontend (UI, i18n, charts, diff viewer)
src-tauri/src/        Rust core
  catalog.rs          loads the embedded rule catalog
  gitmod.rs           read-only libgit2 access (diffs, refs, status)
  engines/            regex runner + 22 contextual heuristics
  scanner.rs          orchestration, scoring, progress events
  ollama.rs           optional local AI client (masked diffs only)
  report.rs           Markdown / HTML / JSON exporters (bilingual)
  history.rs settings.rs projects.rs safety.rs
src-tauri/resources/rules.json   the rule catalog (single source of truth)
tools/                catalog generator + validator (Python)
docs/en, docs/fa      user documentation in both languages
.github/workflows/    CI + Windows release pipeline
```

## Contributing

Contributions are welcome — new detection rules are the easiest way to help:
add an entry to `tools/rules_*.py` (with English **and** Persian text), run
`python3 tools/gen_rules.py`, and open a pull request. See
[CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
