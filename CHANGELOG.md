# Changelog

All notable changes to AgentGuard are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Persian changelog: [docs/fa/changelog.md](docs/fa/changelog.md)

## [Unreleased]

- *(nothing yet)*

## [0.1.1] - 2026-10-17

### Fixed

- **Secrets are masked everywhere they leave the app.** A credential detected by
  an engine other than *Secrets*, or by a heuristic that reports no matched
  fragment (e.g. `SEC-SECRET-HIGH-ENTROPY-STRING`), could reach the UI, the JSON
  history and exported Markdown/HTML/JSON reports in clear text. All findings now
  pass `scanner::mask_findings` before they are emitted, stored or exported.
- **The Ollama prompt is really masked.** `build_prompt` documented a masked diff
  but forwarded raw lines; `Catalog::mask_secrets_in` now masks secret-shaped
  tokens before the prompt is assembled.
- Masking keeps a recognizable prefix (`AKIA••••T4VB`) and leaves non-secret
  values (file names reported by `credential_file_added`, ordinary code) readable.

### Added

- End-to-end pipeline test: a real temporary Git repository → diff → all seven
  engines → scoring, asserting a critical AWS-key finding, a dangerous
  `curl … | bash` finding, a BLOCK verdict, absence of the raw key in every
  finding field, and a zero-finding PASS for a clean documentation change.
- Catalog test for `mask_secrets_in`.
- CI / release / download / license / platform badges in `README.md` and
  `README.fa.md`.
- "Cutting a release" checklist in `CONTRIBUTING.md` (every tag must publish
  Windows binaries, never source only).

## [0.1.0] - 2026-10-17

### Added

- First public release of AgentGuard for Windows (x64): NSIS installer, MSI
  package and portable executable, all produced by GitHub Actions.
- Local Git change review with six comparison bases: working tree, staged
  changes, branch merge-base, single commit and last N commits, plus optional
  inclusion of untracked files.
- Rule catalog v1 with **144 rules** across seven engines — Secrets & API keys
  (29), Dangerous commands (24), Security regressions (33), Test integrity (13),
  Suspicious changes (20), Supply chain (13), CI/CD hardening (12) — each rule
  carrying English and Persian title, description and remediation.
- 22 contextual heuristics beyond regex matching (typosquatting, lockfile drift,
  removed assertions, zero-width/homoglyph characters, `pull_request_target` +
  checkout, secrets in CI target, minified lines, encoded blobs, …).
- Deterministic risk scoring (0–100) with Safe/Low/Elevated/High/Critical bands
  and PASS / REVIEW / BLOCK verdicts.
- Finding triage: severity/engine filters, free-text search, detail panel with
  CWE references, confidence, masked snippets, copy-to-clipboard, jump-to-diff
  and reveal-in-explorer.
- Unified diff viewer with per-file finding counts and marked lines.
- Secret redaction with automatic timestamped backup, gated behind an explicit
  user confirmation.
- Optional project test runner (npm/pnpm/yarn, cargo, go, mvn, gradle, dotnet,
  pytest) gated behind an explicit user confirmation.
- Optional local AI review through Ollama (masked diffs only, no cloud APIs),
  with connection test, model listing and lenient output parsing.
- Report export to Markdown, HTML (RTL-aware) and JSON, in English or Persian.
- Local scan history (up to 100 reports) with re-open, delete and clear.
- Settings: language (English default / Persian), dark/light theme, default
  engines, ignore globs, per-user data directory, danger zone.
- Bilingual documentation (EN + FA): installation, user guide, security model,
  Ollama setup, architecture and contributing.
- CI: frontend typecheck/build, Rust `cargo check` (Ubuntu + Windows),
  `cargo test`, clippy (advisory), rule catalog regeneration and validation.

[Unreleased]: https://github.com/Manixpcshot/agentguard-desktop/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/Manixpcshot/agentguard-desktop/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Manixpcshot/agentguard-desktop/releases/tag/v0.1.0
