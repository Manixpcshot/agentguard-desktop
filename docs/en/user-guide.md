# User guide

> فارسی: [docs/fa/user-guide.md](../fa/user-guide.md)

## 1. Open a project

Click **Choose project folder** (or pick one from *Recent projects*). AgentGuard
locates the enclosing Git repository automatically — you can open a subfolder of
a monorepo and the whole repository is analysed, while paths stay relative.

The header card shows branch, commit count, uncommitted changes and untracked
files so you always know what will be reviewed.

## 2. Choose the comparison base

| Base | Meaning |
|---|---|
| Working tree | `HEAD` → your disk (staged + unstaged + optionally untracked). The default for reviewing an AI session you have not committed yet |
| Staged | index vs `HEAD` — exactly what the next commit would contain |
| Branch merge-base | `merge-base(HEAD, <branch>)` → disk. Perfect for “what did this feature branch change vs `main`?” |
| Single commit | that commit vs its first parent — audit one AI commit |
| Last N commits | `HEAD~N` → disk |

Toggle **Include untracked files** to also review files the AI created but you
have not `git add`-ed yet.

## 3. Pick engines

All seven engines are on by default. Switch off what you do not need for a
faster, quieter scan (e.g. disable *CI/CD* in repos without workflows).

## 4. Scan

Press **Start scan**. Progress phases: opening → diffing → filtering →
analyzing → scoring → (optional AI) → saving. Cancel any time; partial results
are discarded.

When the scan finishes you get:

- **Risk score (0–100)** with a band (Safe / Low / Elevated / High / Critical)
  and a verdict: **PASS**, **REVIEW** or **BLOCK**.
- Counts by severity, category and engine.
- The findings list.

### How the score works

Each finding contributes `weight(severity) × (0.5 + 0.5 × confidence)`:
critical = 48, high = 22, medium = 8, low = 3, info = 1. The sum is capped at
100. Bands: `<15` Low, `<40` Elevated, `<70` High, `≥70` Critical. The verdict is
**BLOCK** when any critical finding exists or the score ≥ 70, **REVIEW** when any
high/medium finding exists or the score ≥ 15, otherwise **PASS**.

## 5. Triage findings

Filters: severity pills, engine dropdown and free-text search (file, rule id,
snippet, tags). Selecting a finding opens the detail panel:

- localized title, description and **remediation**
- file and line, matched fragment (secrets are masked, so the full value is
  never stored in history or written into an exported report)
- CWE identifiers, references, tags, confidence
- actions:
  - **Copy** a plain-text summary for your issue tracker
  - **View in diff** jumps to the Changes view with the line marked
  - **Reveal in file explorer**
  - **Redact secret…** (only for redactable findings) — see *Safety* below

## 6. Review the diff

The Changes view lists every changed file with +/− counts and a finding badge.
The diff viewer shows unified hunks with old/new line numbers; lines that carry
a finding get an accent marker.

## 7. Run the real tests (optional)

**Findings → Run project tests…** detects the runner (`npm test`, `cargo test`,
`pytest`, `go test`, `mvn test`, `gradle test`, `dotnet test`), shows the exact
command and asks for confirmation. The output is displayed in a dialog. No
files are modified.

## 8. Export reports

**Markdown**, **HTML** (standalone, styled, RTL when Persian) or **JSON** via
the save dialog. Reports embed the full finding list, the AI section (if used)
and metadata.

## 9. History & settings

Every scan is stored locally (`%APPDATA%\dev.agentguard.desktop\history`).
Reopen any report, delete single entries or clear everything from
*History* or *Settings → Danger zone*.

Settings cover language (English default / فارسی), theme, scan defaults,
ignore globs, Ollama connection and confirmation validity.

## Safety model (short version)

- Scans are strictly **read-only**.
- Redacting a secret rewrites exactly one line, replaces the matched value with
  `<redacted-by-AgentGuard>` and writes a timestamped backup next to the file.
- Running tests executes your project's own test command.
- Both require a confirmation nonce that the UI issues and that expires after
  `confirmTtlSecs` (default 300 s). Replay or forged calls are rejected.
