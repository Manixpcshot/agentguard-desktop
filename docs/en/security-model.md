# Security model & privacy

> فارسی: [docs/fa/security-model.md](../fa/security-model.md)

## Threat model

AgentGuard reviews *untrusted input by design*: the diff it analyses may have
been produced by a compromised model, a poisoned prompt or a malicious
dependency. The app therefore treats repository content as data, never as
instructions, and is built around these rules:

1. **Read-only by default.** The Git layer (`gitmod.rs`) only opens, reads and
   diffs. There is no code path that stages, commits, pushes, checks out or
   writes inside the reviewed repository.
2. **Two gated mutations, both confirmed.**
   - *Redact secret*: rewrites exactly the matched span of one line, writes a
     timestamped backup (`<name>.agentguard-backup-<ts>`) first (optional but
     on by default), and requires a fresh confirmation nonce.
   - *Run tests*: executes the project's own detected test command with no
     extra flags, requires a fresh confirmation nonce, runs with a timeout and
     is killed on drop.
3. **Confirmation nonces.** `issue_confirmation(action, detail)` mints a UUID
   token bound to an action name with an expiry (default 300 s). Mutating
   commands consume the token: wrong action, unknown token or expiry → hard
   error. A scripted or replayed call cannot bypass the UI dialog.
4. **Path containment.** Relative paths passed by the UI are validated
   (`no '..'`, not absolute) before any file access; the project root comes
   from the folder picker.
5. **Secrets never leave the app in clear text.** A detected credential is
   masked (`AKIA••••MPLE`) in the finding's snippet and matched fragment, in
   exported reports, in logs and in the prompt sent to a local Ollama model.
   Masking happens where findings are created, so heuristic detectors are
   covered as well as regex rules. The diff viewer still renders your own
   working-tree content unchanged — it is your repository, on your screen — and
   the full value only exists in memory during the single-line rewrite of a
   redaction.
6. **No network by default.** The app makes zero outbound requests except,
   when enabled, to the Ollama host you configure (default
   `http://127.0.0.1:11434`). There is no telemetry, analytics or update
   phone-home.
7. **Hardened webview.** Tauri CSP blocks remote scripts/styles/frames;
   `connect-src` is limited to the IPC origin. The frontend has no filesystem
   or shell access; everything sensitive lives behind typed Rust commands.

## What the analysis can and cannot do

- Rules are deterministic regular expressions plus 22 contextual heuristics;
  false positives are possible and every finding shows its confidence.
- The optional Ollama review is advisory; its output is displayed separately
  and never changes rule severities.
- AgentGuard does not execute repository code during a scan. Only the
  explicitly confirmed test run executes anything, using the project's own
  test entry point.

## Reporting vulnerabilities in AgentGuard itself

See [SECURITY.md](../../SECURITY.md). Please do not file public issues for
security problems in the app.
