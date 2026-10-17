# Security policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems in AgentGuard.

Report privately instead:

- Use GitHub's **“Report a vulnerability”** button on the
  [Security Advisories page](https://github.com/Manixpcshot/agentguard-desktop/security/advisories/new), or
- Email the maintainer address listed in the repository profile.

Include: affected version, a minimal reproduction (repository/diff sample),
impact, and whether the issue is already public. We aim to acknowledge reports
within 7 days and to publish fixes in a patch release.

## Scope

In-scope examples:

- A scan or rule that writes to, stages, commits or executes anything inside
  the reviewed repository without an explicit user confirmation.
- Path traversal that escapes the chosen project folder or the app data dir.
- A confirmation nonce that can be reused, forged or bypassed.
- Leaking a detected secret value into logs, history, exported reports or the
  Ollama prompt unmasked.
- Webview/CSP weakening, or a Tauri capability granting more than the frontend needs.

Out of scope: findings AgentGuard reports about *your* project (those are the
product), theoretical issues requiring a locally compromised machine, and
missing code signing (tracked publicly on the roadmap).

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ security fixes |
| < 0.1 | ❌ |

## Disclosure

We follow coordinated disclosure: fixes ship in a release, then the advisory is
published with credit to the reporter (unless they prefer to stay anonymous).
