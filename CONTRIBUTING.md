# Contributing to AgentGuard

Thanks for your interest! AgentGuard is a small codebase with a big rule
catalog, so the highest-leverage contribution is usually a detection rule.

Persian summary at the bottom · خلاصه فارسی در پایان

## Getting started

```bash
git clone https://github.com/Manixpcshot/agentguard-desktop.git
cd agentguard-desktop
npm install
npm run tauri dev
```

Prerequisites: Node.js ≥ 20, Rust ≥ 1.77 (`rustup`), WebView2 runtime on
Windows. On Linux install `libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev`.

Useful commands:

| Command | Purpose |
|---|---|
| `npm run typecheck` | TypeScript only |
| `npm run test:ui` | Vite dev server for the UI (Tauri APIs unavailable → demo mode is not implemented, so prefer `tauri dev`) |
| `npm run rules:gen` | Regenerate `src-tauri/resources/rules.json` |
| `npm run rules:check` | Validate the catalog (needs Python 3.9+) |
| `cd src-tauri && cargo test` | Rust unit tests |
| `cd src-tauri && cargo clippy` | Lints (CI runs them, advisory) |

## Adding a detection rule

1. Open the matching source in `tools/` — `rules_secrets.py`,
   `rules_dangerous.py`, `rules_security.py`, `rules_tests.py`,
   `rules_suspicious.py`, `rules_supply_chain.py`, `rules_ci_cd.py`.
2. Add a `rule(...)` entry. Required fields include `id`, `engine`, `severity`,
   `title_en/fa`, `desc_en/fa`, `fix_en/fa`, plus `patterns` and/or `heuristic`.
3. Keep regexes **Rust `regex` compatible**: no lookahead/lookbehind, no
   backreferences. Use a `heuristic` for context-sensitive logic.
4. Provide both English and Persian text. If your Persian is imperfect, still
   submit it — reviewers will help.
5. Run `npm run rules:gen && npm run rules:check`, then commit the regenerated
   `rules.json` together with your Python change (CI fails if they drift).
6. Open a PR describing the false positive/negative it fixes, ideally with a
   sample snippet.

## Adding a heuristic

Implement it in `src-tauri/src/engines/heuristics.rs`, register the name in the
dispatch table, then reference that name from a rule's `heuristic` field.
Add a unit test in the same file.

## Localization

- UI strings: `src/i18n/en.ts` and `src/i18n/fa.ts` — keys must stay in sync
  (TypeScript enforces this).
- Rule knowledge: the catalog (`*_en` / `*_fa` fields).
- Reports switch to RTL automatically when Persian is selected.

## Style

- Rust: `cargo fmt`, avoid `unwrap()` in library code paths, return `AppResult`.
- TypeScript: strict mode is on, `noUnusedLocals` included.
- Keep the UI dark-first and honour `dir` for RTL.
- Do not add runtime dependencies without a comment explaining why.

## Process

1. Fork and branch from `main`.
2. Keep changes focused; one rule family or one feature per PR.
3. Make sure `npm run typecheck`, `cargo test` and the catalog check pass —
   CI runs all three.
4. Security problems in AgentGuard itself go to [SECURITY.md](SECURITY.md),
   not to a public issue.

---

## مشارکت در ایجنت‌گارد (خلاصه)

مؤثرترین مشارکت معمولاً افزودن **قانون تشخیص** است:

1. در `tools/rules_*.py` یک `rule(...)` با متن انگلیسی **و فارسی** اضافه کنید.
2. عبارات منظم باید با کرت `regex` راست سازگار باشند (بدون lookaround/backreference)؛
   منطق زمینه‌ای را با `heuristic` بنویسید.
3. `npm run rules:gen && npm run rules:check` را اجرا کنید و `rules.json`
   بازتولیدشده را همراه تغییر پایتون کامیت کنید.
4. برای اجرای محلی: `npm install` سپس `npm run tauri dev` (Node ≥ 20، Rust ≥ 1.77).
5. مسائل امنیتی خود برنامه را در [SECURITY.md](SECURITY.md) گزارش کنید، نه در issue عمومی.
