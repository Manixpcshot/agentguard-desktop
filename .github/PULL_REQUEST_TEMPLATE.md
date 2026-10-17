## Summary

<!-- What does this PR do? One or two sentences. -->

## Type

- [ ] New detection rule(s)
- [ ] New heuristic / engine
- [ ] Rust core change
- [ ] Frontend / UI change
- [ ] Localization (EN / FA)
- [ ] Docs
- [ ] CI / build
- [ ] Bug fix

## Details

<!-- Why this approach? Note any behaviour change for existing users. -->

## Checklist

- [ ] `npm run typecheck` passes
- [ ] `npm run build` passes
- [ ] `cd src-tauri && cargo test` passes (or I noted that CI covers it)
- [ ] Rule changes: `npm run rules:gen && npm run rules:check` run, and the
      regenerated `src-tauri/resources/rules.json` is committed with the
      `tools/*.py` change
- [ ] New regexes are Rust `regex` compatible (no lookaround / backreferences)
- [ ] New user-facing strings exist in **both** `src/i18n/en.ts` and `src/i18n/fa.ts`
- [ ] New rules include English **and** Persian `title`, `desc` and `fix`
- [ ] No mutation of user files or command execution was added without a
      confirmation nonce (see `src-tauri/src/safety.rs`)
- [ ] Docs / changelog updated where relevant

## Notes for reviewers

<!-- Screenshots welcome for UI changes. Mention follow-ups or known limits. -->
