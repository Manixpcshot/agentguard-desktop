#!/usr/bin/env python3
"""Validate the compiled rule catalog.

Checks performed:
  * JSON parses and has the expected schema
  * rule ids are unique and well formed
  * every rule carries English *and* Persian text
  * regular expressions avoid constructs the Rust `regex` crate rejects
    (lookaround, back-references) and compile under a compatible engine
  * globs are non-empty

Usage: python3 tools/check_rules.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "src-tauri" / "resources" / "rules.json"

ENGINES = {"secrets", "dangerous", "security", "tests", "suspicious", "supply_chain", "ci_cd"}
CATEGORIES = {
    "secret_leak", "dangerous_operation", "vulnerability", "test_integrity",
    "suspicious_change", "supply_chain", "ci_cd",
}
SEVERITIES = {"info", "low", "medium", "high", "critical"}
TARGETS = {"added", "removed", "file", "both"}

BANNED = [
    (re.compile(r"\(\?="), "lookahead (?= is unsupported by the Rust regex crate"),
    (re.compile(r"\(\?!"), "negative lookahead (?! is unsupported"),
    (re.compile(r"\(\?<[=!a-zA-Z]"), "lookbehind / named group syntax unsupported"),
    (re.compile(r"\\[1-9]"), "back-references are unsupported"),
]


def check_pattern(rule_id: str, pattern: str, errors: list[str]) -> None:
    for rx, why in BANNED:
        if rx.search(pattern):
            errors.append(f"{rule_id}: pattern {pattern!r}: {why}")
    try:
        re.compile(pattern)
    except re.error as exc:  # pragma: no cover - defensive
        errors.append(f"{rule_id}: pattern {pattern!r} does not compile: {exc}")


def main() -> int:
    if not CATALOG.exists():
        print(f"catalog missing: {CATALOG} (run tools/gen_rules.py first)")
        return 1
    data = json.loads(CATALOG.read_text(encoding="utf-8"))
    errors: list[str] = []
    rules = data.get("rules", [])
    ids: set[str] = set()

    if not isinstance(data.get("version"), int):
        errors.append("catalog: missing integer 'version'")

    for r in rules:
        rid = r.get("id", "<no id>")
        if rid in ids:
            errors.append(f"{rid}: duplicate id")
        ids.add(rid)
        if r.get("engine") not in ENGINES:
            errors.append(f"{rid}: bad engine {r.get('engine')!r}")
        if r.get("category") not in CATEGORIES:
            errors.append(f"{rid}: bad category {r.get('category')!r}")
        if r.get("severity") not in SEVERITIES:
            errors.append(f"{rid}: bad severity {r.get('severity')!r}")
        if r.get("target") not in TARGETS:
            errors.append(f"{rid}: bad target {r.get('target')!r}")
        if not isinstance(r.get("confidence"), (int, float)) or not 0.0 <= r["confidence"] <= 1.0:
            errors.append(f"{rid}: confidence out of range")
        if not r.get("include"):
            errors.append(f"{rid}: empty include globs")
        if not r.get("patterns") and not r.get("heuristic"):
            errors.append(f"{rid}: neither patterns nor heuristic")
        for p in r.get("patterns", []):
            check_pattern(rid, p, errors)
        for p in r.get("negative", []):
            check_pattern(rid, p, errors)
        text = r.get("text", {})
        for field in ("title", "description", "remediation"):
            block = text.get(field, {})
            for lang in ("en", "fa"):
                if not str(block.get(lang, "")).strip():
                    errors.append(f"{rid}: missing {lang} {field}")

    if errors:
        print(f"FAILED: {len(errors)} problem(s)")
        for e in errors:
            print("  -", e)
        return 1

    print(f"OK: {len(rules)} rules, catalog v{data['version']}, bilingual text complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
