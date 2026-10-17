#!/usr/bin/env python3
"""Compile the authored rule tables into the embedded JSON catalog.

Usage:  python3 tools/gen_rules.py
Output: src-tauri/resources/rules.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

import rules_lib  # noqa: E402
import rules_secrets_dangerous  # noqa: E402,F401
import rules_security_tests  # noqa: E402,F401
import rules_suspicious_supply_ci  # noqa: E402,F401

CATALOG_VERSION = 1
OUT = ROOT / "src-tauri" / "resources" / "rules.json"


def main() -> int:
    rules = rules_lib.RULES
    seen: dict[str, int] = {}
    for r in rules:
        if r["id"] in seen:
            raise SystemExit(f"duplicate rule id: {r['id']}")
        seen[r["id"]] = 1
        for lang in ("en", "fa"):
            for field in ("title", "description", "remediation"):
                text = r["text"][field][lang].strip()
                if not text:
                    raise SystemExit(f"{r['id']}: missing {lang} {field}")

    payload = {"version": CATALOG_VERSION, "rules": rules}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    engines: dict[str, int] = {}
    severities: dict[str, int] = {}
    for r in rules:
        engines[r["engine"]] = engines.get(r["engine"], 0) + 1
        severities[r["severity"]] = severities.get(r["severity"], 0) + 1
    print(f"wrote {OUT.relative_to(ROOT)} with {len(rules)} rules (catalog v{CATALOG_VERSION})")
    print("  engines:   ", ", ".join(f"{k}={v}" for k, v in sorted(engines.items())))
    print("  severities:", ", ".join(f"{k}={v}" for k, v in sorted(severities.items())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
