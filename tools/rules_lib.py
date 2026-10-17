"""Shared helper for authoring the AgentGuard rule catalog.

The catalog is authored in Python (so regular expressions can be written as raw
strings and JSON escaping is handled by ``json``) and compiled to
``src-tauri/resources/rules.json``, which is embedded into the Rust binary with
``include_str!`` at build time.

Keep every user-facing string bilingual: English first (primary), Persian
second.
"""

from __future__ import annotations

RULES: list[dict] = []


def rule(
    id: str,
    engine: str,
    category: str,
    severity: str,
    *,
    confidence: float = 0.8,
    patterns: list[str] | None = None,
    target: str = "added",
    include: tuple[str, ...] = ("**",),
    exclude: tuple[str, ...] = (),
    negative: list[str] | None = None,
    require_all: bool = False,
    heuristic: str | None = None,
    redactable: bool = False,
    cwe: tuple[str, ...] = (),
    tags: tuple[str, ...] = (),
    refs: tuple[str, ...] = (),
    title: tuple[str, str] = ("", ""),
    description: tuple[str, str] = ("", ""),
    remediation: tuple[str, str] = ("", ""),
) -> None:
    """Register one detection rule."""
    if patterns is None and heuristic is None:
        raise ValueError(f"{id}: needs patterns or heuristic")
    RULES.append(
        {
            "id": id,
            "engine": engine,
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "cwe": list(cwe),
            "tags": list(tags),
            "include": list(include),
            "exclude": list(exclude),
            "target": target,
            "patterns": list(patterns or []),
            "negative": list(negative or []),
            "require_all": require_all,
            "heuristic": heuristic,
            "redactable": redactable,
            "references": list(refs),
            "text": {
                "title": {"en": title[0], "fa": title[1]},
                "description": {"en": description[0], "fa": description[1]},
                "remediation": {"en": remediation[0], "fa": remediation[1]},
            },
        }
    )
