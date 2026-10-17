//! Rule catalog: loaded from the embedded `rules.json`, compiled once at start.

use crate::error::{AppError, AppResult};
use crate::models::{Category, Engine, Language, RuleTarget, RuleText, Severity};
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use regex::Regex;
use serde::Deserialize;

const RAW_CATALOG: &str = include_str!("../resources/rules.json");

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub id: String,
    pub engine: Engine,
    pub category: Category,
    pub severity: Severity,
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    #[serde(default)]
    pub cwe: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_include")]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default = "default_target")]
    pub target: RuleTarget,
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub negative: Vec<String>,
    #[serde(default)]
    pub require_all: bool,
    #[serde(default)]
    pub heuristic: Option<String>,
    #[serde(default)]
    pub redactable: bool,
    #[serde(default)]
    pub references: Vec<String>,
    pub text: RuleText,
}

fn default_confidence() -> f64 {
    0.8
}
fn default_include() -> Vec<String> {
    vec!["**".to_string()]
}
fn default_target() -> RuleTarget {
    RuleTarget::Added
}

#[derive(Debug, Deserialize)]
struct CatalogFile {
    version: u32,
    rules: Vec<Rule>,
}

#[derive(Debug)]
pub struct CompiledRule {
    pub rule: Rule,
    pub regexes: Vec<Regex>,
    pub negatives: Vec<Regex>,
    pub include: GlobSet,
    pub exclude: GlobSet,
}

impl CompiledRule {
    /// Glob match that also treats `**/x` as matching a root-level `x`.
    pub fn path_matches(&self, path: &str) -> bool {
        if self.exclude.is_match(path) || self.exclude.is_match(&format!("root/{path}")) {
            return false;
        }
        self.include.is_match(path) || self.include.is_match(&format!("root/{path}"))
    }

    pub fn negatives_match(&self, line: &str) -> bool {
        self.negatives.iter().any(|n| n.is_match(line))
    }

    pub fn localized(&self, lang: Language) -> RuleText {
        let _ = lang;
        self.rule.text.clone()
    }
}

#[derive(Debug)]
pub struct Catalog {
    pub version: u32,
    rules: Vec<CompiledRule>,
}

impl Catalog {
    pub fn load() -> AppResult<Catalog> {
        let file: CatalogFile = serde_json::from_str(RAW_CATALOG)
            .map_err(|e| AppError::Catalog(format!("embedded catalog is invalid: {e}")))?;
        let mut rules = Vec::with_capacity(file.rules.len());
        for rule in file.rules {
            let mut regexes = Vec::with_capacity(rule.patterns.len());
            for p in &rule.patterns {
                regexes.push(Regex::new(p).map_err(|e| {
                    AppError::Catalog(format!("rule {} bad pattern {:?}: {e}", rule.id, p))
                })?);
            }
            let mut negatives = Vec::with_capacity(rule.negative.len());
            for p in &rule.negative {
                negatives.push(Regex::new(p).map_err(|e| {
                    AppError::Catalog(format!("rule {} bad negative {:?}: {e}", rule.id, p))
                })?);
            }
            let include = build_globs(&rule.include)
                .map_err(|e| AppError::Catalog(format!("rule {}: {e}", rule.id)))?;
            let exclude = if rule.exclude.is_empty() {
                GlobSet::empty()
            } else {
                build_globs(&rule.exclude)
                    .map_err(|e| AppError::Catalog(format!("rule {}: {e}", rule.id)))?
            };
            rules.push(CompiledRule {
                rule,
                regexes,
                negatives,
                include,
                exclude,
            });
        }
        Ok(Catalog {
            version: file.version,
            rules,
        })
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &CompiledRule> {
        self.rules.iter()
    }

    pub fn for_engine(&self, engine: Engine) -> impl Iterator<Item = &CompiledRule> {
        self.rules.iter().filter(move |r| r.rule.engine == engine)
    }

    pub fn find(&self, id: &str) -> Option<&CompiledRule> {
        self.rules.iter().find(|r| r.rule.id == id)
    }
}

fn build_globs(patterns: &[String]) -> Result<GlobSet, String> {
    let mut builder = GlobSetBuilder::new();
    for p in patterns {
        let glob = GlobBuilder::new(p)
            .literal_separator(false)
            .case_insensitive(true)
            .backslash_escape(true)
            .build()
            .map_err(|e| format!("bad glob {p:?}: {e}"))?;
        builder.add(glob);
    }
    builder.build().map_err(|e| format!("bad glob set: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_loads_and_matches_paths() {
        let catalog = Catalog::load().expect("catalog loads");
        assert!(catalog.len() > 100, "expected a rich catalog");
        let rule = catalog
            .find("SEC-SECRET-AWS-ACCESS-KEY")
            .expect("aws rule present");
        assert!(rule.path_matches("src/deploy.ts"));
        assert!(rule.regexes[0].is_match("const k = \"AKIAIOSFODNN7EXAMPLE\";"));
        assert!(rule.negatives_match("AKIAIOSFODNN7EXAMPLE")); // documented example is filtered
    }

    #[test]
    fn glob_root_and_nested() {
        let catalog = Catalog::load().expect("catalog loads");
        let rule = catalog.find("SEC-SECRET-ENV-FILE").expect("env rule");
        assert!(rule.path_matches(".env"));
        assert!(rule.path_matches("apps/api/.env.local"));
        assert!(!rule.path_matches(".env.example"));
    }
}
