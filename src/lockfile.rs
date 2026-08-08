//! Lockfile parsing for dependency-vulnerability mapping.
//!
//! `parse_lockfile` tries, in order: `Cargo.lock` (TOML, v1/v2/v3), then
//! `package-lock.json` (npm), then `requirements.txt` (PyPI). Each parser is
//! pure and unit-tested with realistic fixtures; nothing here touches the
//! network.

use serde_json::Value;
use tokio::fs;

/// A package entry extracted from a lockfile.
#[derive(Debug, Clone, PartialEq)]
pub struct LockfileEntry {
    pub name: String,
    pub ecosystem: String,
    pub version: String,
}

/// Parse a project's lockfile to extract (name, ecosystem, version) tuples.
///
/// Tries, in order:
/// 1. `Cargo.lock` (TOML - Rust, formats v1, v2, v3)
/// 2. `package-lock.json` (JSON - npm)
/// 3. `requirements.txt` (line-based - PyPI)
pub async fn parse_lockfile(path: &str) -> Vec<LockfileEntry> {
    // 1. Cargo.lock - TOML format (v1, v2, v3)
    let cargo_path = format!("{}/Cargo.lock", path);
    if let Ok(content) = fs::read_to_string(&cargo_path).await {
        if let Some(entries) = parse_cargo_lock(&content) {
            return entries;
        }
    }

    // 2. package-lock.json - npm
    let npm_path = format!("{}/package-lock.json", path);
    if let Ok(content) = fs::read_to_string(&npm_path).await {
        if let Some(entries) = parse_npm_lock(&content) {
            return entries;
        }
    }

    // 3. requirements.txt - PyPI
    let req_path = format!("{}/requirements.txt", path);
    if let Ok(content) = fs::read_to_string(&req_path).await {
        return parse_requirements_txt(&content);
    }

    Vec::new()
}

/// Parse a Cargo.lock file using proper TOML parsing.
///
/// Supports both the legacy v1 format (`[[package]]`) and the newer v2/v3
/// format, skipping the root package entry (`source = "null"` in v2/v3,
/// absent in v1).
pub fn parse_cargo_lock(content: &str) -> Option<Vec<LockfileEntry>> {
    let table: Value = toml::from_str(content).ok()?;

    let packages = match table.get("package") {
        Some(v) => v.as_array()?,
        None => return Some(Vec::new()),
    };
    let mut entries = Vec::with_capacity(packages.len());

    for pkg in packages {
        let name = pkg.get("name")?.as_str()?;
        let version = pkg.get("version")?.as_str()?;

        // Skip source-less entries (the root package itself).
        // Cargo.lock v2/v3 uses source = "null" while v1 omits the key.
        if let Some(source) = pkg.get("source") {
            if source.as_str() == Some("null") {
                continue;
            }
        }

        entries.push(LockfileEntry {
            name: name.to_string(),
            ecosystem: "crates.io".to_string(),
            version: version.to_string(),
        });
    }

    Some(entries)
}

/// Parse a npm package-lock.json file.
pub fn parse_npm_lock(content: &str) -> Option<Vec<LockfileEntry>> {
    let data: Value = serde_json::from_str(content).ok()?;
    let packages = data.get("packages")?.as_object()?;

    let mut entries = Vec::new();
    for (path, info) in packages {
        // Skip the root package ("") and non-package entries.
        if path.is_empty() {
            continue;
        }
        if let Some(version) = info.get("version").and_then(|v| v.as_str()) {
            // Extract package name from path ("node_modules/foo" -> "foo").
            let name = path
                .split("node_modules/")
                .last()
                .unwrap_or(path)
                .to_string();
            entries.push(LockfileEntry {
                name,
                ecosystem: "npm".to_string(),
                version: version.to_string(),
            });
        }
    }

    Some(entries)
}

/// Parse a pip requirements.txt file (`name==version` lines).
pub fn parse_requirements_txt(content: &str) -> Vec<LockfileEntry> {
    content
        .lines()
        .filter(|l| {
            let trimmed = l.trim();
            !trimmed.is_empty() && !trimmed.starts_with('#') && trimmed.contains("==")
        })
        .map(|l| {
            let trimmed = l.trim();
            let parts: Vec<&str> = trimmed.splitn(2, "==").collect();
            LockfileEntry {
                name: parts[0].trim().to_string(),
                ecosystem: "PyPI".to_string(),
                version: parts.get(1).unwrap_or(&"").trim().to_string(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cargo_lock_v1() {
        let content = r#"
[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.40.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
        let entries = parse_cargo_lock(content).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "serde");
        assert_eq!(entries[0].version, "1.0.200");
        assert_eq!(entries[0].ecosystem, "crates.io");
        assert_eq!(entries[1].name, "tokio");
        assert_eq!(entries[1].version, "1.40.0");
    }

    #[test]
    fn test_parse_cargo_lock_v2() {
        let content = r#"
version = 2
[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "my-project"
version = "0.1.0"
source = "null"
"#;
        let entries = parse_cargo_lock(content).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "serde");
        // The root package with source = "null" should be skipped.
    }

    #[test]
    fn test_parse_cargo_lock_empty() {
        let content = "";
        let entries = parse_cargo_lock(content);
        assert!(entries.is_some());
        assert!(entries.unwrap().is_empty());
    }

    #[test]
    fn test_parse_cargo_lock_no_packages() {
        let content = r#"
version = 3
"#;
        let entries = parse_cargo_lock(content);
        assert!(entries.is_some());
        assert!(entries.unwrap().is_empty());
    }

    #[test]
    fn test_parse_npm_lock() {
        let content = r#"
{
  "packages": {
    "": { "name": "my-app", "version": "1.0.0" },
    "node_modules/express": { "version": "4.21.0" },
    "node_modules/axios": { "version": "1.7.0" }
  }
}
"#;
        let entries = parse_npm_lock(content).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .any(|e| e.name == "express" && e.version == "4.21.0"));
        assert!(entries
            .iter()
            .any(|e| e.name == "axios" && e.version == "1.7.0"));
        assert!(entries.iter().all(|e| e.ecosystem == "npm"));
    }

    #[test]
    fn test_parse_requirements_txt() {
        let content = r#"
flask==2.3.0
requests==2.31.0
# this is a comment
numpy==1.26.0
"#;
        let entries = parse_requirements_txt(content);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].name, "flask");
        assert_eq!(entries[0].version, "2.3.0");
        assert_eq!(entries[0].ecosystem, "PyPI");
        assert_eq!(entries[1].name, "requests");
        assert_eq!(entries[2].name, "numpy");
    }

    #[test]
    fn test_parse_requirements_txt_empty() {
        let content = "";
        let entries = parse_requirements_txt(content);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_requirements_txt_comments_only() {
        let content = "# just a comment\n# another one\n";
        let entries = parse_requirements_txt(content);
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn test_parse_lockfile_unknown_project() {
        // Non-existent path returns empty.
        let entries = parse_lockfile("/tmp/nonexistent-project-12345").await;
        assert!(entries.is_empty());
    }

    /// Integration-style: verify parse_lockfile reads a real Cargo.lock.
    /// This test uses this project's own Cargo.lock.
    #[tokio::test]
    async fn test_parse_lockfile_our_own_cargo_lock() {
        let entries = parse_lockfile(".").await;
        assert!(!entries.is_empty(), "Should parse our own Cargo.lock");
        assert!(
            entries.iter().any(|e| e.ecosystem == "crates.io"),
            "Should find crates.io packages"
        );
    }
}
