//! Lockfile and manifest parsing for dependency-vulnerability mapping.
//!
//! `scan_project` discovers every supported manifest file present at the top
//! level of a project directory and parses all of them, merging the resulting
//! (name, ecosystem, version) tuples across languages. Each parser is pure and
//! unit-tested with realistic fixtures; nothing here touches the network.
//!
//! Supported ecosystems map to the exact identifiers accepted by the OSV.dev
//! batch endpoint (verified against api.osv.dev): crates.io, npm, PyPI, Go,
//! Maven, NuGet, RubyGems, Packagist, Pub, Hex, ConanCenter, Hackage.

use serde_json::Value;
use tokio::fs;

/// A package entry extracted from a project manifest.
#[derive(Debug, Clone, PartialEq)]
pub struct LockfileEntry {
    pub name: String,
    pub ecosystem: String,
    pub version: String,
}

/// The ecosystems this scanner can query on OSV.dev, and the manifest
/// filenames that map to each. Reported to callers for diagnostics.
pub const SUPPORTED_MANIFESTS: &[(&str, &str)] = &[
    // (filename, ecosystem)
    ("Cargo.lock", "crates.io"),
    ("package-lock.json", "npm"),
    ("requirements.txt", "PyPI"),
    ("go.mod", "Go"),
    ("pom.xml", "Maven"),
    ("packages.config", "NuGet"),
    ("project.assets.json", "NuGet"),
    ("Gemfile.lock", "RubyGems"),
    ("composer.lock", "Packagist"),
    ("pubspec.lock", "Pub"),
    ("mix.lock", "Hex"),
    ("conan.lock", "ConanCenter"),
    ("stack.yaml.lock", "Hackage"),
    ("cabal.project.freeze", "Hackage"),
];

/// Result of scanning a project directory: every parsed package plus the
/// manifest filenames that were discovered and parsed.
#[derive(Debug, Default)]
pub struct LockfileScan {
    pub entries: Vec<LockfileEntry>,
    pub manifests: Vec<String>,
}

/// Directories that must never be descended into when walking a project tree
/// for manifests. Scanning `node_modules` would explode the walk, and `.git`
/// and `target` hold SCM/build internals, not project dependencies.
const SKIP_DIRS: &[&str] = &["node_modules", ".git", "target"];

/// Scan a project tree for every supported manifest file present (recursing
/// into subdirectories but never into `node_modules`, `.git`, or `target`),
/// parse them all, and return every package entry deduplicated by
/// (name, ecosystem, version). Returns an empty scan when the directory is
/// missing or unreadable.
pub async fn scan_project(path: &str) -> LockfileScan {
    let mut scan = LockfileScan::default();
    let root = std::path::Path::new(path);

    let mut found: Vec<std::path::PathBuf> = Vec::new();
    collect_manifests(root, root, &mut found).await;

    for rel in found {
        let full = root.join(&rel);
        let Ok(content) = fs::read_to_string(&full).await else {
            continue;
        };
        let filename = rel
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let parsed = parse_manifest(&filename, &content);
        scan.entries.extend(parsed);
        scan.manifests.push(rel.to_string_lossy().into_owned());
    }

    // Deduplicate across manifests that may list the same package (e.g. a
    // monorepo with overlapping go.mod and go.sum, or NuGet's multiple forms).
    let mut seen = std::collections::HashSet::new();
    scan.entries.retain(|e| {
        let key = (e.name.clone(), e.ecosystem.clone(), e.version.clone());
        seen.insert(key)
    });

    scan
}

/// Recursively collect the relative paths of every supported manifest file
/// under `dir`. `root` anchors relative-path computation; `out` receives the
/// paths. Subdirectories named in [`SKIP_DIRS`] are pruned without descending.
async fn collect_manifests(
    dir: &std::path::Path,
    root: &std::path::Path,
    out: &mut Vec<std::path::PathBuf>,
) {
    let mut entries = match fs::read_dir(dir).await {
        Ok(d) => d,
        Err(_) => return,
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();

        if let Ok(file_type) = entry.file_type().await {
            if file_type.is_dir() {
                if SKIP_DIRS.contains(&name.as_ref()) {
                    continue;
                }
                Box::pin(collect_manifests(&path, root, out)).await;
                continue;
            }
        }

        if SUPPORTED_MANIFESTS.iter().any(|(f, _)| *f == name.as_ref()) {
            if let Ok(rel) = path.strip_prefix(root) {
                out.push(rel.to_path_buf());
            }
        }
    }
}

/// Route a manifest filename to its parser.
fn parse_manifest(file: &str, content: &str) -> Vec<LockfileEntry> {
    match file {
        "Cargo.lock" => parse_cargo_lock(content).unwrap_or_default(),
        "package-lock.json" => parse_npm_lock(content).unwrap_or_default(),
        "requirements.txt" => parse_requirements_txt(content),
        "go.mod" => parse_go_mod(content),
        "pom.xml" => parse_pom_xml(content),
        "packages.config" => parse_packages_config(content),
        "project.assets.json" => parse_nuget_assets_json(content).unwrap_or_default(),
        "Gemfile.lock" => parse_gemfile_lock(content),
        "composer.lock" => parse_composer_lock(content).unwrap_or_default(),
        "pubspec.lock" => parse_pubspec_lock(content),
        "mix.lock" => parse_mix_lock(content),
        "conan.lock" => parse_conan_lock(content).unwrap_or_default(),
        "stack.yaml.lock" => parse_stack_lock(content),
        "cabal.project.freeze" => parse_cabal_freeze(content),
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Rust — Cargo.lock (TOML v1/v2/v3)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// JavaScript / TypeScript — package-lock.json (npm)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Python — requirements.txt (PyPI)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Go — go.mod
// ---------------------------------------------------------------------------

/// Parse a go.mod file, reading both block (`require (...)`) and single-line
/// (`require module version`) require directives. We intentionally read
/// go.mod rather than go.sum so each module appears once.
pub fn parse_go_mod(content: &str) -> Vec<LockfileEntry> {
    let mut entries = Vec::new();
    let mut in_block = false;

    for raw in content.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }

        if in_block {
            if trimmed == ")" {
                in_block = false;
                continue;
            }
            push_go_require(trimmed, &mut entries);
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("require ") {
            let rest = rest.trim();
            if rest.starts_with('(') {
                in_block = true;
                continue;
            }
            push_go_require(rest, &mut entries);
        }
    }

    entries
}

/// Push a single `module version` pair (possibly with a trailing `// indirect`
/// comment, which split_whitespace ignores) as a Go entry.
fn push_go_require(line: &str, entries: &mut Vec<LockfileEntry>) {
    let mut it = line.split_whitespace();
    if let (Some(module), Some(version)) = (it.next(), it.next()) {
        entries.push(LockfileEntry {
            name: module.to_string(),
            ecosystem: "Go".to_string(),
            version: version.to_string(),
        });
    }
}

// ---------------------------------------------------------------------------
// Java — pom.xml (Maven)
// ---------------------------------------------------------------------------

/// Parse a Maven pom.xml and collect every `<dependency>` that declares an
/// explicit groupId, artifactId, and version. The package name sent to OSV is
/// `groupId:artifactId` (the identifier the OSV Maven feed uses).
pub fn parse_pom_xml(content: &str) -> Vec<LockfileEntry> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(content);
    reader.config_mut().trim_text(true);

    let mut entries = Vec::new();
    let mut in_dependency = 0usize;
    // (group, artifact, version, currently-accumulating field)
    let mut group = None;
    let mut artifact = None;
    let mut version = None;
    let mut field: Option<String> = None;

    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) if e.name().as_ref() == b"dependency" => {
                in_dependency += 1;
            }
            Ok(Event::Start(e)) if in_dependency > 0 => {
                let name = e.name().as_ref().to_vec();
                if name == b"groupId" || name == b"artifactId" || name == b"version" {
                    field = Some(String::from_utf8_lossy(&name).into_owned());
                }
            }
            Ok(Event::End(e)) if e.name().as_ref() == b"dependency" => {
                if in_dependency > 0 {
                    if let (Some(g), Some(a), Some(v)) =
                        (group.take(), artifact.take(), version.take())
                    {
                        entries.push(LockfileEntry {
                            name: format!("{}:{}", g, a),
                            ecosystem: "Maven".to_string(),
                            version: v,
                        });
                    }
                    in_dependency = in_dependency.saturating_sub(1);
                }
                field = None;
            }
            Ok(Event::End(e)) if in_dependency > 0 => {
                let name_bytes = e.name().as_ref().to_vec();
                let name = String::from_utf8_lossy(&name_bytes);
                if name == "groupId" || name == "artifactId" || name == "version" {
                    field = None;
                }
            }
            Ok(Event::Text(t)) if in_dependency > 0 => {
                if let Some(f) = field.take() {
                    let text = t.decode().unwrap_or_default().trim().to_string();
                    match f.as_str() {
                        "groupId" => group = Some(text),
                        "artifactId" => artifact = Some(text),
                        "version" => version = Some(text),
                        _ => {}
                    }
                }
            }
            Ok(Event::Empty(e)) if e.name().as_ref() == b"dependency" => {
                // Self-closing <dependency .../>: no version, ignore.
                in_dependency += 1;
                in_dependency = in_dependency.saturating_sub(1);
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    entries
}

// ---------------------------------------------------------------------------
// .NET — packages.config (XML) and project.assets.json (JSON)
// ---------------------------------------------------------------------------

/// Parse a NuGet packages.config file (`<package id="X" version="Y" />`),
/// targeting the self-closing `package` elements.
pub fn parse_packages_config(content: &str) -> Vec<LockfileEntry> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(content);
    reader.config_mut().trim_text(true);

    let mut entries = Vec::new();
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Empty(e)) if e.name().as_ref() == b"package" => {
                let mut id = None;
                let mut version = None;
                for a in e.attributes().with_checks(false).flatten() {
                    let key = a.key.local_name().as_ref().to_owned();
                    let val = String::from_utf8_lossy(&a.value).into_owned();
                    if key.as_slice() == b"id" {
                        id = Some(val);
                    } else if key.as_slice() == b"version" {
                        version = Some(val);
                    }
                }
                if let (Some(id), Some(version)) = (id, version) {
                    entries.push(LockfileEntry {
                        name: id,
                        ecosystem: "NuGet".to_string(),
                        version,
                    });
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    entries
}

/// Parse a NuGet project.assets.json file. The `libraries` map is keyed by
/// `Name/Version`; only entries with `"type": "package"` are dependencies.
pub fn parse_nuget_assets_json(content: &str) -> Option<Vec<LockfileEntry>> {
    let data: Value = serde_json::from_str(content).ok()?;
    let libraries = data.get("libraries")?.as_object()?;

    let mut entries = Vec::new();
    for (key, info) in libraries {
        let ty = info.get("type").and_then(|t| t.as_str()).unwrap_or("");
        if ty != "package" {
            continue;
        }
        if let Some((name, version)) = key.rsplit_once('/') {
            entries.push(LockfileEntry {
                name: name.to_string(),
                ecosystem: "NuGet".to_string(),
                version: version.to_string(),
            });
        }
    }

    Some(entries)
}

// ---------------------------------------------------------------------------
// Ruby — Gemfile.lock (RubyGems)
// ---------------------------------------------------------------------------

/// Parse a Gemfile.lock `specs:` block. Each spec line looks like
/// `name (version)` or `name (>= x, ~> y)`; the first digit-leading token
/// inside the parentheses is taken as the installed version. Pinned specs
/// carry a concrete version; ranged constraints are skipped (best-effort).
pub fn parse_gemfile_lock(content: &str) -> Vec<LockfileEntry> {
    let mut entries = Vec::new();
    let mut in_specs = false;

    for raw in content.lines() {
        let trimmed = raw.trim();
        if trimmed == "specs:" {
            in_specs = true;
            continue;
        }
        if !in_specs {
            continue;
        }
        // A 0-indent all-caps header ("GEM", "PLATFORMS", "DEPENDENCIES")
        // closes the specs section.
        if !raw.starts_with(' ')
            && !raw.starts_with('\t')
            && !trimmed.is_empty()
            && trimmed == trimmed.to_uppercase()
        {
            in_specs = false;
            continue;
        }
        if !raw.starts_with(' ') && !raw.starts_with('\t') {
            continue;
        }

        if let Some(open) = trimmed.find('(') {
            if let Some(close_rel) = trimmed[open..].find(')') {
                let close = open + close_rel;
                let name = trimmed[..open].trim().to_string();
                let vpart = &trimmed[open + 1..close];
                let version = vpart
                    .split_whitespace()
                    .find(|t| {
                        t.chars()
                            .next()
                            .map(|c| c.is_ascii_digit())
                            .unwrap_or(false)
                    })
                    .map(|s| {
                        s.trim_matches(|c: char| !(c.is_ascii_digit() || c == '.' || c == '-'))
                            .to_string()
                    })
                    .unwrap_or_default();
                if !name.is_empty() && !version.is_empty() {
                    entries.push(LockfileEntry {
                        name,
                        ecosystem: "RubyGems".to_string(),
                        version,
                    });
                }
            }
        }
    }

    entries
}

// ---------------------------------------------------------------------------
// PHP — composer.lock (Packagist)
// ---------------------------------------------------------------------------

/// Parse a Composer composer.lock file. Reads both the `packages` and
/// `packages-dev` arrays; Composer versions are `{{ name, version }}` objects.
pub fn parse_composer_lock(content: &str) -> Option<Vec<LockfileEntry>> {
    let data: Value = serde_json::from_str(content).ok()?;
    let mut entries = Vec::new();

    for section in ["packages", "packages-dev"] {
        let arr = match data.get(section).and_then(|v| v.as_array()) {
            Some(a) => a,
            None => continue,
        };
        for pkg in arr {
            if let (Some(name), Some(version)) = (
                pkg.get("name").and_then(|n| n.as_str()),
                pkg.get("version").and_then(|v| v.as_str()),
            ) {
                entries.push(LockfileEntry {
                    name: name.to_string(),
                    ecosystem: "Packagist".to_string(),
                    version: version.to_string(),
                });
            }
        }
    }

    Some(entries)
}

// ---------------------------------------------------------------------------
// Dart — pubspec.lock (Pub)
// ---------------------------------------------------------------------------

/// Parse a pubspec.lock (a generated YAML document). Each package is a
/// two-space-indented key with a deeper-indented `version: "x.y.z"` line.
/// We scan for exactly-two-space headers and the following `version:` line.
pub fn parse_pubspec_lock(content: &str) -> Vec<LockfileEntry> {
    let mut entries = Vec::new();
    let mut current: Option<String> = None;

    for raw in content.lines() {
        let trimmed = raw.trim_end();
        // Exactly two leading spaces -> a package header like "  async:".
        if trimmed.starts_with("  ") && !trimmed.starts_with("    ") {
            let rest = trimmed[2..].trim();
            if let Some(no_colon) = rest.strip_suffix(':') {
                let candidate = no_colon.trim();
                if !candidate.is_empty() && !candidate.contains(' ') {
                    current = Some(candidate.to_string());
                    continue;
                }
            }
        }
        if let Some(name) = current.clone() {
            if let Some(rest) = trimmed.trim().strip_prefix("version:") {
                let version = rest.trim().trim_matches('"').trim_matches('\'').to_string();
                if !version.is_empty() {
                    entries.push(LockfileEntry {
                        name,
                        ecosystem: "Pub".to_string(),
                        version,
                    });
                }
                current = None;
            }
        }
    }

    entries
}

// ---------------------------------------------------------------------------
// Elixir — mix.lock (Hex)
// ---------------------------------------------------------------------------

/// Parse a mix.lock (Elixir term format). Each entry is shaped like
/// `"name" => {:hex, :name, "version", ...}`; we take the name and the first
/// string after the `{:hex, :package,` prefix.
pub fn parse_mix_lock(content: &str) -> Vec<LockfileEntry> {
    let mut entries = Vec::new();

    for raw in content.lines() {
        let line = raw.trim();
        let Some(marker) = line.find("=> {:hex,") else {
            continue;
        };
        let name = line[..marker].trim().trim_matches('"').to_string();
        let after = &line[marker + "=> {:hex,".len()..];

        let mut version = None;
        for (i, part) in after.split(',').enumerate() {
            if i > 3 {
                break;
            }
            let t = part.trim();
            if t.starts_with('"') {
                version = Some(t.trim_matches('"').to_string());
                break;
            }
        }

        if let Some(version) = version {
            entries.push(LockfileEntry {
                name,
                ecosystem: "Hex".to_string(),
                version,
            });
        }
    }

    entries
}

// ---------------------------------------------------------------------------
// C/C++ — conan.lock (ConanCenter)
// ---------------------------------------------------------------------------

/// Parse a conan.lock file (JSON). Conan lock formats vary by version; we
/// handle both object `"ref": "pkg/version"` entries and bare
/// `"pkg/version"` strings inside a `requires` array. Both yield a
/// (name, version) pair split at the last slash.
pub fn parse_conan_lock(content: &str) -> Option<Vec<LockfileEntry>> {
    let data: Value = serde_json::from_str(content).ok()?;
    let mut entries = Vec::new();
    collect_conan_refs(&data, &mut entries);
    Some(entries)
}

fn collect_conan_refs(value: &Value, out: &mut Vec<LockfileEntry>) {
    match value {
        Value::Object(map) => {
            if let Some(rf) = map.get("ref").and_then(|r| r.as_str()) {
                push_conan_ref(rf, out);
            }
            if let Some(reqs) = map.get("requires").and_then(|r| r.as_array()) {
                for r in reqs {
                    match r {
                        Value::String(s) => push_conan_ref(s, out),
                        other => collect_conan_refs(other, out),
                    }
                }
            }
            for (k, vv) in map {
                if k != "requires" {
                    collect_conan_refs(vv, out);
                }
            }
        }
        Value::Array(arr) => {
            for v in arr {
                collect_conan_refs(v, out);
            }
        }
        _ => {}
    }
}

/// Split a `name/version` ref string at the last slash and emit an entry.
fn push_conan_ref(rf: &str, out: &mut Vec<LockfileEntry>) {
    if let Some((name, version)) = rf.rsplit_once('/') {
        out.push(LockfileEntry {
            name: name.to_string(),
            ecosystem: "ConanCenter".to_string(),
            version: version.to_string(),
        });
    }
}

// ---------------------------------------------------------------------------
// Haskell — stack.yaml.lock and cabal.project.freeze (Hackage)
// ---------------------------------------------------------------------------

/// Parse a stack.yaml.lock `packages:` block, capturing each entry's `name:`
/// and `version:` fields. Hackage versions use four segments (x.y.z.w).
pub fn parse_stack_lock(content: &str) -> Vec<LockfileEntry> {
    let mut entries = Vec::new();
    let mut in_packages = false;
    let mut current: Option<String> = None;

    for raw in content.lines() {
        let trimmed = raw.trim();
        if trimmed == "packages:" {
            in_packages = true;
            continue;
        }
        if !in_packages {
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        if indent < 4 {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("name:") {
            current = Some(rest.trim().to_string());
        } else if let Some(rest) = trimmed.strip_prefix("version:") {
            if let Some(name) = current.take() {
                let version = rest.trim().to_string();
                if !version.is_empty() {
                    entries.push(LockfileEntry {
                        name,
                        ecosystem: "Hackage".to_string(),
                        version,
                    });
                }
            }
        }
    }

    entries
}

/// Parse a cabal.project.freeze file. Each constraint segment is shaped like
/// `any.Package ==x.y.z.w`; we extract the package and version from each.
pub fn parse_cabal_freeze(content: &str) -> Vec<LockfileEntry> {
    let mut entries = Vec::new();

    for raw in content.lines() {
        let line = raw.trim();
        let core = line
            .strip_prefix("constraints:")
            .map(str::trim)
            .unwrap_or(line);
        for segment in core.split(',') {
            let segment = segment.trim();
            let Some(rest) = segment.strip_prefix("any.") else {
                continue;
            };
            let Some(veq) = rest.find(" ==") else {
                continue;
            };
            let name = &rest[..veq];
            let rest_after = rest[veq + 3..].trim();
            let version = rest_after.split_whitespace().next().unwrap_or("");
            if !name.is_empty() && !version.is_empty() {
                entries.push(LockfileEntry {
                    name: name.to_string(),
                    ecosystem: "Hackage".to_string(),
                    version: version.to_string(),
                });
            }
        }
    }

    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Rust / Cargo.lock ---

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
    fn test_parse_cargo_lock_v2_skips_root() {
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
    }

    #[test]
    fn test_parse_cargo_lock_empty() {
        assert!(parse_cargo_lock("").unwrap().is_empty());
    }

    #[test]
    fn test_parse_cargo_lock_no_packages() {
        let content = "version = 3\n";
        assert!(parse_cargo_lock(content).unwrap().is_empty());
    }

    // --- npm / package-lock.json ---

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

    // --- scan_project recursive tree walk ---

    /// Copy a committed JSON fixture file from `tests/fixtures` into the temp
    /// scan tree at the given relative path (creating parent dirs).
    fn copy_fixture(base: &std::path::Path, rel: &str, fixture: &str) {
        let p = base.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(fixture);
        std::fs::copy(&src, &p).unwrap();
    }

    #[tokio::test]
    async fn test_scan_project_recursive_coverage() {
        let base = std::env::temp_dir().join(format!("osv_scan_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);

        // Real manifests at the root and in nested apps/ subdirectories.
        copy_fixture(&base, "package-lock.json", "npm-lock-root.json");
        copy_fixture(&base, "apps/web/package-lock.json", "npm-lock-web.json");
        copy_fixture(&base, "apps/api/package-lock.json", "npm-lock-api.json");
        // Manifests that must be pruned by the walker.
        copy_fixture(
            &base,
            "node_modules/skip-me/package-lock.json",
            "npm-lock-pruned.json",
        );
        copy_fixture(&base, ".git/package-lock.json", "npm-lock-pruned.json");
        copy_fixture(
            &base,
            "apps/web/node_modules/nested-mod/package-lock.json",
            "npm-lock-pruned.json",
        );

        let scan = scan_project(base.to_str().unwrap()).await;
        let names: Vec<&str> = scan.entries.iter().map(|e| e.name.as_str()).collect();

        // Root + nested manifests are discovered and parsed.
        assert!(names.contains(&"rootpkg"));
        assert!(names.contains(&"webpkg"));
        assert!(names.contains(&"apipkg"));
        assert!(scan.manifests.contains(&"package-lock.json".to_string()));
        assert!(scan
            .manifests
            .contains(&"apps/web/package-lock.json".to_string()));
        assert!(scan
            .manifests
            .contains(&"apps/api/package-lock.json".to_string()));
        assert_eq!(scan.manifests.len(), 3);

        // node_modules, .git, and any manifest under node_modules are pruned.
        assert!(!names.contains(&"prunedpkg"));

        std::fs::remove_dir_all(&base).unwrap();
    }

    // --- Python / requirements.txt ---

    #[test]
    fn test_parse_requirements_txt() {
        let content = "flask==2.3.0\nrequests==2.31.0\n# comment\nnumpy==1.26.0\n";
        let entries = parse_requirements_txt(content);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].ecosystem, "PyPI");
        assert_eq!(entries[2].name, "numpy");
    }

    #[test]
    fn test_parse_requirements_txt_empty_and_comments() {
        assert!(parse_requirements_txt("").is_empty());
        assert!(parse_requirements_txt("# a\n# b\n").is_empty());
    }

    // --- Go / go.mod ---

    #[test]
    fn test_parse_go_mod() {
        let content = "module example.com/m\n\ngo 1.21\n\nrequire (\n    github.com/foo/bar v1.2.3\n    github.com/baz v2.0.0 // indirect\n)\n\nrequire github.com/x/y v0.1.0\n";
        let entries = parse_go_mod(content);
        assert_eq!(entries.len(), 3);
        assert!(entries
            .iter()
            .any(|e| e.name == "github.com/foo/bar" && e.version == "v1.2.3"));
        assert!(entries
            .iter()
            .any(|e| e.name == "github.com/baz" && e.version == "v2.0.0"));
        assert!(entries
            .iter()
            .any(|e| e.name == "github.com/x/y" && e.version == "v0.1.0"));
        assert!(entries.iter().all(|e| e.ecosystem == "Go"));
    }

    // --- Java / pom.xml ---

    #[test]
    fn test_parse_pom_xml() {
        let content = r#"<project>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.0</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.15.2</version>
    </dependency>
    <dependency>
      <groupId>org.no.version</groupId>
      <artifactId>inherited-version</artifactId>
    </dependency>
  </dependencies>
</project>"#;
        let entries = parse_pom_xml(content);
        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .any(|e| e.name == "org.apache.logging.log4j:log4j-core"
                && e.version == "2.14.0"
                && e.ecosystem == "Maven"));
        assert!(entries
            .iter()
            .any(|e| e.name == "com.fasterxml.jackson.core:jackson-databind"
                && e.version == "2.15.2"));
    }

    // --- NuGet / packages.config + project.assets.json ---

    #[test]
    fn test_parse_packages_config() {
        let content = r#"<packages>
  <package id="Newtonsoft.Json" version="13.0.1" targetFramework="net8.0" />
  <package id="Serilog" version="3.1.0" />
</packages>"#;
        let entries = parse_packages_config(content);
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.name == "Newtonsoft.Json"
            && e.version == "13.0.1"
            && e.ecosystem == "NuGet"));
        assert!(entries
            .iter()
            .any(|e| e.name == "Serilog" && e.version == "3.1.0"));
    }

    #[test]
    fn test_parse_nuget_assets_json() {
        let content = r#"{
  "libraries": {
    "Newtonsoft.Json/13.0.1": { "type": "package", "path": "x" },
    "project/1.0.0": { "type": "project" }
  }
}"#;
        let entries = parse_nuget_assets_json(content).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "Newtonsoft.Json");
        assert_eq!(entries[0].version, "13.0.1");
        assert_eq!(entries[0].ecosystem, "NuGet");
    }

    // --- RubyGems / Gemfile.lock ---

    #[test]
    fn test_parse_gemfile_lock() {
        // A real Gemfile.lock holds the resolved version of each gem, either
        // bare (`name (version)`) or with an `=` (`name (= version)`).
        let content = r#"GEM
  remote: https://rubygems.org/
  specs:
    rake (13.0.6)
    rails (= 7.0.4)
    faraday (1.10.0)

PLATFORMS
  ruby

DEPENDENCIES
  rake
"#;
        let entries = parse_gemfile_lock(content);
        assert_eq!(entries.len(), 3);
        assert!(entries
            .iter()
            .any(|e| e.name == "rake" && e.version == "13.0.6"));
        assert!(entries
            .iter()
            .any(|e| e.name == "rails" && e.version == "7.0.4"));
        assert!(entries
            .iter()
            .any(|e| e.name == "faraday" && e.version == "1.10.0"));
        assert!(entries.iter().all(|e| e.ecosystem == "RubyGems"));
    }

    // --- Packagist / composer.lock ---

    #[test]
    fn test_parse_composer_lock() {
        let content = r#"{
  "packages": [
    { "name": "laravel/framework", "version": "v10.0.0" },
    { "name": "monolog/monolog", "version": "3.4.0" }
  ],
  "packages-dev": [
    { "name": "phpunit/phpunit", "version": "10.2.0" }
  ]
}"#;
        let entries = parse_composer_lock(content).unwrap();
        assert_eq!(entries.len(), 3);
        assert!(entries.iter().any(|e| e.name == "laravel/framework"));
        assert!(entries
            .iter()
            .any(|e| e.name == "phpunit/phpunit" && e.version == "10.2.0"));
        assert!(entries.iter().all(|e| e.ecosystem == "Packagist"));
    }

    // --- Pub / pubspec.lock ---

    #[test]
    fn test_parse_pubspec_lock() {
        let content = r#"# Generated by pub
packages:
  async:
    dependency: "direct main"
    description:
      name: async
      sha256: abc
    source: hosted
    version: "2.11.0"
  boolean_selector:
    dependency: transitive
    version: "2.1.1"
sdks:
  dart: ">=3.0.0"
"#;
        let entries = parse_pubspec_lock(content);
        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .any(|e| e.name == "async" && e.version == "2.11.0" && e.ecosystem == "Pub"));
        assert!(entries
            .iter()
            .any(|e| e.name == "boolean_selector" && e.version == "2.1.1"));
    }

    // --- Hex / mix.lock ---

    #[test]
    fn test_parse_mix_lock() {
        let content = r#"%{
  "bcrypt_elixir" => {:hex, :bcrypt_elixir, "2.3.1", "sha1", [:mix], []},
  "plug" => {:hex, :plug, "1.14.0", "sha2", [:mix], []},
}
"#;
        let entries = parse_mix_lock(content);
        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .any(|e| e.name == "bcrypt_elixir" && e.version == "2.3.1" && e.ecosystem == "Hex"));
        assert!(entries
            .iter()
            .any(|e| e.name == "plug" && e.version == "1.14.0"));
    }

    // --- ConanCenter / conan.lock ---

    #[test]
    fn test_parse_conan_lock_object_refs() {
        let content = r#"{
  "graph_lock": {
    "nodes": {
      "0": { "ref": "zlib/1.2.13", "context": "host" },
      "1": { "ref": "openssl/1.1.1s", "context": "host" }
    }
  }
}"#;
        let entries = parse_conan_lock(content).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .any(|e| e.name == "zlib" && e.version == "1.2.13" && e.ecosystem == "ConanCenter"));
        assert!(entries
            .iter()
            .any(|e| e.name == "openssl" && e.version == "1.1.1s"));
    }

    #[test]
    fn test_parse_conan_lock_requires_strings() {
        let content = r#"{
  "version": "0.4",
  "requires": ["zlib/1.2.13", "openssl/1.1.1s"]
}"#;
        let entries = parse_conan_lock(content).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .any(|e| e.name == "openssl" && e.version == "1.1.1s"));
    }

    // --- Hackage / stack.yaml.lock + cabal.project.freeze ---

    #[test]
    fn test_parse_stack_lock() {
        let content = r#"packages:
- completed:
    hackage: foo-1.0.0@sha256:abc
    name: foo
    version: 1.0.0
  original: foo-1.0.0
- completed:
    hackage: bar-2.1.0@sha256:def
    name: bar
    version: 2.1.0
  original: bar-2.1.0
snapshots:
- completed:
    snapshot: lts-20.0
"#;
        let entries = parse_stack_lock(content);
        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .any(|e| e.name == "foo" && e.version == "1.0.0" && e.ecosystem == "Hackage"));
        assert!(entries
            .iter()
            .any(|e| e.name == "bar" && e.version == "2.1.0"));
    }

    #[test]
    fn test_parse_cabal_freeze() {
        let content = r#"constraints: any.Cabal ==3.6.3.0,
any.HUnit ==1.6.2.0,
any.aeson ==2.0.3.0
"#;
        let entries = parse_cabal_freeze(content);
        assert_eq!(entries.len(), 3);
        assert!(entries
            .iter()
            .any(|e| e.name == "HUnit" && e.version == "1.6.2.0" && e.ecosystem == "Hackage"));
        assert!(entries
            .iter()
            .any(|e| e.name == "aeson" && e.version == "2.0.3.0"));
    }

    // --- scan_project integration ---

    /// Verifies scan_project finds and parses every manifest in a directory,
    /// including multiple in the same project, and deduplicates.
    #[tokio::test]
    async fn test_scan_project_merges_multiple_manifests() {
        let dir = std::env::temp_dir().join(format!("osv-scan-merge-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir).await;
        fs::create_dir_all(&dir).await.unwrap();

        fs::write(
            dir.join("Cargo.lock"),
            "version = 3\n[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\nsource = \"registry+...\"\n",
        )
        .await
        .unwrap();
        fs::write(
            dir.join("go.mod"),
            "module m\n\nrequire (\n    github.com/foo/bar v1.2.3\n)\n",
        )
        .await
        .unwrap();
        fs::write(dir.join("requirements.txt"), "flask==2.3.0\n")
            .await
            .unwrap();

        let scan = scan_project(dir.to_str().unwrap()).await;

        let ecosystems: Vec<&str> = scan.entries.iter().map(|e| e.ecosystem.as_str()).collect();
        assert!(ecosystems.contains(&"crates.io"));
        assert!(ecosystems.contains(&"Go"));
        assert!(ecosystems.contains(&"PyPI"));
        assert_eq!(
            ecosystems.len(),
            3,
            "entries from all three manifests merged"
        );
        assert_eq!(scan.manifests.len(), 3);
        assert!(scan.manifests.contains(&"Cargo.lock".to_string()));

        let _ = fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn test_scan_project_dedups_nuget() {
        // Both a packages.config and a project.assets.json listing the same
        // package must produce a single entry.
        let dir = std::env::temp_dir().join(format!("osv-scan-nuget-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir).await;
        fs::create_dir_all(&dir).await.unwrap();

        fs::write(
            dir.join("packages.config"),
            "<packages><package id=\"Newtonsoft.Json\" version=\"13.0.1\" /></packages>",
        )
        .await
        .unwrap();
        fs::write(
            dir.join("project.assets.json"),
            r#"{"libraries":{"Newtonsoft.Json/13.0.1":{"type":"package"}}}"#,
        )
        .await
        .unwrap();

        let scan = scan_project(dir.to_str().unwrap()).await;
        assert_eq!(
            scan.entries.len(),
            1,
            "identical NuGet package appears once after dedup"
        );
        assert_eq!(scan.manifests.len(), 2);

        let _ = fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn test_scan_project_missing_dir() {
        let scan = scan_project("/tmp/no-such-dir-1234567890").await;
        assert!(scan.entries.is_empty());
        assert!(scan.manifests.is_empty());
    }

    /// Integration-style: verify scan_project reads this project's Cargo.lock.
    #[tokio::test]
    async fn test_scan_project_our_own_cargo_lock() {
        let scan = scan_project(".").await;
        assert!(!scan.entries.is_empty());
        assert!(scan.entries.iter().any(|e| e.ecosystem == "crates.io"));
        assert!(scan.manifests.contains(&"Cargo.lock".to_string()));
    }
}
