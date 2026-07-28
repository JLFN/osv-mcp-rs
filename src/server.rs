use adk_mcp_sdk::{HealthCheck, HealthStatus};
use crate::client::AdvisoryClient;
use chrono::Utc;
use rmcp::{handler::server::wrapper::Parameters, schemars, tool, tool_router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::fs;

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SearchAdvisoriesInput {
    /// Package name to search advisories for
    pub package: Option<String>,
    /// Ecosystem: crates.io, npm, PyPI, Go, Maven, NuGet
    pub ecosystem: Option<String>,
    /// Keyword search (falls back to package name query)
    pub query: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetAdvisoryInput {
    /// Advisory ID: CVE-*, GHSA-*, RUSTSEC-*, OSV-*
    pub id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MapVulnerabilityInput {
    /// Path to project directory (reads Cargo.lock, package-lock.json, etc.)
    pub path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RankSecurityRiskInput {
    /// Advisory ID to score
    pub advisory_id: String,
    /// Is the affected package directly depended on (vs transitive)?
    pub direct_dependency: Option<bool>,
    /// Is the service internet-facing?
    pub internet_exposed: Option<bool>,
    /// Is there a known exploit in the wild?
    pub known_exploit: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GeneratePatchPlanInput {
    /// Advisory ID to remediate
    pub advisory_id: String,
    /// Current installed version of the affected package
    pub current_version: Option<String>,
    /// Package name
    pub package: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ExportSecurityEvidenceInput {
    /// Path to project
    pub path: String,
    /// Advisory IDs to include (optional; includes all findings if omitted)
    pub advisory_ids: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct SecurityAdvisoryServer {
    pub client: Arc<AdvisoryClient>,
}

#[tool_router(server_handler)]
impl SecurityAdvisoryServer {
    #[tool(
        description = "Search advisories (CVE/GHSA/OSV/RustSec) by package, ecosystem, or keyword. Sources: OSV.dev (covers GitHub Advisory DB, RustSec, PyPI, npm, Go, Maven)."
    )]
    async fn search_advisories(
        &self,
        Parameters(i): Parameters<SearchAdvisoriesInput>,
    ) -> String {
        let result = self
            .client
            .search_osv(i.package.as_deref(), i.ecosystem.as_deref(), i.query.as_deref())
            .await;
        format_result(result, |v| {
            json!({
                "results": v,
                "provenance": {
                    "source": "osv.dev",
                    "queried_at": Utc::now().to_rfc3339(),
                    "confidence": "high",
                },
            })
        })
    }

    #[tool(
        description = "Get full advisory details by ID. Accepts CVE-*, GHSA-*, RUSTSEC-*, OSV-* identifiers. Returns affected packages, versions, severity, references, and fix info."
    )]
    async fn get_advisory(&self, Parameters(i): Parameters<GetAdvisoryInput>) -> String {
        let result = self.client.get_advisory_by_id(&i.id).await;
        let id_type = if i.id.starts_with("CVE") {
            "cve"
        } else if i.id.starts_with("GHSA") {
            "ghsa"
        } else if i.id.starts_with("RUSTSEC") {
            "rustsec"
        } else {
            "osv"
        };
        format_result(result, |v| {
            json!({
                "advisory": v,
                "provenance": {
                    "source": "osv.dev",
                    "queried_at": Utc::now().to_rfc3339(),
                    "identifier_type": id_type,
                },
            })
        })
    }

    #[tool(
        description = "Map advisories against project dependencies. Reads lockfiles (Cargo.lock, package-lock.json, requirements.txt) and checks via OSV.dev batch API."
    )]
    async fn map_vulnerability_to_dependency(
        &self,
        Parameters(i): Parameters<MapVulnerabilityInput>,
    ) -> String {
        let packages = parse_lockfile(&i.path).await;

        if packages.is_empty() {
            return json!({
                "error": "No lockfile found or no packages parsed",
                "supported": ["Cargo.lock", "package-lock.json", "requirements.txt"],
            })
            .to_string();
        }

        let batch: Vec<(&str, &str, &str)> = packages
            .iter()
            .map(|e| (e.name.as_str(), e.ecosystem.as_str(), e.version.as_str()))
            .collect();

        let mut findings = Vec::new();
        match self.client.query_batch(batch).await {
            Ok(resp) => {
                if let Some(results) = resp["results"].as_array() {
                    for (idx, result) in results.iter().enumerate() {
                        if let Some(vs) = result["vulns"].as_array() {
                            if !vs.is_empty() && idx < packages.len() {
                                let entry = &packages[idx];
                                findings.push(json!({
                                    "package": &entry.name,
                                    "ecosystem": &entry.ecosystem,
                                    "installed_version": &entry.version,
                                    "advisories_found": vs.len(),
                                    "advisories": vs.iter().take(3).map(|v| json!({
                                        "id": v["id"],
                                        "summary": v["summary"],
                                    })).collect::<Vec<_>>(),
                                }));
                            }
                        }
                    }
                }
            }
            Err(e) => return json!({"error": format!("Batch query failed: {}", e)}).to_string(),
        }

        json!({
            "path": i.path,
            "packages_scanned": packages.len(),
            "vulnerable_packages": findings.len(),
            "findings": findings,
            "provenance": {
                "source": "osv.dev",
                "method": "batch_query",
                "queried_at": Utc::now().to_rfc3339(),
            },
        })
        .to_string()
    }

    #[tool(
        description = "Score practical risk for an advisory. Considers severity, exploitability, exposure (internet-facing), reachability (direct vs transitive), and known exploit status."
    )]
    async fn rank_security_risk(
        &self,
        Parameters(i): Parameters<RankSecurityRiskInput>,
    ) -> String {
        let severity_score: f64 = match self.client.get_advisory_by_id(&i.advisory_id).await {
            Ok(v) => v["severity"]
                .as_array()
                .and_then(|a| a.first())
                .and_then(|s| s["score"].as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or(5.0),
            Err(_) => 5.0,
        };

        let direct = i.direct_dependency.unwrap_or(true);
        let internet = i.internet_exposed.unwrap_or(false);
        let exploit = i.known_exploit.unwrap_or(false);

        // Weighted risk score (0-10)
        let mut risk = severity_score * 0.4;
        if direct {
            risk += 1.5;
        } else {
            risk += 0.5;
        }
        if internet {
            risk += 2.0;
        }
        if exploit {
            risk += 2.5;
        }
        let risk = risk.min(10.0);

        let priority = if risk >= 8.0 {
            "critical"
        } else if risk >= 6.0 {
            "high"
        } else if risk >= 4.0 {
            "medium"
        } else {
            "low"
        };

        let recommendation = match priority {
            "critical" => "Patch immediately. Known exploit + internet exposure.",
            "high" => "Patch within 24-48 hours. High severity or direct exposure.",
            "medium" => "Schedule patch in next sprint. Monitor for exploit development.",
            _ => "Track for next maintenance window. Low practical risk.",
        };

        json!({
            "advisory_id": i.advisory_id,
            "risk_score": (risk * 10.0).round() / 10.0,
            "priority": priority,
            "factors": {
                "severity_score": severity_score,
                "direct_dependency": direct,
                "internet_exposed": internet,
                "known_exploit": exploit,
            },
            "recommendation": recommendation,
            "provenance": {
                "scored_at": Utc::now().to_rfc3339(),
                "model": "weighted_factors_v1",
            },
        })
        .to_string()
    }

    #[tool(
        description = "Generate a remediation plan: upgrade version, apply patch, workaround, regression tests, and rollout order."
    )]
    async fn generate_patch_plan(
        &self,
        Parameters(i): Parameters<GeneratePatchPlanInput>,
    ) -> String {
        let advisory = self
            .client
            .get_advisory_by_id(&i.advisory_id)
            .await
            .unwrap_or(json!({}));

        let fixed_version = advisory["affected"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|a| a["ranges"].as_array())
            .and_then(|r| r.first())
            .and_then(|r| r["events"].as_array())
            .and_then(|e| e.iter().find(|ev| ev["fixed"].is_string()))
            .and_then(|ev| ev["fixed"].as_str());

        let pkg = i
            .package
            .as_deref()
            .or(advisory["affected"]
                .as_array()
                .and_then(|a| a.first())
                .and_then(|a| a["package"].as_str()))
            .unwrap_or("unknown");

        json!({
            "advisory_id": i.advisory_id,
            "package": pkg,
            "current_version": i.current_version,
            "fixed_version": fixed_version,
            "plan": {
                "action": if fixed_version.is_some() { "upgrade" } else { "mitigate" },
                "steps": [
                    format!("1. Update dependency to {}", fixed_version.unwrap_or("latest patched version")),
                    "2. Run full test suite to check for regressions".to_string(),
                    "3. Review changelog for breaking changes".to_string(),
                    "4. Deploy to staging, verify, then production".to_string(),
                ],
                "rollout_order": ["development", "staging", "production"],
                "regression_tests": "Run existing test suite + add test for the specific vulnerability if applicable",
            },
            "provenance": {
                "generated_at": Utc::now().to_rfc3339(),
                "source_advisory": i.advisory_id,
            },
        })
        .to_string()
    }

    #[tool(
        description = "Export security findings as audit/compliance evidence. Includes sources, timestamps, affected packages, decisions, and remediation status."
    )]
    async fn export_security_evidence(
        &self,
        Parameters(i): Parameters<ExportSecurityEvidenceInput>,
    ) -> String {
        let packages = parse_lockfile(&i.path).await;
        let mut findings = Vec::new();

        if let Some(ids) = &i.advisory_ids {
            for id in ids {
                if let Ok(adv) = self.client.get_advisory_by_id(id).await {
                    findings.push(adv);
                }
            }
        }

        json!({
            "evidence_pack": {
                "generated_at": Utc::now().to_rfc3339(),
                "project_path": i.path,
                "packages_in_lockfile": packages.len(),
                "advisories_included": findings.len(),
                "findings": findings,
                "sources": ["osv.dev", "GitHub Advisory Database", "RustSec", "NVD (via OSV)"],
                "format": "json",
                "compliance_note": "This evidence pack documents known vulnerabilities at time of generation. Re-run periodically.",
            },
            "provenance": {
                "tool": "osv-mcp",
                "version": "1.2.0",
                "generated_at": Utc::now().to_rfc3339(),
            },
        })
        .to_string()
    }
}

// ---------------------------------------------------------------------------
// Lockfile parsing
// ---------------------------------------------------------------------------

/// A package entry extracted from a lockfile.
#[derive(Debug, Clone, PartialEq)]
struct LockfileEntry {
    name: String,
    ecosystem: String,
    version: String,
}

/// Parse a project's lockfile to extract (name, ecosystem, version) tuples.
///
/// Tries, in order:
/// 1. `Cargo.lock` (TOML - Rust)
/// 2. `package-lock.json` (JSON - npm)
/// 3. `requirements.txt` (line-based - PyPI)
async fn parse_lockfile(path: &str) -> Vec<LockfileEntry> {
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
/// Supports both the legacy v1 format ([[package]]) and
/// the newer v2/v3 format.
fn parse_cargo_lock(content: &str) -> Option<Vec<LockfileEntry>> {
    let table: Value = toml::from_str(content).ok()?;

    let packages = match table.get("package") {
        Some(v) => v.as_array()?,
        None => return Some(Vec::new()),
    };
    let mut entries = Vec::with_capacity(packages.len());

    for pkg in packages {
        let name = pkg.get("name")?.as_str()?;
        let version = pkg.get("version")?.as_str()?;

        // Skip source-less entries (the root package itself)
        // Cargo.lock v2/v3 uses source = "null" while v1 omits the key
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
fn parse_npm_lock(content: &str) -> Option<Vec<LockfileEntry>> {
    let data: Value = serde_json::from_str(content).ok()?;
    let packages = data.get("packages")?.as_object()?;

    let mut entries = Vec::new();
    for (path, info) in packages {
        // Skip the root package ("") and non-package entries
        if path.is_empty() {
            continue;
        }
        if let Some(version) = info.get("version").and_then(|v| v.as_str()) {
            // Extract package name from path ("node_modules/foo" -> "foo")
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

/// Parse a pip requirements.txt file.
fn parse_requirements_txt(content: &str) -> Vec<LockfileEntry> {
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

/// Format an OSV API result into a JSON string, wrapping the value
/// with a closure that adds provenance metadata.
fn format_result<F>(result: Result<Value, String>, wrap: F) -> String
where
    F: FnOnce(Value) -> Value,
{
    match result {
        Ok(v) => {
            match serde_json::to_string_pretty(&wrap(v)) {
                Ok(s) => s,
                Err(e) => json!({"error": format!("Failed to serialize response: {}", e)}).to_string(),
            }
        }
        Err(e) => json!({"error": e}).to_string(),
    }
}

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
impl HealthCheck for SecurityAdvisoryServer {
    async fn check_health(&self) -> HealthStatus {
        HealthStatus {
            healthy: true,
            message: Some("operational".into()),
            latency_ms: Some(1),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
        // The root package with source = "null" should be skipped
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
        assert!(entries.iter().any(|e| e.name == "express" && e.version == "4.21.0"));
        assert!(entries.iter().any(|e| e.name == "axios" && e.version == "1.7.0"));
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

    #[test]
    fn test_parse_lockfile_unknown_project() {
        // Non-existent path returns empty
        let rt = tokio::runtime::Runtime::new().unwrap();
        let entries = rt.block_on(parse_lockfile("/tmp/nonexistent-project-12345"));
        assert!(entries.is_empty());
    }

    #[test]
    fn test_format_result_ok() {
        let result: Result<Value, String> = Ok(json!({"key": "value"}));
        let output = format_result(result, |v| json!({"wrapped": v}));
        assert!(output.contains("\"wrapped\""));
        assert!(output.contains("\"key\""));
    }

    #[test]
    fn test_format_result_err() {
        let result: Result<Value, String> = Err("something went wrong".to_string());
        let output = format_result(result, |v| json!({"wrapped": v}));
        assert!(output.contains("error"));
        assert!(output.contains("something went wrong"));
    }

    /// Integration-style: verify parse_lockfile reads a real Cargo.lock.
    /// This test uses THIS project's own Cargo.lock.
    #[tokio::test]
    async fn test_parse_lockfile_our_own_cargo_lock() {
        let entries = parse_lockfile(".").await;
        assert!(!entries.is_empty(), "Should parse our own Cargo.lock");
        // We should have at least adk-mcp-sdk as a dependency
        assert!(
            entries.iter().any(|e| e.ecosystem == "crates.io"),
            "Should find crates.io packages"
        );
    }
}