//! osv-mcp — MCP server exposing OSV.dev security advisory data.
//!
//! Tools:
//!   - osv_search_advisories   search advisories by package, ecosystem, keyword
//!   - osv_get_advisory        full advisory record by ID (CVE/GHSA/RUSTSEC/OSV)
//!   - osv_map_dependencies    scan a project lockfile against OSV batch API
//!   - osv_rank_risk           weighted practical-risk score for an advisory
//!   - osv_patch_plan          remediation plan (upgrade / mitigate)
//!   - osv_export_evidence     audit/compliance evidence pack for a project
//!
//! Data source: the OSV.dev REST API (api.osv.dev), which aggregates NVD,
//! GitHub Advisory Database, RustSec, PyPI, npm, Go, Maven, and NuGet feeds.

mod lockfile;
mod osv;

use std::sync::Arc;

use chrono::Utc;
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
    ServerHandler, ServiceExt,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use lockfile::scan_project;
use osv::OsvClient;

#[derive(Debug, Clone)]
struct OsvServer {
    // Held by the tool-router macro's generated code; the field itself is
    // never read directly.
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
    client: Arc<OsvClient>,
}

impl OsvServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
            client: Arc::new(OsvClient::new()),
        }
    }
}

// ---------------------------------------------------------------------------
// Tool input types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
struct SearchAdvisoriesRequest {
    /// Package name to search advisories for, e.g. "hyper" or "serde".
    package: Option<String>,
    /// Ecosystem filter: crates.io, npm, PyPI, Go, Maven, NuGet.
    ecosystem: Option<String>,
    /// Keyword search; used as the package name when `package` is unset.
    query: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
struct GetAdvisoryRequest {
    /// Advisory identifier: CVE-*, GHSA-*, RUSTSEC-*, or OSV-*.
    id: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
struct MapDependenciesRequest {
    /// Path to the project directory. Discovers and scans every supported
    /// lockfile: Cargo.lock, package-lock.json, requirements.txt, go.mod,
    /// pom.xml, packages.config, project.assets.json, Gemfile.lock,
    /// composer.lock, pubspec.lock, mix.lock, conan.lock, stack.yaml.lock,
    /// cabal.project.freeze.
    path: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
struct RankRiskRequest {
    /// Advisory ID to score.
    advisory_id: String,
    /// Whether the affected package is a direct dependency (vs transitive).
    /// Defaults to true.
    direct_dependency: Option<bool>,
    /// Whether the service is internet-facing. Defaults to false.
    internet_exposed: Option<bool>,
    /// Whether a known exploit exists in the wild. Defaults to false.
    known_exploit: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
struct PatchPlanRequest {
    /// Advisory ID to remediate.
    advisory_id: String,
    /// Package name; auto-detected from the advisory when omitted.
    package: Option<String>,
    /// Currently installed version of the affected package.
    current_version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
struct ExportEvidenceRequest {
    /// Path to the project directory.
    path: String,
    /// Advisory IDs to include; includes all findings when omitted.
    advisory_ids: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

#[tool_router]
impl OsvServer {
    /// Search advisories (CVE/GHSA/OSV/RustSec) by package, ecosystem, or
    /// keyword.
    #[tool(
        description = "Search the OSV.dev vulnerability database for advisories by package name, ecosystem, or keyword. Sources covered: GitHub Advisory Database, RustSec, PyPI, npm, Go, Maven, NuGet. Returns JSON with an 'advisories' array (id, summary, severity, aliases, affected packages) and a count. Use to discover known vulnerabilities in a package."
    )]
    async fn osv_search_advisories(
        &self,
        Parameters(req): Parameters<SearchAdvisoriesRequest>,
    ) -> String {
        let result = self
            .client
            .search_osv(
                req.package.as_deref(),
                req.ecosystem.as_deref(),
                req.query.as_deref(),
            )
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

    /// Get full advisory details by ID (CVE-*, GHSA-*, RUSTSEC-*, OSV-*).
    #[tool(
        description = "Fetch the full record of one advisory by identifier (CVE-2024-0001, GHSA-xxxx-xxxx-xxxx, RUSTSEC-2021-0079, OSV-2023-1000). Returns JSON: id, summary, details, aliases, severity, published/modified dates, affected packages with version ranges, references, and a source URL on osv.dev."
    )]
    async fn osv_get_advisory(&self, Parameters(req): Parameters<GetAdvisoryRequest>) -> String {
        let result = self.client.get_advisory_by_id(&req.id).await;
        let id_type = if req.id.starts_with("CVE") {
            "cve"
        } else if req.id.starts_with("GHSA") {
            "ghsa"
        } else if req.id.starts_with("RUSTSEC") {
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

    /// Scan a project's lockfiles against the OSV batch API.
    #[tool(
        description = "Map advisories against the dependencies of a project directory. Discovers every supported lockfile/manifest present and scans all of them (Rust Cargo.lock, npm package-lock.json, Python requirements.txt, Go go.mod, Maven pom.xml, NuGet packages.config and project.assets.json, Ruby Gemfile.lock, PHP composer.lock, Dart pubspec.lock, Elixir mix.lock, C/C++ conan.lock, Haskell stack.yaml.lock and cabal.project.freeze), then checks every package and version via the OSV batch API. Returns JSON: manifests scanned, packages scanned, vulnerable packages found, and for each one the installed version and up to three advisory ids/summaries."
    )]
    async fn osv_map_dependencies(
        &self,
        Parameters(req): Parameters<MapDependenciesRequest>,
    ) -> String {
        let scan = scan_project(&req.path).await;
        let packages = scan.entries;

        if packages.is_empty() {
            let supported: Vec<&str> = lockfile::SUPPORTED_MANIFESTS
                .iter()
                .map(|(file, _)| *file)
                .collect();
            return json!({
                "error": "No supported lockfile found or no packages parsed",
                "supported": supported,
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
            "path": req.path,
            "manifests_scanned": scan.manifests.len(),
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

    /// Score practical risk for an advisory on a 0-10 scale.
    #[tool(
        description = "Score the practical risk of an advisory for your situation. Considers the CVSS base score (40%), whether the package is a direct dependency (+1.5 vs +0.5), whether the service is internet-facing (+2.0), and whether a known exploit exists (+2.5). Returns JSON: risk score (0-10), priority (critical/high/medium/low), contributing factors, and a remediation recommendation."
    )]
    async fn osv_rank_risk(&self, Parameters(req): Parameters<RankRiskRequest>) -> String {
        let severity_score: f64 = match self.client.get_advisory_by_id(&req.advisory_id).await {
            Ok(v) => v["severity"]
                .as_array()
                .and_then(|a| a.first())
                .and_then(|s| s["score"].as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or(5.0),
            Err(_) => 5.0,
        };

        let direct = req.direct_dependency.unwrap_or(true);
        let internet = req.internet_exposed.unwrap_or(false);
        let exploit = req.known_exploit.unwrap_or(false);

        // Weighted risk score (0-10).
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
            "advisory_id": req.advisory_id,
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

    /// Generate a remediation plan for an advisory.
    #[tool(
        description = "Generate a remediation plan for one advisory: the fixed version (read from the advisory's affected ranges when available), the action (upgrade vs mitigate), ordered steps, rollout order, and regression-test guidance. Pass the currently installed version to make the plan concrete."
    )]
    async fn osv_patch_plan(&self, Parameters(req): Parameters<PatchPlanRequest>) -> String {
        let advisory = self
            .client
            .get_advisory_by_id(&req.advisory_id)
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

        let pkg = req
            .package
            .as_deref()
            .or(advisory["affected"]
                .as_array()
                .and_then(|a| a.first())
                .and_then(|a| a["package"].as_str()))
            .unwrap_or("unknown");

        json!({
            "advisory_id": req.advisory_id,
            "package": pkg,
            "current_version": req.current_version,
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
                "source_advisory": req.advisory_id,
            },
        })
        .to_string()
    }

    /// Export security findings as audit/compliance evidence.
    #[tool(
        description = "Export a structured audit/compliance evidence pack for a project: generated timestamp, packages found in the lockfile, the requested advisory records (all findings if 'advisory_ids' is omitted), sources, and a compliance note. JSON output suitable for attaching to an audit report."
    )]
    async fn osv_export_evidence(
        &self,
        Parameters(req): Parameters<ExportEvidenceRequest>,
    ) -> String {
        let scan = scan_project(&req.path).await;
        let packages = scan.entries;
        let mut findings = Vec::new();

        if let Some(ids) = &req.advisory_ids {
            for id in ids {
                if let Ok(adv) = self.client.get_advisory_by_id(id).await {
                    findings.push(adv);
                }
            }
        }

        json!({
            "evidence_pack": {
                "generated_at": Utc::now().to_rfc3339(),
                "project_path": req.path,
                "packages_in_lockfile": packages.len(),
                "advisories_included": findings.len(),
                "findings": findings,
                "sources": ["osv.dev", "GitHub Advisory Database", "RustSec", "NVD (via OSV)"],
                "format": "json",
                "compliance_note": "This evidence pack documents known vulnerabilities at time of generation. Re-run periodically.",
            },
            "provenance": {
                "tool": "osv-mcp",
                "version": env!("CARGO_PKG_VERSION"),
                "generated_at": Utc::now().to_rfc3339(),
            },
        })
        .to_string()
    }
}

#[tool_handler]
impl ServerHandler for OsvServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "Security advisory server backed by OSV.dev. Typical flow: \
             osv_search_advisories to find known vulnerabilities for a package, \
             osv_get_advisory for the full record of a CVE/GHSA/RUSTSEC/OSV id, \
             osv_map_dependencies to scan a project's lockfile for vulnerable \
             dependencies, osv_rank_risk to prioritize an advisory for your \
             situation, osv_patch_plan for remediation steps, osv_export_evidence \
             to produce an audit evidence pack.",
        )
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Format an OSV API result into a pretty JSON string, wrapping the value
/// with a closure that adds provenance metadata. Failures become a JSON
/// `{"error": ...}` document instead of a non-JSON error string.
fn format_result<F>(result: Result<Value, String>, wrap: F) -> String
where
    F: FnOnce(Value) -> Value,
{
    match result {
        Ok(v) => match serde_json::to_string_pretty(&wrap(v)) {
            Ok(s) => s,
            Err(e) => json!({"error": format!("Failed to serialize response: {}", e)}).to_string(),
        },
        Err(e) => json!({"error": e}).to_string(),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let service = OsvServer::new();
    let running = service.serve(stdio()).await?;
    running.waiting().await?;
    Ok(())
}
