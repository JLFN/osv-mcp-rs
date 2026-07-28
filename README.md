# OSV MCP Advisory - MCP Server

**Version:** 1.2.0
**License:** Apache-2.0
**Language:** Rust (edition 2024)

## 1. Overview

This project implements a Model Context Protocol (MCP) server that provides structured access to security advisory data from the OSV.dev open vulnerability database. It enables AI assistants to query, scan, and assess software vulnerabilities across multiple ecosystems.

### 1.1 Purpose

- Search for known vulnerabilities (CVE, GHSA, RUSTSEC, OSV) by package, ecosystem, or keyword
- Retrieve full advisory details including severity, affected versions, and remediation data
- Scan project lockfiles against the advisory database
- Score risk using a weighted factor model
- Generate patch plans and compliance evidence

### 1.2 Data Sources

All advisory data is sourced from OSV.dev (Google), which aggregates:
- National Vulnerability Database (NVD)
- GitHub Security Advisory Database (GHSA)
- RustSec Advisory Database (RUSTSEC)
- PyPI, npm, Go, Maven, NuGet advisory feeds

---

## 2. Tools

### 2.1 Tool Inventory

| Tool | Description | Use Case |
|------|-------------|----------|
| `search_advisories` | Search advisories by package, ecosystem, or keyword | Identify vulnerabilities in a given package |
| `get_advisory` | Retrieve full details for a specific advisory ID | Investigate CVE, GHSA, RUSTSEC, or OSV identifiers |
| `map_vulnerability_to_dependency` | Scan project lockfile against advisory database | Assess whether project dependencies have known vulnerabilities |
| `rank_security_risk` | Score practical risk using weighted factors | Prioritize remediation efforts |
| `generate_patch_plan` | Generate remediation steps | Plan upgrade or mitigation strategy |
| `export_security_evidence` | Export findings as audit evidence | Generate compliance documentation |

### 2.2 Tool Specifications

#### 2.2.1 search_advisories

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `package` | string | false | Package name to search (e.g., "hyper", "serde") |
| `ecosystem` | string | false | Ecosystem filter: crates.io, npm, PyPI, Go, Maven, NuGet |
| `query` | string | false | Keyword search; falls back to package name if `package` is unset |

Returns matching advisories with identifiers, summaries, severity levels, and affected version ranges.

#### 2.2.2 get_advisory

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | string | true | Advisory identifier: CVE-*, GHSA-*, RUSTSEC-*, OSV-* |

Returns full advisory record including summary, details, severity score, aliases, affected packages, version ranges, and references.

#### 2.2.3 map_vulnerability_to_dependency

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | true | Absolute path to project directory |

Lockfiles are read in the following order:

| File | Format | Ecosystem |
|------|--------|-----------|
| Cargo.lock | TOML (v1, v2, v3) | Rust (crates.io) |
| package-lock.json | JSON | npm |
| requirements.txt | name==version lines | Python (PyPI) |

Returns scan results showing each vulnerable package with installed version and associated advisories.

#### 2.2.4 rank_security_risk

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `advisory_id` | string | true | - | Advisory ID to score |
| `direct_dependency` | bool | false | true | Whether package is a direct dependency |
| `internet_exposed` | bool | false | false | Whether service is internet-facing |
| `known_exploit` | bool | false | false | Whether a known exploit exists |

Risk score is computed using the following weighted model:

| Factor | Weight | Description |
|--------|--------|-------------|
| CVSS severity | 40% | Base vulnerability severity (0.0 - 10.0) |
| Direct dependency | +1.5 | Direct dependency versus transitive |
| Internet exposed | +2.0 | Service faces the public internet |
| Known exploit | +2.5 | Exploit exists in the wild |

Score thresholds: Critical (>=8.0), High (>=6.0), Medium (>=4.0), Low (<4.0)

#### 2.2.5 generate_patch_plan

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `advisory_id` | string | true | Advisory ID to remediate |
| `package` | string | false | Package name (auto-detected if omitted) |
| `current_version` | string | false | Currently installed version |

Returns an ordered remediation plan with upgrade target, test steps, and rollout stages.

#### 2.2.6 export_security_evidence

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | true | Path to project directory |
| `advisory_ids` | array[string] | false | Specific IDs to include (all findings if omitted) |

Returns a structured evidence pack suitable for compliance and audit documentation.

---

## 3. Supported Identifiers

| Type | Format | Source |
|------|--------|--------|
| CVE | CVE-YYYY-NNNNN | NVD / MITRE |
| GHSA | GHSA-xxxx-xxxx-xxxx | GitHub Advisory Database |
| RUSTSEC | RUSTSEC-YYYY-NNNN | RustSec Advisory Database |
| OSV | OSV-YYYY-NNNN | OSV.dev |

## 4. Supported Ecosystems

- crates.io (Rust)
- npm (JavaScript / Node.js)
- PyPI (Python)
- Go
- Maven (Java)
- NuGet (.NET)
- Packagist (PHP)
- RubyGems (Ruby)

---

## 5. Installation

### 5.1 Prerequisites

- Rust toolchain with edition 2024 support
- MCP-compatible client (Open Grok, Claude Desktop, Cursor, or similar)

### 5.2 Build from Source

```bash
git clone https://github.com/JLFN/osv-mcp
cd osv-mcp
cargo build --release
```

The binary is written to `./target/release/osv-mcp`.

### 5.3 Building from Source (alternate method)

```bash
cargo build --release --bin osv-mcp
```

Note: This package is not published on crates.io. Build from source using one of the methods above.

---

## 6. Integration Guide

### 6.1 Open Grok Configuration

Add the following entry to `~/.opengrok/config.toml`:

```toml
[mcp_servers.osv-mcp]
command = "/path/to/osv-mcp/target/release/osv-mcp"
enabled = true
```

After saving:
1. Open Open Grok
2. Enter `/mcps` to open the MCP servers modal
3. Press `r` to refresh the server list
4. Confirm `osv-mcp` appears with 6 tools

No API key is required. OSV.dev is a free, publicly accessible service.

### 6.2 Claude Desktop Configuration

```json
{
  "mcpServers": {
    "osv-mcp": {
      "command": "/path/to/osv-mcp"
    }
  }
}
```

### 6.3 Cursor Configuration

```json
{
  "mcpServers": {
    "osv-mcp": {
      "command": "/path/to/osv-mcp"
    }
  }
}
```

---

## 7. Usage Examples

### 7.1 Search Advisories by Package

Request:
> "Are there any known vulnerabilities in the hyper crate?"

The model invokes `search_advisories` with parameters:
- package: "hyper"
- ecosystem: "crates.io"

Response contains advisory count, identifiers, severity levels, and fix versions for each advisory found.

### 7.2 Retrieve Advisory Details

Request:
> "Tell me about RUSTSEC-2021-0079"

The model invokes `get_advisory` with parameter:
- id: "RUSTSEC-2021-0079"

Response includes summary, CVSS score, affected versions, fixed version, aliases, and reference URLs.

### 7.3 Scan Project Dependencies

Request:
> "Scan the project at /home/user/my-project for vulnerabilities"

The model invokes `map_vulnerability_to_dependency` with parameter:
- path: "/home/user/my-project"

The server reads the project lockfile, queries the OSV.dev batch API, and returns the count of packages scanned, vulnerable packages found, and associated advisories.

### 7.4 Assess Risk Severity

Request:
> "How risky is RUSTSEC-2021-0079 for our internet-facing service?"

The model invokes `rank_security_risk` with parameters:
- advisory_id: "RUSTSEC-2021-0079"
- direct_dependency: true
- internet_exposed: true
- known_exploit: true

Response includes a numerical risk score (0-10), priority label, contributing factors, and a remediation recommendation.

### 7.5 Generate Remediation Plan

Request:
> "How do I fix RUSTSEC-2021-0079? We are on hyper 0.14.0"

The model invokes `generate_patch_plan` with parameters:
- advisory_id: "RUSTSEC-2021-0079"
- package: "hyper"
- current_version: "0.14.0"

Response includes the fixed version, ordered upgrade steps, and rollout sequence.

### 7.6 Export Compliance Evidence

Request:
> "Generate a security audit report for /home/user/my-project"

The model invokes `export_security_evidence` with parameter:
- path: "/home/user/my-project"

Response is a structured JSON evidence pack containing all findings with timestamps and source attribution.

---

## 8. Architecture

```
+---------------------+     stdio transport     +---------------------------+
|                     |    (MCP JSON-RPC)       |                           |
| Open Grok / Claude  | <---------------------> | osv-mcp                  |
| / Cursor / other    |                         | (Rust binary)             |
| MCP client          |                         |                           |
+---------------------+                         |  +---------------------+  |
                                                |  | AdvisoryClient      |  |
                                                |  | (in-memory cache)   |--+--> OSV.dev API (HTTPS)
                                                |  +---------------------+  |       api.osv.dev
                                                |  +---------------------+  |
                                                |  | Lockfile Parser     |  |
                                                |  | (TOML, JSON, text)  |  |
                                                |  +---------------------+  |
                                                +---------------------------+
```

### 8.1 Communication Protocol

The server communicates exclusively over standard input/output (stdio) using the MCP JSON-RPC protocol. All advisory data is fetched from the OSV.dev REST API.

### 8.2 Caching

Responses from OSV.dev are cached in-memory with a time-to-live (TTL) of 5 minutes. Cache entries are keyed by query parameters to avoid redundant network requests during a session.

### 8.3 Security

- The server makes outbound HTTPS connections to `api.osv.dev` only
- No telemetry, analytics, or phone-home functionality is present
- Lockfile parsing is read-only; no files are modified
- All tool operations are declared as `read_only` in the server manifest

---

## 9. Development

### 9.1 Build

```bash
cargo build --release
```

### 9.2 Test

```bash
cargo test
```

The test suite covers the following scenarios:

- Cargo.lock parsing (v1 format with source fields)
- Cargo.lock v2/v3 format (root packages with source = "null" are skipped)
- Empty Cargo.lock files (valid TOML with no package entries)
- npm package-lock.json parsing
- Python requirements.txt parsing (including comments and empty lines)
- Non-existent lockfile paths (returns empty result)
- Error formatting for API failure conditions

### 9.3 Environment Variables

| Variable | Description |
|----------|-------------|
| RUST_LOG | Tracing log level filter (e.g., "debug", "info", "warn") |

### 9.4 Extending Lockfile Support

1. Add a parser function in `src/server.rs` that returns `Vec<LockfileEntry>`
2. Insert a call to the new parser in `parse_lockfile()` before the fallback return
3. Add corresponding test cases in the `#[cfg(test)] mod tests` block

---

## 10. Version History

### 10.1 Version 1.2.0 (Current)

- Proper TOML-based Cargo.lock parsing supporting v1, v2, and v3 formats
- npm package-lock.json support via JSON parser
- In-memory response caching with 5-minute TTL
- Complete removal of `.unwrap()` calls; replaced with proper error propagation
- 12 unit tests covering lockfile parsing and error paths
- HTTP client timeout and user-agent configuration

### 10.2 Version 1.1.0

- HealthCheck trait implementation for registry monitoring
- Structured tracing via tracing-subscriber with environment filter
- Edition upgrade to Rust 2024

### 10.3 Version 1.0.0

- Initial release with 6 MCP tools
- OSV.dev API integration
- Basic lockfile parsing
- Risk scoring and patch planning

---

## 11. License

Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

---

## 12. Notes

- No API key is required. OSV.dev is a free, publicly accessible vulnerability database provided by Google.
- The server initiates HTTPS connections to `api.osv.dev` only. No other network communication occurs.
- All lockfile parsing operations are read-only. The server does not create, modify, or delete any files on disk.