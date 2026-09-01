---
name: osv-mcp
description: >
  Look up software vulnerabilities (CVE, GHSA, RUSTSEC, OSV) and scan
  project lockfiles through the osv-mcp MCP server, backed by the OSV.dev
  vulnerability database: search advisories by package, ecosystem, or
  keyword; fetch full advisory records; map a project's lockfiles across
  twelve ecosystems against known vulnerabilities;
  rank practical risk; plan remediation; and export compliance evidence.
  Use when the user asks whether a package or dependency has known
  vulnerabilities, wants details on a CVE/GHSA/RUSTSEC/OSV id, asks to scan
  a project for vulnerable dependencies, or runs /osv-mcp.
argument-hint: "[package] [advisory-id] [path]"
when-to-use: osv, osv.dev, cve, security advisory, vulnerability, known vulnerabilities, RUSTSEC, GHSA, scan dependencies, vulnerable dependency, patch plan, /osv-mcp, security audit
user-invocable: true
---

# OSV MCP — Security Advisory Lookup

Answer questions about known software vulnerabilities with the osv-mcp MCP server (project osv-mcp, binary osv-mcp, installable via cargo install osv-mcp). The server reads one public structured API, OSV.dev, which aggregates NVD, the GitHub Advisory Database, RustSec, and the PyPI, npm, Go, Maven, NuGet, Packagist, and RubyGems feeds. Tools are invoked as osv__osv_<name>.

## When to Use

- "Are there known vulnerabilities in package X?" / "is crate X vulnerable?"
- "What is CVE-2024-0001 / GHSA-xxxx-xxxx-xxxx / RUSTSEC-2021-0079 about?"
- "Scan my project at /path for vulnerable dependencies" / "security audit this repo"
- "How risky is this advisory for us?" / "how do I fix this advisory?"
- Any question that needs real vulnerability data, not guesses: severity, affected versions, fixed versions, references.

## The Tools

1. osv_search_advisories — search OSV.dev by package name, ecosystem (crates.io, npm, PyPI, Go, Maven, NuGet), or keyword. Returns advisories with id, summary, severity, aliases, affected packages.
2. osv_get_advisory — the full record for one advisory id (CVE-*, GHSA-*, RUSTSEC-*, OSV-*): summary, details, aliases, severity, dates, affected packages with version ranges, references, source URL.
3. osv_map_dependencies — scan a project directory: discovers every
   supported lockfile present and parses all of them — Rust (Cargo.lock),
   JavaScript/TypeScript (package-lock.json), Python (requirements.txt),
   Go (go.mod), Java (pom.xml), .NET (packages.config, project.assets.json),
   Ruby (Gemfile.lock), PHP (composer.lock), Dart (pubspec.lock), Elixir
   (mix.lock), C/C++ (conan.lock), Haskell (stack.yaml.lock,
   cabal.project.freeze) — checks every package via the OSV batch API, and
   returns the vulnerable ones with installed versions and advisory ids.
4. osv_rank_risk — weighted 0-10 risk score for an advisory: CVSS base (40%), direct vs transitive dependency, internet exposure, known exploit. Returns priority (critical/high/medium/low) and a recommendation.
5. osv_patch_plan — remediation plan: fixed version (read from the advisory's affected ranges), action (upgrade vs mitigate), ordered steps, rollout order, regression-test guidance.
6. osv_export_evidence — audit/compliance evidence pack for a project: timestamped JSON with lockfile package count, advisory records, sources, and a compliance note.

## Workflow

1. Search. For "is package X vulnerable", call osv_search_advisories(package, ecosystem). For a specific id, skip straight to osv_get_advisory.
2. Read. osv_get_advisory for the full record: severity, affected ranges, fixed versions, references.
3. Scan a project. osv_map_dependencies(path) to find which packages across
   all detected languages are vulnerable.
4. Prioritize. osv_rank_risk(advisory_id, direct_dependency, internet_exposed, known_exploit) to decide urgency.
5. Remediate. osv_patch_plan(advisory_id, current_version) for the fixed version and steps.
6. Evidence. osv_export_evidence(path, advisory_ids) to attach a compliance pack to a report.

## Rules

- Report what OSV.dev returns. Absence of a result is not proof a package is clean; say so when the user needs certainty.
- Lockfile parsing is read-only and best-effort. The scan walks the project
  tree recursively — including monorepo subdirectories — while pruning
  node_modules, .git, and target, and parses every supported manifest it
  finds (all twelve ecosystems); only concrete installed versions are queried
  (pinned requirements.txt `name==version` lines, Maven dependencies with an
  explicit version, resolved Gemfile.lock specs, frozen Haskell pins).
  Unpinned, ranged, or versionless entries are ignored. Large dependency sets
  are queried in chunked sub-batches so the scan stays within OSV.dev's
  per-request query cap.
- No API key is needed; the server only talks to api.osv.dev over HTTPS.
- If the server is not listed, check it with: open-grok mcp doctor osv-mcp.

## Example

User: "Does my project at /home/user/app have any vulnerable dependencies, and how urgent are they?"
Flow: osv_map_dependencies(path "/home/user/app") to list the vulnerable packages, osv_get_advisory for each advisory id to read the record, osv_rank_risk(advisory_id, internet_exposed true) to prioritize, then osv_patch_plan(advisory_id, current_version) for the fix.
