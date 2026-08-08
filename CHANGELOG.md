# Changelog - osv-mcp

## [1.3.0] - 2026-08-08

### Changed
- Refactored the server onto the standard MCP factory template (rmcp 3.1):
  `OsvServer` with a `ToolRouter`, `#[tool_router]` tools, and a
  `#[tool_handler]` `get_info` with instructions. Removed the adk-mcp-sdk
  dependency, the `HealthCheck` trait, tracing, and the `mcp-server.toml`
  manifest.
- Tools renamed with the server prefix, one tool per question type:
  `search_advisories` -> `osv_search_advisories`, `get_advisory` ->
  `osv_get_advisory`, `map_vulnerability_to_dependency` ->
  `osv_map_dependencies`, `rank_security_risk` -> `osv_rank_risk`,
  `generate_patch_plan` -> `osv_patch_plan`, `export_security_evidence` ->
  `osv_export_evidence`. Client-facing tool names change; update prompts
  that referenced the old names.
- Edition downgraded to 2021 and rust-version raised to 1.88 (rmcp 3.1
  floor).
- License changed to dual MIT OR Apache-2.0 (LICENSE-MIT + LICENSE-APACHE).
- Repository metadata points at the canonical repo
  (https://github.com/JLFN/osv-mcp-rs); the crates.io `repository` field
  redirects there.

### Added
- In-process mock HTTP tests for the OSV client (search, advisory lookup,
  batch queries, cache behavior, 404 error path) — no live network calls.
- Standard repo layout: README with badge row, docs/setup.md and
  docs/verification.md, skills/osv-mcp/SKILL.md, embedded build/ builder,
  .gitignore.

## [1.2.0] - 2025-07-29

### Added
- Proper TOML-based Cargo.lock parsing supporting v1, v2, and v3 formats
- npm package-lock.json support via JSON parser
- In-memory response caching with 5-minute TTL
- 12 unit tests covering lockfile parsing and error paths
- HTTP client timeout and user-agent configuration

### Changed
- Complete removal of `.unwrap()` calls; replaced with proper error propagation
- Lockfile parsing returns structured `LockfileEntry` struct instead of raw tuples
- Comprehensive ISO-standard documentation rewrite
- Removed all external branding references

### Fixed
- All error paths now produce descriptive error messages
- Cache key generation handles empty parameters gracefully

## [1.1.0] - 2025-05-24

### Added
- HealthCheck trait implementation for registry monitoring
- `mcp-server.toml` manifest for ADK registry onboarding
- Structured tracing with `tracing-subscriber` (env-filter)

### Changed
- Edition upgraded to Rust 2024
- Added `adk-mcp-sdk` HealthCheck integration

