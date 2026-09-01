# Changelog - osv-mcp

## [1.4.1] - 2026-09-01

### Docs
- Corrected the README "Known limitations" wording that claimed manifest
  discovery is top-level only and that nested lockfiles are not recursed
  into. The published documentation now matches the 1.4.0 behavior: the scan
  walks the project tree recursively (pruning `node_modules`, `.git`,
  `target`) and queries large dependency sets in chunked `/v1/querybatch`
  sub-batches. No code changed in this patch; it exists to refresh the
  README frozen into the published crate.

## [1.4.0] - 2026-08-22

### Added
- Multi-language lockfile scanning. `osv_map_dependencies` (and
  `osv_export_evidence`) now discover and parse every supported manifest
  present in a project directory, not just the first one found, so a
  project with several lockfiles is scanned across all of its languages.
- Lockfile parsers for nine new ecosystems, in addition to the existing
  crates.io / npm / PyPI support:
  - Go (`go.mod`)
  - Maven / Java (`pom.xml`, package name `groupId:artifactId`)
  - NuGet / .NET (`packages.config`, `project.assets.json`)
  - RubyGems / Ruby (`Gemfile.lock`)
  - Packagist / PHP (`composer.lock`)
  - Pub / Dart (`pubspec.lock`)
  - Hex / Elixir (`mix.lock`)
  - ConanCenter / C/C++ (`conan.lock`)
  - Hackage / Haskell (`stack.yaml.lock`, `cabal.project.freeze`)
- Ecosystem identifiers match the strings accepted by the OSV.dev batch
  endpoint (verified live), including the non-obvious `Pub` for Dart and
  `ConanCenter` for C/C++.
- `osv_map_dependencies` response now reports `manifests_scanned` alongside
  the packages-scanned count.
- `quick-xml` dependency for XML manifest parsing (`pom.xml`,
  `packages.config`).

### Changed
- Lockfile parsing is deduplicated by (name, ecosystem, version) so the
  same package listed in multiple manifests (for example both NuGet forms)
  is queried once.
- HTTP client user-agent version is now derived from the crate version
  instead of a hard-coded string.

### Notes
- Parsers are read-only and best-effort. Maven dependencies without an
  explicit version are skipped; `requirements.txt` only reads
  `name==version` pins; `Gemfile.lock` reads the resolved version of each
  spec; `cabal.project.freeze` and `stack.yaml.lock` read concrete pinned
  versions. The scan now walks the project tree recursively (pruning
  `node_modules`, `.git`, and `target`), so nested and monorepo lockfiles are
  covered rather than only the top-level directory.

### Fixed
- Monorepo false negatives. `osv_map_dependencies` now recurses into
  subdirectories, so nested application lockfiles (for example
  `apps/web/package-lock.json`) are scanned instead of only the top-level
  directory; vulnerable packages that appear only in nested lockfiles were
  previously missed.
- Large-batch reliability. Large dependency sets are now split into chunked
  `/v1/querybatch` sub-batches and merged positionally, because OSV.dev
  returns HTTP 400 for a single batch beyond ~1000 queries. A failed chunk
  does not drop the others (its slots come back null and a warning is
  attached).

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

