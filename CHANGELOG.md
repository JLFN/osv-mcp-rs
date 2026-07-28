# Changelog - osv-mcp

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

