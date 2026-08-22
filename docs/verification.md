# Verification guide

How the test suites work, and how to verify a release build before shipping.

## Test layers

1. Unit tests for lockfile parsing (`src/lockfile.rs`) — one parser per
   supported ecosystem: Cargo.lock v1/v2/v3 (including skipping the root
   package), npm `package-lock.json`, `requirements.txt` with comments and
   blank lines, `go.mod`, `pom.xml`, `packages.config` and
   `project.assets.json`, `Gemfile.lock`, `composer.lock`, `pubspec.lock`,
   `mix.lock`, `conan.lock`, `stack.yaml.lock`, and `cabal.project.freeze`,
   plus directory scans that merge multiple manifests and deduplicate.
   Pure parsers, no network.

2. Client tests (`src/osv.rs`) — the `OsvClient` is exercised against an
   in-process mock HTTP server (a `tokio` TCP listener answering with canned
   JSON), so no live network call is needed. Covers search parsing, advisory
   lookup, batch queries, the five-minute cache (a second call is served
   without a second connection), and the 404 error path.

3. Manual smoke test — run the compiled binary over stdio and speak MCP
   like a real client (below).

## Running everything

```console
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Verifying a release build

```console
bash build/linux/build.sh
ls -la bin/osv-mcp
```

Smoke-test the built binary directly over stdio: send an `initialize`
request and expect a JSON-RPC result back:

```console
printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0.0.1"}}}\n' \
  | bin/osv-mcp
```

Then check the tools are listed over stdio:

```console
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"0.1"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | bin/osv-mcp
```

Expect six tools named `osv_*`. Finally, confirm the server registers
cleanly with Open Grok:

```console
open-grok mcp doctor osv-mcp
```

## Badge verification

Every badge in the README must render. Check each shields.io URL returns an
SVG that does not contain "badge not found":

```console
curl -sL 'https://img.shields.io/crates/v/osv-mcp.svg' | grep -c 'badge not found' || true
```
