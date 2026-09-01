# osv-mcp — CVE and security advisory lookup for AI assistants

[![crates.io](https://img.shields.io/crates/v/osv-mcp.svg?style=for-the-badge&color=fc8d62&logo=rust)](https://crates.io/crates/osv-mcp)
[![docs.rs](https://img.shields.io/badge/docs.rs-osv_mcp-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs)](https://docs.rs/osv-mcp)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-97ca00?style=for-the-badge)](LICENSE-MIT)
[![github](https://img.shields.io/badge/github-JLFN_osv_mcp_rs-8da0cb?style=for-the-badge&labelColor=555555&logo=github)](https://github.com/JLFN/osv-mcp-rs)

An MCP server that answers questions about known software vulnerabilities
from the [OSV.dev](https://osv.dev) vulnerability database — no HTML
scraping, no API keys, no local database to maintain. It reads one public
structured API and returns JSON over MCP stdio.

OSV.dev aggregates vulnerability feeds from NVD, the GitHub Advisory
Database, RustSec, and the advisory databases of PyPI, npm, Go, Maven,
NuGet, Packagist, and RubyGems. The server turns that into tools an AI
assistant can drive: search advisories, read full advisory records, scan a
project's lockfile for vulnerable dependencies, prioritize by practical
risk, plan remediation, and export compliance evidence.

- **Search** — find advisories (CVE, GHSA, RUSTSEC, OSV) by package,
  ecosystem, or keyword, with severity and affected-version ranges.
- **Advisory records** — the full record for one identifier: summary,
  details, aliases, severity, references, and affected packages.
- **Lockfile mapping** — scan every supported lockfile present in a
  directory against the OSV batch API and report which installed packages
  have known vulnerabilities. Languages covered: Rust (Cargo.lock),
  JavaScript / TypeScript (package-lock.json), Python (requirements.txt),
  Go (go.mod), Java (pom.xml), .NET (packages.config, project.assets.json),
  Ruby (Gemfile.lock), PHP (composer.lock), Dart (pubspec.lock), Elixir
  (mix.lock), C/C++ (conan.lock), and Haskell (stack.yaml.lock,
  cabal.project.freeze).
- **Risk ranking** — score an advisory 0-10 for your situation (CVSS base,
  direct vs transitive dependency, internet exposure, known exploit) with a
  priority label and recommendation.
- **Patch planning** — the fixed version read from the advisory's affected
  ranges, plus ordered upgrade steps, rollout order, and regression-test
  guidance.
- **Evidence export** — a timestamped, source-attributed JSON evidence pack
  for audits and compliance reporting.
- **Caching** — OSV.dev responses are cached in memory for five minutes, so
  repeated queries within a session do not hit the network again.

## Installation

Requires a Rust toolchain (rust-version 1.88). No other runtime
dependencies; the server only needs outbound HTTPS to `api.osv.dev`.

```console
cargo install osv-mcp
```

or install directly from the repository:

```console
cargo install --git https://github.com/JLFN/osv-mcp-rs
```

The binary speaks MCP over stdio; no network listener is opened.

## Configuration

### Open Grok

Add the server to `~/.opengrok/config.toml`:

```toml
[mcp_servers.osv-mcp]
command = "osv-mcp"
enabled = true
```

Refresh the MCP list with `/mcps` (press `r`) or restart. The repository
ships an Open Grok skill at `skills/osv-mcp/SKILL.md` that teaches the agent
when and how to use each tool; install it with:

```console
cp -r skills/osv-mcp ~/.opengrok/skills/osv-mcp
```

### Other MCP clients

Any MCP client that can launch a stdio command works. Point it at the
`osv-mcp` binary; no environment variables or credentials are needed.

## Architecture

The server is a Rust binary using the `rmcp` MCP toolkit. A single
`OsvServer` struct holds the tool router and an `OsvClient` (reqwest with an
in-memory TTL cache). Tools call the OSV.dev REST API (`/v1/query`,
`/v1/vulns/{id}`, `/v1/querybatch`) and return pretty-printed JSON.

```text
+----------------+   MCP stdio (JSON-RPC)   +------------+   HTTPS   +-------------+
| MCP client     | <---------------------> | osv-mcp    | --------> | api.osv.dev |
| (Open Grok,    |                          | (Rust bin) |           |             |
|  Claude, ...)  |                          |  OsvServer |           |             |
+----------------+                          |  OsvClient |           +-------------+
                                            |  lockfile  |
                                            +------------+
```

All tool operations are read-only: the server makes outbound HTTPS calls to
`api.osv.dev` only, and lockfile parsing never modifies files. There is no
telemetry or phone-home behavior.

## Tools

| Tool | Answers |
| --- | --- |
| `osv_search_advisories` | Are there known vulnerabilities in this package? |
| `osv_get_advisory` | Show me the full record for this CVE/GHSA/RUSTSEC/OSV id. |
| `osv_map_dependencies` | Which of my project's dependencies are vulnerable? |
| `osv_rank_risk` | How risky is this advisory for my situation? |
| `osv_patch_plan` | How do I fix this advisory? |
| `osv_export_evidence` | Produce an audit evidence pack for a project. |

## Example

Scanning a project and prioritizing the findings:

1. `osv_map_dependencies(path: "/home/user/my-project")` — returns the
   packages scanned, the vulnerable ones, and their advisory ids.
2. `osv_get_advisory(id: "RUSTSEC-2021-0079")` — the full record: summary,
   severity, affected versions, fixed version, references.
3. `osv_rank_risk(advisory_id: "RUSTSEC-2021-0079", internet_exposed: true,
   known_exploit: true)` — a 0-10 score with a critical/high/medium/low
   priority and a recommendation.
4. `osv_patch_plan(advisory_id: "RUSTSEC-2021-0079", current_version:
   "0.14.0")` — the fixed version and ordered upgrade steps.

## Testing

```console
cargo test
```

The suite covers lockfile parsing for all twelve supported ecosystems
(Cargo.lock v1/v2/v3, package-lock.json, requirements.txt, go.mod, pom.xml,
packages.config, project.assets.json, Gemfile.lock, composer.lock,
pubspec.lock, mix.lock, conan.lock, stack.yaml.lock, cabal.project.freeze)
and the OSV client against an in-process mock HTTP server (search parsing,
advisory lookup, batch queries, caching, and the 404 error path) — no live
network calls. See [docs/verification.md](docs/verification.md) for the full
verification guide.

## Project layout

- `src/main.rs` — `OsvServer`, the six tools, and the MCP handler.
- `src/osv.rs` — `OsvClient`: OSV.dev HTTP calls plus the in-memory cache.
- `src/lockfile.rs` — lockfile parsers for all twelve ecosystems and the
  multi-manifest directory scanner.
- `docs/` — setup and verification guides.
- `skills/osv-mcp/` — the Open Grok skill for this server.

## Documentation

- [docs/setup.md](docs/setup.md) — building, installing, and registering the
  server with Open Grok.
- [docs/verification.md](docs/verification.md) — test layers, quality gates,
  and how to verify a release build.

## Known limitations

- OSV.dev coverage depends on the upstream feeds: not every ecosystem or
  every advisory is present, and the NVD feed through OSV can lag NVD
  itself. The server reports what OSV.dev returns; absence of a result is
  not proof a package is clean.
- `requirements.txt` parsing only picks up `name==version` pins; ranges,
  extras, and editable installs are ignored.
- Parsers are best-effort: Maven dependencies without an explicit version
  are skipped, ranged `Gemfile.lock` constraints are not resolved, and
  `cabal.project.freeze` / `stack.yaml.lock` read concrete pinned versions
  only. The scan walks the project tree recursively (pruning `node_modules`,
  `.git`, and `target`), so nested and monorepo lockfiles are covered, not
  just the top-level directory. Large dependency sets are queried in chunked
  `/v1/querybatch` sub-batches and merged positionally, because OSV.dev
  returns HTTP 400 for a single batch beyond ~1000 queries.
- For Maven, the package name sent to OSV is `groupId:artifactId`, matching
  the identifier the OSV Maven feed uses.
- The evidence pack documents the state at generation time; re-run it
  periodically for ongoing compliance.

## License

Licensed under either of [Apache License, Version
2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
