# Setup guide

This guide covers building osv-mcp, installing the binary, and wiring the
server into Open Grok.

## Prerequisites

- Rust toolchain 1.88 or newer (rmcp 3.1 requires 1.88).
- Outbound HTTPS access to `api.osv.dev`. No API key is required.

## Building

Iterative development (keeps the incremental cache):

```console
cargo build
```

Release binary with the standard builder (produces `bin/osv-mcp` and removes
`target/`):

```console
bash build/linux/build.sh
```

The same builder can be run from the shared location on this machine (see the
rust-build skill).

## Installing

```console
cargo install --path .
```

or copy the built binary:

```console
cp bin/osv-mcp ~/.local/bin/
```

## Registering with Open Grok

Add to `~/.opengrok/config.toml`:

```toml
[mcp_servers.osv-mcp]
command = "osv-mcp"
enabled = true
```

Check the server:

```console
open-grok mcp doctor osv-mcp
```

Refresh the MCP list in the client with `/mcps` (press `r`) or restart. The
tools appear as `osv__osv_search_advisories`, `osv__osv_get_advisory`,
`osv__osv_map_dependencies`, `osv__osv_rank_risk`, `osv__osv_patch_plan`,
and `osv__osv_export_evidence`.

## Installing the skill

The repository ships an Open Grok skill at `skills/osv-mcp/SKILL.md`:

```console
cp -r skills/osv-mcp ~/.opengrok/skills/osv-mcp
```

## Environment variables

None required. `RUST_LOG` had no effect in previous releases and is no
longer used.
