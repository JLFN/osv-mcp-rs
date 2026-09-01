# AGENTS.md — osv-mcp-rs

Canonical handoff (read first): /data/osv-mcp-rs/osv-mcp-rs-handoff.md.
Project memory: ~/.opengrok/memory/osv-mcp-rs-7c495650/MEMORY.md.

This is osv-mcp, an MCP server (Rust, rmcp stdio) exposing six osv_ tools backed by
the live OSV.dev API (api.osv.dev; no local DB). Repo github.com/JLFN/osv-mcp-rs, PUBLIC.

Active work (unit 4): fix osv_map_dependencies false negatives — it currently (a) scans
only the top-level directory for manifests (misses nested app lockfiles) and (b) drops
advisories that OSV.dev does return when all packages are sent in one giant querybatch.
Diagnosis + phases A-E are in the handoff's section 3.

Guardrails: build only via the canonical builder
(bash /data/build/linux/build.sh -p /data/osv-mcp-rs); keep the osv_ tool prefix;
no emojis / plain text / conventional commits; OSV scan before push; graphify rebuild at
commit time; verify repo visibility before any push.