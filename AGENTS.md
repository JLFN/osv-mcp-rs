# AGENTS.md — osv-mcp-rs

Local handoff (machine-local, NOT part of this public repo — read first):
/data/osv-mcp-rs/osv-mcp-rs-handoff.md. It is maintained on this machine and
is never committed to this branch. Project memory:
~/.opengrok/memory/osv-mcp-rs-7c495650/MEMORY.md.

This is osv-mcp, an MCP server (Rust, rmcp stdio) exposing six osv_ tools backed by
the live OSV.dev API (api.osv.dev; no local DB). Repo github.com/JLFN/osv-mcp-rs, PUBLIC.

Unit 4 (2026-09-01) landed: osv_map_dependencies now walks the project tree
recursively to find every lockfile (pruning node_modules/.git/target) and chunks
/v1/querybatch into 256-query sub-batches, because OSV.dev returns HTTP 400 for a
single batch beyond ~1000 queries. Verified on /data/praviohr/NEW: 5 manifests,
1816 packages, 33 vulnerable (was 1 / 906 / 5), including the previously dropped
dompurify/jspdf/js-yaml baseline clusters. Next-unit plan: local handoff section 3.

Guardrails: build only via the canonical builder
(bash /data/build/linux/build.sh -p /data/osv-mcp-rs); keep the osv_ tool prefix;
no emojis / plain text / conventional commits; OSV scan before push; graphify rebuild at
commit time; verify repo visibility before any push; the handoff and memory are local
only and are never committed to any public branch.