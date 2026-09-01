---
project: osv-mcp-rs
plan_start_commit: b0e6637
last_updated_commit: b0e6637
branch: main
remote: https://github.com/JLFN/osv-mcp-rs.git
handoff_written_at_context_usage: 19%
handoff_written_at: 2026-09-01T05:13:38+02:00
session_id: 01a05ab9-ea9f-76a3-9e75-b36c1bcd9c69
---
--- handoff probe (auto) ---
=== handoff probe (osv-mcp-rs) ===
--- units completed since plan start (b0e6637):
  (none)
--- progress diff stat:
AGENTS.md             |  17 +++++
 docs/handoff.md       |  83 ++----------------------
 osv-mcp-rs-handoff.md | 176 ++++++++++++++++++++++++++++++++++++++++++++++++++
 3 files changed, 197 insertions(+), 79 deletions(-)
--- staleness (last_updated_commit b0e6637 .. HEAD):
312e9bd docs(handoff): record unit 4 (osv_map_dependencies false negatives) and move to canonical path
--- end handoff probe ---


Handoff + executable plan — osv-mcp-rs (2026-09-01)

Note on the frontmatter: it MUST be the first thing in the file, with
bare values (no inline comments after the value) — the handoff-hooks
parser reads it verbatim, and a commented or misplaced frontmatter
silently breaks the SessionStart probe readout.

0. Rules for writing THIS document

- Only write or replace this file at a clean, verified, committed, pushed boundary.
- Every claim in "Current state" must be re-verified by running the relevant command
  in this session, not copied from a past handoff. Mark unverified if you cannot re-run it.
- Hard caps: "Current state" <= 15 lines. "Guardrails and open items" <= 15 lines.
  "Next unit plan" has no cap — it is the actual work spec.
- Do NOT replay prior units' logs (git log is the record), re-explain global rules in
  ~/.opengrok/AGENTS.md, or record acceptance evidence you did not observe this session.
- The handoff-hooks binary (registered globally) scaffolds the frontmatter and refreshes
  the progress/staleness readout at SessionStart; it is passive and fails open. Keep the
  template shape so the automation can manage it.

1. Session protocol (read first)

This project is a sequence of release units; each ends with a verified, pushed commit set
whose final commit carries the trailer "Unit: N complete".

1. Read context usage from the session's signals.json (contextTokensUsed /
   contextWindowTokens) under ~/.opengrok/sessions/<percent-encoded-cwd>/<session-id>/
   (newest session dir). Pick the session matching this repo's cwd.
2. If usage < 40%: continue working immediately — write the next unit's plan into
   section 3 below, execute it, verify, commit, push, re-check usage, repeat.
3. At the ~40% threshold: do not pause or ask. Finish writing this handoff, then launch
   a fresh session preloaded with it (open-grok-handoff or the gnome-terminal launcher
   per global rule 9).

2. Current state (2026-09-01 — a real bug was discovered; unit 4 is planned, not landed)

- Repo: osv-mcp v1.4.0 (main, remote github.com/JLFN/osv-mcp-rs.git, PUBLIC). Multi-
  language lockfile scanning landed in unit 3 (c8377db). Clean working tree at b0e6637.
- NEW this session, VERIFIED: osv_map_dependencies FALSE-NEGATIVES on real projects.
  Running it on /data/praviohr/NEW returned manifests_scanned 1, packages_scanned 906,
  vulnerable_packages 5 (decode-uri-component@0.2.2, react-router@6.30.6, vite@5.4.21,
  esbuild@0.21.5, vitest@2.1.9). It missed dompurify/jspdf/js-yaml/postcss/minimatch etc.
  even though they ARE in the root package-lock.json it scanned, and OSV.dev live returns
  them for the same packages (see section 3 ground truth).
- The osv-mcp server does NOT use the local DB (/data/osv-dev-db/data/osv.db): src/osv.rs
  is an HTTP client to https://api.osv.dev (base_url, in-memory TTL cache). Confirmed from
  source this session.
- An independent scanner, OSV-Scanner v2.5.1 (added as report-only CI on the pravio
  project), found 88 findings over the same tree (3 lockfiles, 1700 packages) —
  the true signal. The osv-mcp map under-reports badly.
- Branch/commit/installed state: see frontmatter and section 4.

3. Next unit plan — Fix osv_map_dependencies false negatives (2026-09-01)

Status: not started. This unit fixes the server; it does NOT change the pravio CI
(osv-scan.yml / OSV-Scanner) which is correct.

Goal / acceptance: after the fix, osv_map_dependencies on /data/praviohr/NEW must
(a) scan ALL lockfiles in the tree (>= 3 manifests: root, apps/web, apps/api; packages_scanned
grows from 906 toward the 1700 OSV-Scanner counted) and (b) surface the advisories OSV.dev
already returns for the packages it scans (the dompurify x18, jspdf x9, js-yaml x4,
decode-uri-component x1 groups it currently drops). Compare the result against the saved
88-finding baseline: EVIDENCE.md "OSV-Scanner baseline: 2026-09-01" and the remediation
TODO.md in /data/praviohr/NEW.

Live ground truth, verified 2026-09-01 (re-verify first; reference-implementation rule):
- osv_map_dependencies /data/praviohr/NEW -> 1 manifest, 906 pkgs, 5 vulnerable.
- curl -X POST https://api.osv.dev/v1/query, body {"package":{"name":"dompurify",
  "ecosystem":"npm"},"version":"3.3.0"} -> 18 vulns incl GHSA-39q2-94rc-95cp (CVE-2026-65903).
- Same for jspdf@4.0.0 -> 9; js-yaml@4.1.0 -> 4; decode-uri-component@0.2.2 -> 1.
- POST /v1/querybatch with a 4-query batch -> results[0]=dompurify 18, [1]=decode 1,
  [2]=jspdf 9, [3]=js-yaml 4 (positional). So a SMALL batch returns everything.
- grep confirms dompurify/jspdf/js-yaml/postcss/minimatch/brace-expansion are present in
  /data/praviohr/NEW/package-lock.json (68 hits) — they are parsed and queried.

Phase A — Reproduce + diagnose the large-batch miss (before changing code):
Build the exact query body osv-mcp sends (one /v1/querybatch POST carrying all ~906 root-lock
queries, see src/osv.rs query_batch and main.rs osv_map_dependencies) and replay it against
https://api.osv.dev/v1/querybatch. Print len(results) and whether the dompurify entry
(the index of the "node_modules/dompurify" entry in the parsed lock) comes back with vulns.
Determine which is true: (A1) OSV truncates/errors on a ~906-query body (then the fix is
chunking), or (A2) the response comes back complete but main.rs's `for (idx, result)`
index mapping or the parser drops results (then the fix is parsing/order). Record the exact
observation in the commit body.

Phase B — Fix manifest coverage (src/lockfile.rs scan_project):
It currently does fs::read_dir on the given path only (top level, no recursion), so a
monorepo yields just the root lockfile. Add a recursive walker that descends the tree from
`path`, skipping node_modules (and .git, target), collecting every SUPPORTED_MANIFESTS
filename. Keep the existing per-file parsers unchanged. Add unit tests: a temp dir tree
with root + nested package-lock.json files yields the expected (name, ecosystem, version)
entries and manifests list. Bound the walk (skip huge dirs) to avoid scanning node_modules.

Phase C — Fix the large-batch path (src/osv.rs query_batch + main.rs mapping):
Chunk `packages` into sub-batches of a guardrail size (start 64 or 128) and merge results by
index across chunks so every package's status is preserved; do not let one failing chunk drop
the others. Add a unit test for the chunker and a mock-server test that returns more than one
chunk's worth of results to prove the merge is positional and lossless.

Phase D — Verify + ship (canonical builder, rule 5):
- bruise builds MUST use the canonical builder: bash /data/build/linux/build.sh -p /data/osv-mcp-rs
  (produces bin/osv-mcp under bin/, removes target/).
- cargo test --all-targets (expect >28 tests now), cargo fmt --check, cargo clippy -- -D warnings.
- Install: atomic move of the new bin to ~/.local/bin/osv-mcp, then restart the osv-mcp MCP
  server so an in-session osv_map_dependencies serves the fixed binary.
- Re-run osv_map_dependencies on /data/praviohr/NEW and check acceptance counts above.

Phase E — Commit + push:
Conventional commit(s), final one with trailer "Unit: 4 complete". Before push, verify
visibility: gh repo view JLFN/osv-mcp-rs --json isPrivate,visibility (PUBLIC expected,
rule 6). Push to origin main. Rebuild graphify-rs (rule 12) at commit time.

Notes/decisions: osv-mcp queries live api.osv.dev; the local /data/osv-dev-db is a separate
tool and irrelevant to this bug. Keep the osv_ tool-name prefix. Do not touch the pravio
OSV-Scanner CI workflow — it is the correct signal and the false-negative is only in
osv-mcp's map. The 88-finding remediation for pravio is tracked in /data/praviohr/NEW
(EVIDENCE.md + TODO.md), not here.

4. Project facts a fresh session cannot re-derive

- Deliverable binary: bin/osv-mcp (gitignored; reproduce with
  bash /data/build/linux/build.sh -p /data/osv-mcp-rs). Installed copy at
  ~/.local/bin/osv-mcp, registered as [mcp_servers.osv-mcp] in ~/.opengrok/config.toml
  (command "osv-mcp", stdio). Restart the MCP server after reinstall to serve the new binary.
- Source layout: src/main.rs (six osv_ tools via rmcp ToolRouter), src/osv.rs (HTTP client +
  TTL cache to api.osv.dev), src/lockfile.rs (multi-ecosystem manifest parsers).
- Skill: skills/osv-mcp/SKILL.md tracked in repo, synced to ~/.opengrok/skills/osv-mcp/.
- Environment: outbound HTTPS to api.osv.dev required; no API key; the server has no local DB.
  OSV ecosystems verified: Pub, ConanCenter, Hackage accepted; Swift/swiftpm rejected.
- Prior verification baseline: 28 cargo tests (parsers + mock-HTTP client), fmt + clippy
  clean, repo's own OSV scan clean after bumping anyhow/quinn-proto (RUSTSEC-2026-0190,
  RUSTSEC-2026-0185). Re-derive counts from git if in doubt.

5. Guardrails and open items

- Global rules in effect (full list in ~/.opengrok/AGENTS.md): canonical builder for Rust
  deliverables (5); OSV scan before push (10) — the scan tool here is osv-mcp itself;
  graphify rebuild at commit time (12); repo-rag on demand (11); never publish private /
  visibility check before any remote action (6); no emojis / plain text / conventional
  commits with detailed bodies (1-3); QA gate for deliverable projects (19).
- Project-specific: keep the osv_ tool prefix; repo has no AGENTS.md yet (adding one as a
  pointer per rule 9). Repo JLFN/osv-mcp-rs is PUBLIC (re-verify via gh before push).
- OPEN: (1) the false-negative bug is the current unit; (2) pravio's 88 findings are a
  downstream remediation tracked in /data/praviohr/NEW, not here.
- When this handoff's unit completes: replace section 3 with the next unit's plan and fold
  this unit's outcome into section 2 in the SAME commit.

6. Progress and staleness check (run this first, every session)

Progress meter:
    cd /data/osv-mcp-rs
    git log --oneline b0e6637..HEAD
    git diff --stat b0e6637..HEAD
    git log --grep "Unit: .* complete" b0e6637..HEAD
Trust git over the plan headings: continue with the first unit whose work is NOT in the diff.

Staleness check (does this handoff predate newer work):
    cd /data/osv-mcp-rs && git log --oneline b0e6637..HEAD
Any output means this handoff predates newer commits; read the log and diffs before
trusting sections 2-5, then advance last_updated_commit. Branch/remote in frontmatter that
differs from the repo means stop and reconcile first.

This document is COMPLETE and self-contained: a new session can execute this project end to
end from this file alone. History is deliberately absent — git log and the project memory
entry are the historical record.
