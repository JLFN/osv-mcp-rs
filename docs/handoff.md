---
project: osv-mcp-rs
plan_start_commit: e41a10a
last_updated_commit: c8377db
branch: main
remote: https://github.com/JLFN/osv-mcp-rs.git
handoff_written_at_context_usage: ~5% (fresh session; signals.json not reliably written)
handoff_written_at: 2026-08-11T22:50:26+02:00
session_id: 019ff28c-9a8f-72c2-8f59-55e0a2e2f008 (parent orchestrator session)
---

# Handoff + executable plan — osv-mcp (2026-08-11)

## 0. Rules for writing THIS document (read before editing, not just before reading)

- Only write or replace this file at a clean, verified, committed, pushed boundary. Never checkpoint mid-work.
- Start drafting once context usage crosses ~25%. Finalize and commit before 40% — do not wait for the threshold to begin writing. The writing is a summarization task and degrades like any other task under context pressure. Treat 25-35 as the drafting target and 40 as the hard cap.
- Every claim in "Current state" (section 2) must be re-verified by running the relevant command in this session, not copied or paraphrased from the previous handoff. If you cannot re-run it, mark it unverified rather than asserting it.
- Hard caps: "Current state" max 15 lines. "Guardrails and open items" max 15 lines. "Next unit plan" has no cap — it is the actual work spec. If a section would exceed its cap, cut detail; do not compress into denser prose (denser prose is where drift hides).
- Do NOT: replay prior units' logs (git log is the record), re-explain global rules already in ~/.opengrok/AGENTS.md, restate anything the staleness check in section 6 already covers, or record acceptance evidence you did not personally observe this session.
- The handoff-hooks binary (~/.opengrok/hooks/bin/handoff-hooks, the handoff automation registered 2026-08-11) scaffolds the frontmatter at SessionEnd/PreCompact, refreshes the progress/staleness readout at SessionStart, and warns when a unit's final commit lacks the "Unit: N complete" trailer. It is passive and fails open; keep the document in the template shape so the automation can manage it.

## 1. Session protocol (global rule 9)

This project is a sequence of release units (git log records one so far: v1.2.0 -> v1.3.0); each unit ends with a verified, pushed commit set. On completing a unit: do not stop at the boundary. Begin drafting the next unit's plan text (section 3) once usage crosses ~30%; the 40% mark is when you cut over, not when you start writing.

1. Read context usage from ~/.opengrok/sessions/<percent-encoded-cwd>/<session-id>/signals.json (contextTokensUsed / contextWindowTokens, newest session dir). If signals.json is not reliably written, use the /context gauge as the authority.
2. If usage < 40%: continue immediately — write the next unit's plan into section 3 below, execute it, verify, commit, push, re-check usage, repeat.
3. At the ~40% threshold: do not pause or ask. Finish the write-up of this handoff (started per section 0's drafting rule), then launch a fresh session via ~/.local/bin/open-grok-handoff or the project wrapper.

Standing rules currently in effect:
- Backup (global rule 7): runs at commit time whenever a commit changes open-grok config. No confirmation asked.
- Graphify rebuild (rule 12): at commit time.
- repo-rag reindex (rule 11, 2026-08-11): on demand only — no commit-time step; rebuild only when search must reflect new code.

## 2. Current state (2026-08-22 — v1.4.0 COMPLETE, verified)

- What the repo is: osv-mcp v1.4.0 (Cargo.toml, rust-version 1.88) — MCP server for CVE and security advisory lookup via OSV.dev: search advisories, full advisory records, multi-language lockfile mapping, risk ranking, patch planning, evidence export. Six tools with the osv_ prefix on the rmcp 3.1 factory template (OsvServer + ToolRouter).
- Newest unit outcome: v1.4.0 (2026-08-22) made lockfile scanning multi-language. osv-map-dependencies now discovers and parses every supported manifest in a directory (twelve ecosystems: crates.io, npm, PyPI, Go, Maven, NuGet, RubyGems, Packagist, Pub, Hex, ConanCenter, Hackage) and queries OSV.dev for all of them, deduplicated by (name, ecosystem, version). Added quick-xml for XML manifests.
- Git facts (re-verified this session): branch main; remote origin https://github.com/JLFN/osv-mcp-rs.git; feature commit c8377db "feat(lockfile): scan all languages via multi-ecosystem lockfile parsing" (trailer "Unit: 3 complete"); repo visibility PUBLIC (gh repo view verified).
- Operational protocol: no special protocol — the suite is cargo test --all-targets (28 lockfile-parser + client unit tests, no live network); fmt and clippy (-D warnings) must be clean.
- Installed/registered state: see section 4.

## 3. Next unit plan — none documented

Status: not started.

- No active plan is documented. Derive the next unit from git log and the open issues on github.com/JLFN/osv-mcp-rs; do not invent work.
- Trailer convention: the final commit of each unit carries the trailer "Unit: N complete" as its last body line, so a fresh session can reconstruct unit boundaries with git log --grep "Unit: .* complete" instead of reading diffs (per the template). As of c8377db only that commit carries a trailer; earlier units (v1.2.0, v1.3.0) were not tagged.
- When a unit completes: replace this entire section with the next unit's plan, fold this unit's outcome into section 2, and advance last_updated_commit in the frontmatter in the SAME commit.

## 4. Project facts a fresh session cannot re-derive

- What exists: osv-mcp v1.4.0 crate (src/main.rs, src/lockfile.rs, src/osv.rs). The deliverable binary lives at bin/osv-mcp — /bin is gitignored, so a fresh clone cannot see it; reproduce it with the canonical builder: bash /data/build/linux/build.sh -p /data/osv-mcp-rs (produces bin/osv-mcp, removes target/). The embedded build/ builder is tracked in the repo.
- Installed / registered: ~/.local/bin/osv-mcp = the v1.4.0 release binary (built 2026-08-22, 5357704 bytes, identical to bin/osv-mcp; installed via atomic mv over the running v1.3.0); registered as the [mcp_servers.osv-mcp] entry in ~/.opengrok/config.toml (command "osv-mcp"). The session's connected server process is still the old v1.3.0 inode until restarted; restart to serve the new multi-language tools in-session. Skill skills/osv-mcp/SKILL.md is tracked in the repo and synced to ~/.opengrok/skills/osv-mcp/.
- Environment facts: outbound HTTPS to api.osv.dev required; no API key, no local database. OSV batch ecosystem identifiers verified live: Pub (Dart), ConanCenter (C/C++), Hackage all accepted; Swift/swiftpm rejected by OSV.dev (not supported).
- Verification: 28 tests pass; fmt + clippy clean; OSV scan of the project dirty then clean (two advisories fixed by dependency bumps, see c8377db).

## 5. Guardrails and open items

- Global rules in effect (from ~/.opengrok/AGENTS.md): yolo mode, no pause-and-ask (rules 6/7/8/9/10); canonical builder for deliverables (5); OSV scan before push (10); graphify rebuild at commit time (12); repo-rag on demand (11); never publish private repos, visibility check (gh repo view) before any remote action (6); no emojis / plain text / conventional commits with QA bodies (1-3).
- Project-specific guardrails: none — the repo has no AGENTS.md. Keep the osv_ tool-name prefix (v1.3.0 renamed the tools; prompts referencing the old names must be updated). Repo visibility verified this session via gh repo view JLFN/osv-mcp-rs: PUBLIC (safe to push). The crates.io release is prepared in the README; before publishing, re-run the visibility check.
- OPEN items: none known. The next unit is to be derived from git log and open issues (section 3).

## 6. Progress and staleness check (run this first, every session)

Progress meter (how far through the plan we are — the diff you run after a crash or stop):
    cd /data/osv-mcp-rs
    git log --oneline e41a10a..HEAD
    git diff --stat e41a10a..HEAD
    git log --grep "Unit: .* complete" e41a10a..HEAD

The diff shows what changed; the grep lists completed unit boundaries without reading diffs (each unit's final commit carries the "Unit: N complete" trailer, per section 3). Trust git over the plan headings: continue with the first unit whose work is NOT in the diff. (plan_start_commit equals current HEAD, so the meter is empty until the first unit lands.)

Staleness check (does this handoff predate newer work):
    cd /data/osv-mcp-rs && git log --oneline e41a10a..HEAD
- Any output means this handoff predates newer commits. Read the log and diffs before trusting sections 2-5. Update last_updated_commit in the frontmatter when done.
- Branch or remote in the frontmatter differs from the actual repo: stop and reconcile before continuing; do not proceed on a guess.

This document is COMPLETE and self-contained: a new session can execute the project end to end from this file alone. It carries the plan ahead, the facts git cannot provide, and the guardrails. History is deliberately absent — git log and the project memory entry are the historical record, and the git diff from plan_start_commit is the progress meter.
