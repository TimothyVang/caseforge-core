# CLAUDE.md — caseforge-core

You are in **caseforge-core**, the headless DFIR agentic **controller** of the
VERDICT platform. This file orients any agent working here.

## VERDICT ecosystem — what is what

VERDICT is a local-first DFIR (digital forensics & incident response) agent
platform, split into three repos with distinct roles:

| Repo | Role | It is… |
|---|---|---|
| [`caseforge-core`](https://github.com/TimothyVang/caseforge-core) **(you are here)** | Headless **controller**: privacy-mode routing, model selection, structured findings, custody validation, the `caseforge` CLI. | the **driver** |
| [`verdict-opencode`](https://github.com/TimothyVang/verdict-opencode) | The agent **runtime** — a branded fork of [opencode](https://github.com/sst/opencode); the `verdict` binary is built from it. | the **engine** |
| [`verdict-dfir-community`](https://github.com/TimothyVang/verdict-dfir-community) | The **forensic toolkit**: `findevil-mcp` (Rust, 32 read-only tools) + `findevil-agent-mcp` (Python, 14 custody/crypto tools) + DFIR doctrine + hash-chained chain of custody. Referenced via `VERDICT_DFIR_HOME`. | the **evidence lab** |

**Runtime flow:** `caseforge` (controls + guards) → `verdict` binary (runs the agent) → `findevil` MCP tools (do the forensics) → hash-chained custody → `caseforge verify` validates.

**Two rules everything obeys:**
- The **LLM is not the forensic source of truth** — every reportable finding must cite a `tool_call_id` + `output_sha256` backed by a verified manifest.
- **Real evidence stays local by default** (privacy `local-only`); cloud models only for synthetic / public / operator-approved / redacted material.

## What this repo contains

```
packages/caseforge-sdk/   @verdict/caseforge-sdk — opencode SDK controller (harness),
                          privacy router (privacy.ts), finding schema (finding.ts),
                          run-artifact + custody validation (artifacts.ts, verdict.ts).
                          Vendors the opencode SDK *client* under vendor/opencode-sdk.
packages/caseforge-cli/   @verdict/caseforge-cli — the `caseforge` CLI:
                          doctor · models · investigate · verify (+ planned stubs).
configs/                  opencode.verdict profile (the DFIR agents/commands/skill,
                          absorbed from the archived verdict-dfir-agent) +
                          provider-capabilities / model-routes / gateway|ingest|ocr (planned).
crates/caseforge-ingest/  planned Rust ingest core (Phase 12) — placeholder.
docs/                     PRD, ARCHITECTURE, SECURITY, BUILD_ORDER, MODEL_ROUTING,
                          LLM_SUPPORT_2026, DGX-SPARK, EXTERNAL_WORKBENCH_BRIDGES.
scripts/                  setup.sh (clone+build all 3 repos), selftest.mjs, bootstrap/doctor/…
```

## How to work here (conventions)

- **Build order matters:** the CLI depends on the SDK's built types. Use `npm run build` (root — builds SDK then CLI). Never `--workspaces` unordered.
- **Verify with `node scripts/selftest.mjs`** — 17 model-independent checks (privacy routing, finding rejection, artifact/custody validation). Keep them green.
- **TypeScript, ESM, NodeNext** — imports use `.js` extensions; strict mode.
- **The vendored SDK** (`packages/caseforge-sdk/vendor/opencode-sdk`) is intentionally modifiable — do not replace it with a registry version.
- **CI** (`.github/workflows/caseforge-fixtures.yml`) runs build + selftest + the privacy/verify guarantees against **synthetic fixtures only** — never real evidence.
- **Don't fold in the other repos.** caseforge consumes the `verdict` *binary* (on PATH) and the toolkit *scripts* (via `VERDICT_DFIR_HOME`); their source stays external.

## Using the tools

```bash
npm install && npm run build
export VERDICT_DFIR_HOME=/path/to/verdict-dfir-community   # the forensic toolkit
node packages/caseforge-cli/dist/src/cli.js doctor         # prereq check
node packages/caseforge-cli/dist/src/cli.js models --privacy local-only
node packages/caseforge-cli/dist/src/cli.js investigate <evidence> --privacy cloud-ok --evidence synthetic --route openai
node packages/caseforge-cli/dist/src/cli.js verify <run-dir>
```

**Archived, superseded by this repo:** `verdict-agent-harness` → `packages/caseforge-sdk`; `verdict-dfir-agent` → `configs/opencode`.
