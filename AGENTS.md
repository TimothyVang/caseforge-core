# AGENTS.md — caseforge-core

Agent orientation for **caseforge-core**, the headless DFIR agentic **controller**
of the VERDICT platform. (Same guidance as [`CLAUDE.md`](CLAUDE.md) — read that
for full conventions.)

## VERDICT ecosystem — what is what

| Repo | Role | It is… |
|---|---|---|
| [`caseforge-core`](https://github.com/TimothyVang/caseforge-core) **(here)** | Headless **controller**: privacy routing, model selection, structured findings, custody validation, the `caseforge` CLI. | the **driver** |
| [`verdict-opencode`](https://github.com/TimothyVang/verdict-opencode) | The agent **runtime** — branded fork of [opencode](https://github.com/sst/opencode); build the `verdict` binary from it. | the **engine** |
| [`verdict-dfir-community`](https://github.com/TimothyVang/verdict-dfir-community) | The **forensic toolkit**: `findevil-mcp` (Rust, 32 tools) + `findevil-agent-mcp` (Python, 14 tools) + DFIR doctrine + custody chain. Referenced via `VERDICT_DFIR_HOME`. | the **evidence lab** |

**Flow:** `caseforge` (controls) → `verdict` binary (runs agent) → `findevil` MCP tools (forensics) → custody chain → `caseforge verify`.

## Rules
- The **LLM is not the forensic source of truth** — findings must cite `tool_call_id` + `output_sha256` + a verified manifest.
- **Real evidence stays local by default** (`local-only`); cloud only for synthetic/public/approved/redacted.

## Working here
- Build: `npm run build` (root — SDK then CLI, order matters). Verify: `node scripts/selftest.mjs` (model-independent checks).
- Layout: `packages/caseforge-sdk` (controller+privacy+findings+custody), `packages/caseforge-cli` (`doctor/models/investigate/verify`), `configs/opencode` (DFIR profile), `docs/`.
- Don't fold in `verdict-opencode` (consumed as the `verdict` binary) or the toolkit (referenced via `VERDICT_DFIR_HOME`).
- CI runs against **synthetic fixtures only** — never real evidence.
