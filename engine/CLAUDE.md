# CLAUDE.md — verdict-opencode

You are in the VERDICT agent runtime (a branded opencode fork).

## VERDICT ecosystem — what is what

VERDICT is a local-first DFIR (digital forensics & incident response) agent platform, split into three repos:

| Repo | Role | It is… |
|---|---|---|
| [`caseforge-core`](https://github.com/TimothyVang/caseforge-core) | Headless **controller**: privacy routing, model selection, structured findings, custody validation, the `caseforge` CLI. | the **driver** |
| [`verdict-opencode`](https://github.com/TimothyVang/verdict-opencode) **(this repo)** | The agent **runtime** — a branded fork of [opencode](https://github.com/sst/opencode); the `verdict` binary is built from it. | the **engine** |
| [`verdict-dfir-community`](https://github.com/TimothyVang/verdict-dfir-community) | The **forensic toolkit**: `findevil-mcp` (Rust, 32 tools) + `findevil-agent-mcp` (Python, 14 tools) + DFIR doctrine + hash-chained custody. Referenced via `VERDICT_DFIR_HOME`. | the **evidence lab** |

**Runtime flow:** `caseforge` (controls + guards) → `verdict` binary (this repo runs the agent) → `findevil` MCP tools (do the forensics) → hash-chained custody → `caseforge verify`.

**Two rules everything obeys:** the LLM is not the forensic source of truth (findings must cite a `tool_call_id` + `output_sha256` + verified manifest); real evidence stays local by default.

## Working here

- This is a Bun/TypeScript monorepo fork of opencode.
- Build the `verdict` binary with: `cd packages/opencode && bun run script/build.ts --single --skip-embed-web-ui`.
- Branding lives in a few files and is re-applied by `scripts/verdict-rebrand.sh`.
- It tracks upstream opencode (the `upstream` remote / branch `dev`) — see [`VERDICT-FORK.md`](VERDICT-FORK.md) for the fork changes and re-sync steps.
- Do NOT do DFIR/forensic work here — that lives in `caseforge-core` (the driver) and `verdict-dfir-community` (the toolkit).
