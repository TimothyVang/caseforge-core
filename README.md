<p align="center"><b>caseforge-core</b></p>

<p align="center"><b>Show Me the Evidence — a headless, local-first DFIR agentic core.</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/runtime-opencode%20fork-4D5DFF.svg" alt="opencode">
  <img src="https://img.shields.io/badge/models-provider--agnostic-B8A8FF.svg" alt="providers">
  <img src="https://img.shields.io/badge/privacy-local--only%20by%20default-73D9C2.svg" alt="privacy">
  <img src="https://img.shields.io/badge/findings-evidence--bound%20%2B%20custody-73D9C2.svg" alt="custody">
  <img src="https://img.shields.io/badge/license-Apache--2.0-4D5DFF.svg" alt="license">
</p>

---

> **The LLM is not the forensic source of truth.** It proposes steps and drafts
> reports; every reportable finding must be backed by a VERDICT tool call — a
> `tool_call_id`, an `output_sha256`, and a verified manifest. **Real evidence
> stays local by default.**

`caseforge-core` is the headless DFIR engine that drives the
[VERDICT](https://github.com/TimothyVang/verdict-dfir-community) forensic MCP
tools with the [`verdict`](https://github.com/TimothyVang/verdict-opencode)
agent runtime, on the model **you** choose — local (vLLM/Ollama) or cloud —
under a strict privacy router. It runs on a laptop, DGX/Spark, SIFT workstation,
server, or CI fixture runner. No examiner GUI required.

## Where this fits — the VERDICT ecosystem

VERDICT is a local-first DFIR agent platform split into three repos:

| Repo | Role | It is… |
|---|---|---|
| **caseforge-core** (this repo) | Headless **controller**: privacy routing, model selection, structured findings, custody validation, the `caseforge` CLI. | the **driver** |
| [verdict-opencode](https://github.com/TimothyVang/verdict-opencode) | The agent **runtime** — a branded fork of [opencode](https://github.com/sst/opencode); the `verdict` binary is built from it. | the **engine** |
| [verdict-dfir-community](https://github.com/TimothyVang/verdict-dfir-community) | The **forensic toolkit**: `findevil-mcp` (32 Rust tools) + `findevil-agent-mcp` (14 Python tools) + DFIR doctrine + hash-chained custody. Set as `VERDICT_DFIR_HOME`. | the **evidence lab** |

**Runtime flow:** `caseforge` (controls + guards) → `verdict` binary (runs the agent) → `findevil` MCP tools (do the forensics) → hash-chained custody → `caseforge verify`.
caseforge does **not** contain the other two — it drives the `verdict` binary (on PATH) and the toolkit (via `VERDICT_DFIR_HOME`). `scripts/setup.sh` clones + builds all three.

## Status — MVP core

Implemented and tested (this build):

- **OpenCode SDK controller** (`@verdict/caseforge-sdk`, absorbs the VERDICT agent harness).
- **VERDICT MCP integration** — attaches `findevil-mcp` (32 Rust tools) + `findevil-agent-mcp` (14 Python tools) via the locked profile in `configs/opencode/`.
- **Privacy-mode router** — `local-only` (default) / `redacted-cloud` / `cloud-ok`, fail-closed.
- **Structured finding schema** — every finding cites ≥1 tool call; invalid findings rejected.
- **VERDICT run-artifact + custody validator** — `verify` marks runs `complete` / `incomplete` / `custody-invalid`.
- **Local route readiness** — vLLM/Ollama/Spark routes are registered and checked by selected-route doctor; live local investigations require a running endpoint.
- **CLI** — `doctor`, `models`, `investigate`, `verify`. Fixture-only GitHub workflow.

Planned / stubbed (see [`docs/BUILD_ORDER.md`](docs/BUILD_ORDER.md)): LiteLLM universal gateway (Phase 3), OpenRouter/Z.AI route hardening (5), OCR router (11), Rust ingest core (12–13), benchmarks (14).

## CLI

```bash
caseforge doctor                                   # environment + config prereqs
caseforge models [--privacy MODE] [--evidence CLASS]   # routes + privacy permissions
caseforge investigate <evidence-path> [--privacy …] [--evidence …] [--route …]
caseforge verify <run-dir>                          # validate VERDICT artifacts + custody
# planned: caseforge gateway start | benchmark run | ocr <id> | ingest <path>
```

`privacy` defaults to **local-only**; `evidence` defaults to **sensitive** (fail-closed).

## Privacy routing (the core guarantee)

| Mode | Local models | Cloud models |
| --- | --- | --- |
| **local-only** (default) | ✅ | ❌ blocked — no evidence egress, no web |
| **redacted-cloud** | ✅ | ✅ only after redaction |
| **cloud-ok** | ✅ | ✅ only for synthetic / public / operator-approved evidence |

```bash
caseforge models --privacy local-only          # cloud routes show [deny]
caseforge models --privacy cloud-ok --evidence synthetic   # cloud routes show [allow]
```

## Model reality (important)

Real agentic DFIR needs a **strong native tool-calling** model. In testing on a
CPU-only box: small local models did **not** reliably drive the tools
(`qwen2.5-coder:7b` emitted tool calls as text; `llama3.1:8b` fabricated
findings), while capable cloud models (`gpt-5.5`, `gpt-5.4-mini`) executed the
real `case_open`→`pcap_triage` chain against a fixture. **Local-only real
investigations need a GPU + vLLM serving a strong tool-caller** — the routing is
ready for that the moment the hardware is. See [`docs/MODEL_ROUTING.md`](docs/MODEL_ROUTING.md).

## Quickstart

Fresh box (clones + builds `verdict` binary, forensic MCP tools, and this repo):

```bash
bash scripts/setup.sh        # git, node>=20, cargo, uv, bun required
```

Offline on a **DGX Spark** (local model on the Spark's GPU, no cloud) — see
[docs/DGX-SPARK.md](docs/DGX-SPARK.md).

Manual:

```bash
npm install && npm run build
export VERDICT_DFIR_HOME=~/verdict-dfir-community      # toolkit with the MCP servers
node scripts/selftest.mjs                              # model-independent guarantees
node packages/caseforge-cli/dist/src/cli.js doctor

# synthetic fixture, cloud-ok (needs an authed cloud provider), NOT sensitive:
caseforge investigate fixtures/synthetic --privacy cloud-ok --evidence synthetic
```

## Layout

```
configs/    opencode.verdict profile + provider-capabilities / model-routes / gateway / ingest / ocr
packages/   caseforge-sdk (controller + privacy + findings + custody), caseforge-cli
crates/     caseforge-ingest (planned Rust ingest)
docs/       PRD, ARCHITECTURE, SECURITY, BUILD_ORDER, MODEL_ROUTING, LLM_SUPPORT_2026, EXTERNAL_WORKBENCH_BRIDGES
scripts/    bootstrap, doctor, start-llm-gateway, run-local-smoke, selftest
.github/    fixtures-only CI (synthetic/public evidence only — never real)
```

## Credits & licensing

Apache-2.0. Forensic tools & doctrine: VERDICT
([verdict-dfir-community](https://github.com/TimothyVang/verdict-dfir-community)).
Agent runtime: [verdict-opencode](https://github.com/TimothyVang/verdict-opencode)
(fork of [opencode](https://github.com/sst/opencode), MIT). See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
