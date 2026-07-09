# Tracking: local-LLM seal failure — the fix, per repo

Status: **proposed, not yet implemented.** Diagnosis and reproduction are in
[`LOCAL_LLM_SEAL_FAILURE.md`](./LOCAL_LLM_SEAL_FAILURE.md). This file tracks the fix
and which repo/PR each part belongs to.

## The fix (4 parts)

| # | Fix | What changes | Repo | File(s) |
|---|-----|--------------|------|---------|
| 1 | **Force a real signer on local seal** | `manifest_finalize` defaults to / coerces `signer=ed25519` for local sealing instead of `stub`; a stub-signed manifest can never pass custody, so a model that "finalizes" still fails. Make ed25519 the local default. | **dev** (`dev-verdict-github`) | `services/agent/findevil_agent/crypto/signer.py` (default `kind`), + the `manifest_finalize` MCP tool signer default |
| 2 | **Tolerate the `path` alias** | `manifest_verify` (and siblings) accept `path` as an alias for `manifest_path` so the commonest local-model arg slip doesn't burn a tool call and derail the seal sequence. | **dev** | `services/agent/findevil_agent/crypto/manifest.py` + the MCP input schema/handler for `manifest_verify` |
| 3 | **Constrain EVTX querying + fail loud on stub** | Prompt: run `evtx_query` with **no** `eids` filter first (histogram), then filter — never guess an event id (kills `eids:[1102] -> 0 rows -> NO_EVIL`). caseforge should reject a `stub`-signed produced run with a clear message rather than silently falling back. | **caseforge** (`caseforge-core`) | `packages/caseforge-cli/src/commands/investigate.ts` (prompt block ~395-412; custody message) |
| 4 | **Multi-file case scoping** | Enumerate and open **all** EVTX files in a case directory, not just the first, on both the agent path (`case_open` selection) and the deterministic fallback. | **caseforge** + **dev** | caseforge evidence resolution in `investigate.ts`; `dev` `scripts/find_evil_auto.py` fallback |

## PR routing (and two caveats)

- **dev PR** (`dev-verdict-github`, base `develop`): fixes **1, 2**, and the fallback
  half of **4**. This is the core of the fix — the custody-affecting change.
- **caseforge PR** (`caseforge-core`): fixes **3** and the evidence-scoping half of **4**.
  Continues on the existing `agent/m6-caseforge-local-llm` branch (or a fresh one).
- **beta** (`verdict-dfir-beta`): **not a hand-authored PR.** Per the umbrella CLAUDE.md,
  beta only receives exported snapshots via `dev/scripts/ship-beta.sh` (secret-audited,
  dry-run by default). The correct "beta" step is: **after the dev PR merges, run
  `ship-beta.sh --push`** to publish the fixed snapshot. Tracked here so it is not
  forgotten, but it is a publish action, not a code PR.
- **verdict-opencode** (the engine, subtree under `caseforge/engine`): **no change
  identified as required** — the fixes live in the MCP tools (dev) and the caseforge
  prompt. If we decide the engine should normalize tool-arg drift itself (a more general
  version of fix 2), that PR goes upstream via
  `git subtree push --prefix=caseforge/engine <verdict-opencode-remote> <branch>`.
  Left OPEN pending a decision on whether the engine should own arg-normalization.

## Verification (Definition of Done for the fix)

A local-LLM run is "fixed" when, on the Spark with a local model:

1. `caseforge investigate <case-dir> --route local-ollama` produces a **sealed agent
   run** (not the fallback) — `manifest_verify.overall = true`, `signer = ed25519`.
2. The agent reads **all** EVTX files in the case (the WMI file is parsed; 4624/4688
   appear in the timeline).
3. The verdict is **INDETERMINATE** (single-source EVTX), not `NO_EVIL`, and the
   SpoolFool + WMI findings are present.
4. `node scripts/selftest.mjs` (caseforge) and dev's test suite stay green.
