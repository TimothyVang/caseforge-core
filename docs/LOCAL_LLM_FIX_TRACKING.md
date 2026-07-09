# Tracking: local-LLM seal failure — the fix, per repo

Status: **implemented in open PRs; live Spark re-verify is the remaining done-gate.**
Diagnosis: [`LOCAL_LLM_SEAL_FAILURE.md`](./LOCAL_LLM_SEAL_FAILURE.md).

## The fix (4 parts)

| # | Fix | Status | Repo | Notes |
|---|-----|--------|------|-------|
| 1 | **Force real signer** | **N/A as crypto change** | — | `manifest_finalize` already defaults to `ed25519` (`test_default_signer_is_ed25519`). Model requested `signer:"stub"` — fixed prompt-side in #3. |
| 2 | **Tolerate the `path` alias** | **done** (dev PR #173) | **dev** | MCP `manifest_verify` accepts `path` → `manifest_path`. |
| 3 | **Survey EVTX + forbid stub** | **done** (caseforge PR #9) | **caseforge** | Prompt: no eids on first query; never `signer:'stub'`; name `manifest_path`. |
| 4 | **Multi-file case scoping** | **done** (caseforge PR #9) | **caseforge** | Fallback used to require `caseOpenPath.endsWith(".evtx")`, so multi-EVTX dirs never fell back / collapsed to one file. `resolveEvtxFallbackPath` now passes the **directory** to `find_evil_auto`, which already inventories every EVTX. Agent path already says "Do not collapse the directory to only one file." |

## PR routing (and two caveats)

- **dev PR** (`dev-verdict-github`, base `develop`): fix **2** — #173.
- **caseforge PR** (`caseforge-core`): fixes **3** and **4** — #9.
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
