# Spark seal smoke receipt (Milestone 13)

**Date:** 2026-07-09T17:02Z (UTC)  
**Host:** operator workstation  
**Script:** `scripts/spark-local-seal-smoke.sh`  
**Branch:** `agent/m13-spark-seal-receipt`  
**Env:**

```bash
export VERDICT_DFIR_HOME=/home/assessor/Desktop/PUG-Projects/verdict/dev
export VERDICT_LLM_BASEURL=http://10.126.60.100:11434
export CASEFORGE_SPARK_ENDPOINT=http://10.126.60.100:11434/v1
export CASEFORGE_SPARK_SMOKE_TIMEOUT=240
```

## Spark tags probe (HTTPS not used — LAN Ollama HTTP only)

```text
curl -sS -m 2 http://10.126.60.100:11434/api/tags
# models present include: qwen3.6:35b-a3b, gpt-oss:120b, llama4:16x17b, llama3.1:8b, gpt-oss:20b
```

## Final line (quoted — exact)

```
PASS: investigate completed via fallback (not agent seal)
```

## Supporting evidence (quoted)

```
evidence: signature_kind=ed25519 signer_effective=ed25519 overall=true signature_verified=true used_fallback=1 inv_rc=0
run_dir=/home/assessor/Desktop/PUG-Projects/verdict/dev/tmp/auto-runs/auto-7618e1c5-760e-428a-83fe-363481de2ed8
```

Investigate log notes agent path failed open (`Error: Not Found: 404 page not found` against the local route), then:

```
[caseforge] agent run did not produce a complete sealed EVTX run; using deterministic local EVTX auto-runner fallback.
...
signer          = ed25519
...
manifest_verify = PASS
...
[caseforge] verifying deterministic EVTX fallback run: .../auto-7618e1c5-760e-428a-83fe-363481de2ed8
[OK] ...
  manifest custody: verified
```

## What this proves

- Spark Ollama was reachable (`/api/tags` returned models).
- Investigate completed with **custody verified** and **ed25519** on the **deterministic EVTX fallback** path (`used_fallback=1`).
- Smoke script classification is honest: **PASS fallback**, not agent seal.

## What this does NOT prove

- Autonomous Spark / gpt-oss completion of the full seal sequence without fallback.
- That the agent path is healthy (this run saw agent fail with HTTP 404 before fallback).
- Offline-only seal-proof scripts (`local-ed25519-seal-proof.sh`) are a different gate.

## Prior attempt in the same session (not the quoted outcome)

With `VERDICT_LLM_BASEURL=http://10.126.60.100:11434/v1`, investigate hung until the smoke timeout (rc=124). Case dir existed with only `case.json` (no `run.manifest.json`). Exact line from that attempt:

```
FAIL: run dir missing run.manifest.json (inv_rc=124 run_dir=/home/assessor/Desktop/PUG-Projects/verdict/dev/.project-local/findevil/cases/4a1361c0-861e-4752-a7e6-3a616f4a2769)
```

That FAIL is model/timeout hang behavior, not a smoke-script path/parse bug. No seal claim was made for that attempt.

## Script status

No smoke-script bug fixed in this lane. Receipt only.

## Milestone 14 — REQUIRE_AGENT gate (script option)

`CASEFORGE_SPARK_SMOKE_REQUIRE_AGENT=1` makes the smoke **FAIL** when the
deterministic EVTX fallback ran (`used_fallback=1`). Default remains `0`
(m13 behavior: PASS with fallback, never claim agent seal).

This option does **not** produce an agent seal by itself. A true
`used_fallback=0` agent-path seal is still open until the investigate
agent path succeeds without fallback.

```bash
# Default (honest fallback PASS when agent path fails open):
bash scripts/spark-local-seal-smoke.sh

# Strict (FAIL if fallback was used — use when debugging agent path only):
CASEFORGE_SPARK_SMOKE_REQUIRE_AGENT=1 bash scripts/spark-local-seal-smoke.sh
```
