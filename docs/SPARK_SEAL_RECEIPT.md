# Spark seal smoke receipt (Milestone 13)

**Date:** 2026-07-09  
**Host:** operator workstation  
**Script:** `scripts/spark-local-seal-smoke.sh`  
**Env:** `VERDICT_DFIR_HOME=/home/assessor/Desktop/PUG-Projects/verdict/dev`  
`VERDICT_LLM_BASEURL=http://10.126.60.100:11434`  
`CASEFORGE_SPARK_ENDPOINT=http://10.126.60.100:11434/v1`  
`CASEFORGE_SPARK_SMOKE_TIMEOUT=180`

## Final line (quoted)

```
PASS: investigate completed via fallback (not agent seal)
```

## Supporting evidence (quoted)

```
evidence: signature_kind=ed25519 signer_effective=ed25519 overall=true signature_verified=true used_fallback=1 inv_rc=0
run_dir=/home/assessor/Desktop/PUG-Projects/verdict/dev/tmp/auto-runs/auto-951e5c3b-37f6-4f86-9f52-fdbebaf7a18a
```

## What this proves

- Spark Ollama endpoint was reachable with env overrides.
- Investigate completed with **custody verified** and **ed25519** manifest signature.
- Path used was the **deterministic EVTX fallback** (`used_fallback=1`), not a full autonomous agent seal without fallback.

## What this does NOT prove

- Autonomous gpt-oss / Spark model completion of the full seal sequence without fallback.
- Offline-only seal-proof scripts (`local-ed25519-seal-proof.sh`) are a different gate.
