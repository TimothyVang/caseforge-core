# VERDICT + xAI Grok **cloud** (not local LLM / not Spark)

This is the **cloud model path**: the agent runtime calls **xAI’s Grok API** over the
internet. It is **not** Ollama on a DGX Spark and **not** `local-only` privacy.

## Privacy (read first)

| Mode | Grok cloud allowed? |
|------|---------------------|
| `local-only` (default) | **No** — privacy router blocks `privacy_locations: [cloud]` |
| `redacted-cloud` | Yes **after** redaction |
| `cloud-ok` | Yes for **synthetic / public / lab / operator-approved** evidence only |

**Never** send seized/private case evidence to Grok under `cloud-ok` unless the
operator has explicitly approved cloud egress and classified evidence correctly.

## Setup

1. Get an API key from the [xAI console](https://console.x.ai/).
2. Export it (never commit):

```bash
export XAI_API_KEY=xai-...
```

3. Routes (in `configs/model-routes.yaml`):

| Route id | Model ref passed to engine | Notes |
|----------|----------------------------|--------|
| `xai-grok` | `xai/grok-3` | Default Grok cloud route |
| `xai-grok-mini` | `xai/grok-3-mini` | Smaller / cheaper |

Provider registry: `xai` in `configs/provider-capabilities.yaml` (`XAI_API_KEY`).
Locked profile: `configs/opencode/opencode.json` includes an `xai` provider block.

## Commands

List routes (Grok should show **deny** under local-only, **allow** under cloud-ok + synthetic):

```bash
caseforge models --privacy local-only
caseforge models --privacy cloud-ok --evidence synthetic
```

Investigate with Grok cloud (synthetic fixture example):

```bash
export XAI_API_KEY=...
export VERDICT_DFIR_HOME=/path/to/dev-verdict   # toolkit
export VERDICT_BIN=/path/to/verdict              # engine binary

caseforge investigate fixtures/synthetic \
  --privacy cloud-ok \
  --evidence synthetic \
  --route xai-grok
```

Or DE_1102 lab EVTX (operator-approved public sample):

```bash
caseforge investigate "$VERDICT_DFIR_HOME/evidence/DE_1102_security_log_cleared.evtx" \
  --privacy cloud-ok \
  --evidence public \
  --route xai-grok
```

Smoke helper:

```bash
export XAI_API_KEY=...
bash scripts/grok-cloud-smoke.sh
```

## vs Spark / local

| | Spark Ollama | Grok cloud |
|--|--------------|------------|
| Route | `spark-ollama` | `xai-grok` |
| Endpoint | Your LAN Ollama | `https://api.x.ai/v1` |
| Privacy | `local` | `cloud` |
| Env | `VERDICT_LLM_BASEURL` | `XAI_API_KEY` |
| When offline Spark | fails | works if internet + key |

## Doctor

```bash
caseforge doctor --route xai-grok
# Expect: route present; cloud key not probed the same as local endpoint
```

If `XAI_API_KEY` is missing, investigate will fail at model auth — export the key first.
