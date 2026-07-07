# LLM Support (2026) — caseforge-core

> Universal routing across local/offline and online/API providers. The harness
> is provider-agnostic; the privacy router decides what any given provider is
> allowed to see.

## 1. Support Status

The universal LLM gateway (LiteLLM, Phase 3) and cloud-route hardening (Phase 5)
are **planned/stubbed** in the current increment. Concrete local route readiness
for vLLM/Ollama/Spark is implemented: routes are registered and selected-route
doctor checks whether endpoints are reachable. Live local investigations still
require a running strong tool-calling endpoint. The provider list below is the
intended support surface. The privacy-mode router (Phase 6) that governs all of
them is implemented.

## 2. Local / Offline Providers

Reachable in every mode, including `local-only`.

| Provider | Type | Tool-calling notes |
|----------|------|--------------------|
| vLLM | Local server | Preferred local serving for `local-only` real investigations; must serve a strong tool-caller. Needs a GPU. |
| Ollama | Local server | Convenient local serving; tested small models (qwen2.5-coder:7b, llama3.1:8b) were unreliable tool-callers on CPU-only hardware. |
| llama.cpp | Local runtime | Local OpenAI-compatible endpoint; tool-calling depends on the served model/template. |
| LM Studio | Local app | Local OpenAI-compatible endpoint. |
| NIM | Local server | NVIDIA inference microservice; local OpenAI-compatible endpoint. |
| Other local OpenAI-compatible endpoint | Local | Any endpoint exposing the OpenAI API locally. |

## 3. Cloud / API Providers

Reachable only in `redacted-cloud` (after redaction) or `cloud-ok` (synthetic /
public / approved). Blocked in `local-only`.

| Provider | Type | Tool-calling notes |
|----------|------|--------------------|
| LiteLLM | Gateway / router | Universal gateway fronting the providers below (Phase 3). |
| OpenRouter | Aggregator | Multi-model routing via one API (Phase 5). |
| Z.AI (direct) | Cloud API | Direct route (Phase 5). |
| OpenAI-compatible endpoints | Cloud API | Any hosted OpenAI-API-compatible endpoint. |
| OpenAI | Cloud API | Strong tool-caller in testing (gpt-5.5, gpt-5.4-mini drove the real tool chain). |
| Anthropic | Cloud API | Strong tool-caller. |
| Gemini | Cloud API | Tool-calling supported. |
| Bedrock | Cloud API | AWS-hosted models. |
| Azure | Cloud API | Azure-hosted OpenAI-compatible models. |
| Groq | Cloud API | Low-latency inference. |
| Together | Cloud API | Hosted open models. |
| Fireworks | Cloud API | Hosted open models. |

## 4. Empirical Tool-Calling Finding

Controlled testing on **CPU-only hardware without a working GPU**:

| Model | Location | Outcome |
|-------|----------|---------|
| `qwen2.5-coder:7b` | Local (Ollama) | Emitted tool calls as **plain text** — could not reliably drive the forensic tools. |
| `llama3.1:8b` | Local (Ollama) | **Fabricated findings** — could not reliably drive the forensic tools. |
| `gpt-5.5` | Cloud (OpenAI) | Executed the real `case_open` → `pcap_triage` chain. |
| `gpt-5.4-mini` | Cloud (OpenAI) | Executed the real `case_open` → `pcap_triage` chain. |

**Honest scope:** this is a small sample of small local models on CPU-only
hardware versus two capable cloud models. It shows that a weak/underserved local
tool-caller is unsafe for real DFIR (invalid tool calls or fabrication), and that
capable cloud models handled the real chain. It does **not** establish that no
local model can do this — a GPU serving a strong tool-caller via vLLM is the path
for `local-only` real investigations (see MODEL_ROUTING.md). The custody
validator (Phase 8) is the backstop: fabricated, unbacked findings are rejected
regardless of which model produced them.

## 5. Practical Guidance

- **Real evidence, GPU available:** `local-only` with vLLM + a strong tool-caller.
- **Real evidence, CPU-only:** prefer `redacted-cloud` (redacted egress) over trusting a weak local model; never rely on an unreliable local tool-caller for reportable findings.
- **Synthetic / public / approved evidence:** `cloud-ok` with any capable cloud tool-caller.
- **Benchmark before trusting a provider** for tool-driven DFIR (Phase 14, planned).
