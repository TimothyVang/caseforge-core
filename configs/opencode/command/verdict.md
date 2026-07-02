---
description: Reason over findings (ACH), verify, and seal a signed verdict manifest
agent: verdict
---

Run the reason/seal phase for the current Case `$1` (full argument string: `$ARGUMENTS`), after both pools have returned Findings from an evidence-type playbook. This is the crypto/custody terminal path — operate read-only on evidence, keep every decision on the hash-chained `audit.jsonl`, and cite the originating `tool_call_id` on every Finding.

Sequence (all through the Python `findevil-agent-mcp` crypto/ACH/custody tools; each tool call and decision is appended to the chain via `audit_append`):

1. `detect_contradictions` — surface Pool A ↔ Pool B disagreements. Resolve them, or auto-pass under unattended mode by trusting the higher-credibility pool and logging the decision with `approved_by: "auto"`.
2. **Verifier re-runs cited tool calls.** For each Finding, `verify_finding` re-runs the Finding's cited tool and compares SHA-256 against the recorded `output_sha256` — a deterministic replay must reproduce the same hash. The verifier vetoes only Findings without a valid `tool_call_id`. After each verdict, the verifier calls `pool_handoff(from_role="verifier", to_role="judge", payload={finding_id, action, replay_record_sha256})` so the judge receives structured input.
3. **Apply Analysis of Competing Hypotheses.** `judge_findings` — credibility-weighted merge of the verified Findings (the ACH step).
4. `correlate_findings` — enforce the >=2-artifact-class rule; downgrade unsupported Findings. A `CONFIRMED` Finding whose corroboration count is below 2 artifact classes must be auto-downgraded — flag the downgrade explicitly.
5. `report_qa` — the report QA gate lands in the audit chain BEFORE finalize so it is part of the cryptographic attestation; the agent does not get to revise it after the chain is sealed. A failed or missing report QA gate blocks customer-ready output.
6. **SEAL.** `manifest_finalize` — terminal step: build the Merkle tree over the hash-chained `audit.jsonl` and sign, producing `run.manifest.json`. This seals the Case (no revision after this point). Then `manifest_verify` to verify the signed manifest in-run.
7. For CONFIRMED Findings only, the originating pool calls `memory_remember(...)` with the IOC/hash/TTP a future investigation should recall (HYPOTHESIS-tier is not remembered).

Emit the scoped verdict word with citations:

- `SUSPICIOUS` — reportable evidence found.
- `INDETERMINATE` — leads or limited coverage prevent a scoped clearance.
- `NO_EVIL` — no reportable Finding in the artifacts actually examined; never a whole-environment clean bill of health.

The run is not complete unless the pipeline reached `case_open`, every Finding cites a `tool_call_id`, `report_qa` was audited, and `manifest_verify` reports `overall: true`. If `manifest_verify` is missing or `overall` is not `true`, report `RUN INCOMPLETE / CUSTODY INVALID` and do not describe the output as signed or customer-ready. If the evidence vault was modified mid-run, refuse to sign the manifest.
