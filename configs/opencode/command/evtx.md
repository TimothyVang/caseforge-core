---
description: Investigate a single Windows event log (.evtx) — the lightweight case
agent: verdict
---

Investigate the Windows event log `$1` (full argument string: `$ARGUMENTS`). This is the lightweight case (matches the `--real-evidence` smoke flow).

Operate read-only on evidence. SHA-256 every tool output. Cite the originating `tool_call_id` on every Finding. Emit only the scoped verdict words: `SUSPICIOUS`, `INDETERMINATE`, or `NO_EVIL` (never a whole-environment clean bill).

Tool sequence (thread `case_id` through every call):

1. `case_open` on `$1` — SHA-256 + `case_id`. Read `image_hash`, `image_size_bytes`, `id`. (both pools)
2. `evtx_query` — parse the log; pull the EID histogram (4624/4625/4688/7045…). (both)
3. `hayabusa_scan` (optional) — Sigma rule scan; runs ONLY when a `.evtx` **directory** is available. (Pool A)

A single `.evtx` file gets `evtx_query` only. `hayabusa_scan` is directory-based (it walks a folder), so it runs only when an EVTX *directory* is supplied — e.g. a Velociraptor zip's `Logs/`, or a mixed case dir with >=2 logs in one folder. To get Sigma coverage on one log, put it in a directory and point the run there; this is a deliberate design choice, not a missing tool.

Execution claims require at least two current-case artifact classes; a single EVTX rarely meets that bar on its own, so an execution/persistence lead from one log stays a lead unless a second class corroborates it. Treat Hayabusa/Sigma output as leads until corroborated.

Run both interpretation pools (Pool A persistence: 7045 service installs, T1547/T1543/T1546/T1053/T1574; Pool B exfil/malware: 4688 command lines for `certutil`/`bitsadmin`/`curl`/`wget`/`Invoke-WebRequest`, T1041/T1567/T1048/T1052/T1110). Where they disagree on the same event, `detect_contradictions` is expected to fire — surface it before the judge.

Stop and ask when: `BinaryNotFound`; two consecutive iterations yield no new Findings or contradictions; a `CONFIRMED` Finding corroborates across fewer than 2 artifact classes; or the evidence vault is modified mid-run.

After both pools return Findings, hand off to the reason/seal phase (`/verdict`).
