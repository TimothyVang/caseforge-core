---
description: Triage a mixed evidence case directory (breadth-first)
agent: verdict
---

Investigate the case directory `$1` (full argument string: `$ARGUMENTS`) as the default breadth-first entry point. A mixed case dir — holding a disk image, a memory image, a Velociraptor zip, and EVTX/PCAP files — is how you exercise the whole tool surface in one run.

Operate read-only on evidence. SHA-256 every tool output. Cite the originating `tool_call_id` on every Finding. Emit only the scoped verdict words: `SUSPICIOUS` (reportable evidence found), `INDETERMINATE` (leads or limited coverage prevent a scoped clearance), or `NO_EVIL` (no reportable Finding in the artifacts actually examined — never a whole-environment clean bill).

Sequence:

1. Call `case_open` on `$1` (directory/inventory mode: `case_open_directory` -> `investigate_inventory`). Read the returned `image_hash`, `image_size_bytes`, and `id` (the `case_id` you thread through every subsequent tool via its `case_id` argument).
2. Classify every artifact in the directory and dispatch each to its type playbook, stitching the results together under one `case_id`:
   - **memory** (`.mem`/`.raw`/`.dmp`/`.vmem`) -> `vol_pslist`, then always `vol_psscan`, then `vol_psxview` when pslist diverges from psscan, then `vol_malfind`, then `yara_scan` (Pool B) over the raw image.
   - **disk** (`.e01`/`.dd`/`.raw`/`.aff`) -> `disk_mount`, `disk_extract_artifacts`, `mft_timeline`, `prefetch_parse`, `usnjrnl_query`, `registry_query`, `evtx_query`, `browser_history`, `hayabusa_scan` over the extracted EVTX dir, `yara_scan` over extracted yara-targets, then `disk_unmount` (finally-block).
   - **evtx** (`.evtx`) -> `evtx_query`; add `hayabusa_scan` only when an EVTX *directory* (>=2 logs in one folder) is present.
   - **network** (`.pcap`/`.pcapng`/Sysmon-EVTX/Zeek) -> `sysmon_network_query`, `zeek_summary`, `pcap_triage` (each fires only when its artifact class is present).
   - **velociraptor** (`.zip`) -> safely extract supported members (reject zip-slip and oversized members), then re-dispatch each extracted artifact — including memory dumps inside the zip — to the branches above.
3. Run both interpretation pools over the sequence: Pool A (persistence: Run/Services/IFEO/ScheduledTasks/WMI/injected modules; MITRE T1547/T1543/T1546/T1053/T1574) and Pool B (exfil/general malware: staging dirs, `certutil`/`bitsadmin`/`curl`/`wget`/`Invoke-WebRequest`, cloud-sync, USB writes, suspicious outbound endpoints; MITRE T1041/T1567/T1048/T1052/T1110). Where the pools disagree on the same artifact, `detect_contradictions` is expected to fire — surface it before the judge.

Stop and ask the analyst when: a tool returns `BinaryNotFound`; two consecutive iterations yield no new Findings and no new contradictions; a `CONFIRMED` Finding has a `correlate_findings` corroboration count below 2 artifact classes; or the evidence vault is modified mid-run.

Do not emit disk-content Findings from `case_open` alone — custody-only disk registration is not a Finding. A single-file input only ever triggers that one type's branch; point this command at a mixed directory for full breadth.

After both pools return Findings, hand off to the reason/seal phase (`/verdict`).
