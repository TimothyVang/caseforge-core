#!/usr/bin/env node
/**
 * caseforge self-test — asserts the model-independent MVP guarantees:
 *  - privacy router respects mode (local-only blocks cloud; cloud-ok gates on class)
 *  - invalid findings are rejected (no evidence / bad hash)
 *  - missing VERDICT artifacts => run incomplete
 *  - failed manifest verification => custody-invalid
 *  - citation custody: unknown tool_call_id / mismatched hash => not verified
 */
import { mkdtempSync, writeFileSync, rmSync } from "node:fs"
import { join } from "node:path"
import { tmpdir } from "node:os"
import { fileURLToPath } from "node:url"
import {
  decideModel,
  validateFinding,
  validateRun,
  loadAudit,
  verifyCitations,
  REQUIRED_ARTIFACTS,
} from "../packages/caseforge-sdk/dist/src/index.js"

let pass = 0,
  fail = 0
const ok = (name, cond) => (cond ? (pass++, console.log(`  PASS ${name}`)) : (fail++, console.log(`  FAIL ${name}`)))

const local = { id: "local-ollama", location: "local" }
const cloud = { id: "openai", location: "cloud" }

console.log("privacy router:")
ok("local-only blocks cloud", decideModel(cloud, { mode: "local-only" }).allowed === false)
ok("local-only allows local", decideModel(local, { mode: "local-only" }).allowed === true)
ok("cloud-ok allows synthetic cloud", decideModel(cloud, { mode: "cloud-ok", evidenceClass: "synthetic" }).allowed === true)
ok("cloud-ok blocks sensitive cloud", decideModel(cloud, { mode: "cloud-ok", evidenceClass: "sensitive" }).allowed === false)
ok("redacted-cloud needs redaction", decideModel(cloud, { mode: "redacted-cloud" }).allowed === false)
ok("redacted-cloud allows when redacted", decideModel(cloud, { mode: "redacted-cloud", redacted: true }).allowed === true)
ok("default fail-closed (unknown class, cloud-ok) blocks", decideModel(cloud, { mode: "cloud-ok" }).allowed === false)

console.log("finding validator:")
const sha = "a".repeat(64)
ok("rejects finding with no evidence", validateFinding({ id: "1", title: "t", verdict: "SUSPICIOUS", summary: "s", evidence: [] }).valid === false)
ok("rejects bad sha", validateFinding({ id: "1", title: "t", verdict: "SUSPICIOUS", summary: "s", evidence: [{ tool: "x", tool_call_id: "c1", output_sha256: "nothex" }] }).valid === false)
ok("rejects bad verdict word", validateFinding({ id: "1", title: "t", verdict: "GUILTY", summary: "s", evidence: [{ tool: "x", tool_call_id: "c1", output_sha256: sha }] }).valid === false)
ok("accepts valid finding", validateFinding({ id: "1", title: "t", verdict: "NO_EVIL", summary: "s", evidence: [{ tool: "x", tool_call_id: "c1", output_sha256: sha }] }).valid === true)

console.log("artifact + custody validator:")
const dir = mkdtempSync(join(tmpdir(), "caseforge-run-"))
try {
  // 1. empty dir => incomplete (missing the hard custody files)
  let r = await validateRun(dir)
  ok("missing custody => incomplete", r.status === "incomplete" && r.missing.includes("run.manifest.json") && r.missing.includes("audit.jsonl"))

  // 2. all present but manifest verify fails => custody-invalid
  for (const a of REQUIRED_ARTIFACTS) writeFileSync(join(dir, a), a.endsWith(".jsonl") ? "" : "{}")
  writeFileSync(join(dir, "manifest_verify.json"), JSON.stringify({ ok: false }))
  r = await validateRun(dir)
  ok("failed manifest verify => custody-invalid", r.status === "custody-invalid")

  // 3. auto-runner shape: all present and verified => complete (full report)
  writeFileSync(join(dir, "manifest_verify.json"), JSON.stringify({ ok: true }))
  writeFileSync(join(dir, "verdict.json"), JSON.stringify({ attack_coverage: {}, findings: [] }))
  r = await validateRun(dir)
  ok("auto-runner: all present + verified => complete", r.status === "complete" && r.custodyValid === true)

  // 4. interactive agent seal: only run.manifest.json + audit.jsonl (seal on the
  //    audit chain, no manifest_verify.json / verdict.json) => complete (custody-sealed)
  const seal = mkdtempSync(join(tmpdir(), "caseforge-seal-"))
  try {
    writeFileSync(join(seal, "run.manifest.json"), "{}")
    writeFileSync(
      join(seal, "audit.jsonl"),
      JSON.stringify({ kind: "tool_call_output", payload: { tool_name: "findevil-agent-mcp_manifest_verify", output: { overall: true } } }) + "\n",
    )
    const rs = await validateRun(seal)
    ok("interactive seal (audit-chain) => complete", rs.status === "complete" && rs.custodyValid === true)
    // negative: same but overall:false => custody-invalid
    writeFileSync(
      join(seal, "audit.jsonl"),
      JSON.stringify({ kind: "tool_call_output", payload: { tool_name: "findevil-agent-mcp_manifest_verify", output: { overall: false } } }) + "\n",
    )
    const rf = await validateRun(seal)
    ok("interactive seal overall:false => custody-invalid", rf.status === "custody-invalid")
  } finally {
    rmSync(seal, { recursive: true, force: true })
  }

  // 4. citation custody against audit.jsonl
  writeFileSync(
    join(dir, "audit.jsonl"),
    JSON.stringify({ tool_call_id: "c1", output_sha256: sha }) + "\n",
  )
  const audit = await loadAudit(dir)
  ok("citation matches audit => verified", verifyCitations([{ tool_call_id: "c1", output_sha256: sha }], audit).verified === true)
  ok("unknown tool_call_id => not verified", verifyCitations([{ tool_call_id: "nope", output_sha256: sha }], audit).verified === false)
  ok("hash mismatch => not verified", verifyCitations([{ tool_call_id: "c1", output_sha256: "b".repeat(64) }], audit).verified === false)
} finally {
  rmSync(dir, { recursive: true, force: true })
}

console.log("tui workbench:")
{
  const { loadCase } = await import("../packages/caseforge-tui/dist/src/load.js")
  const { renderHeader, renderFindings, renderScreen } = await import("../packages/caseforge-tui/dist/src/render.js")
  const fixDir = fileURLToPath(new URL("../fixtures/synthetic/sample-run", import.meta.url))
  const v = await loadCase(fixDir)
  ok("tui: fixture run validates complete + custody re-verified", v.validation.status === "complete" && v.validation.custodyValid === true)
  ok("tui: header renders verdict + dual custody lights", /SUSPICIOUS/.test(renderHeader(v)) && /re-verified now/.test(renderHeader(v)))
  ok("tui: findings render cited tool_call_id", /tc-1/.test(renderFindings(v)) && /cited/.test(renderFindings(v)))
  ok("tui: screen composes all panels", renderScreen(v).length > 200)
  const vb = await loadCase(fileURLToPath(new URL("../fixtures/synthetic/broken-chain-run", import.meta.url)))
  ok("tui: broken audit chain caught (chainOk false)", vb.chainOk === false)
  const vn = await loadCase(fileURLToPath(new URL("../fixtures/synthetic/no-report-run", import.meta.url)))
  ok("tui: missing verdict.json degrades but custody holds", vn.verdict === undefined && vn.validation.custodyValid === true)
  const { listRuns } = await import("../packages/caseforge-tui/dist/src/picker.js")
  const { renderPicker } = await import("../packages/caseforge-tui/dist/src/render.js")
  const runs = await listRuns([fileURLToPath(new URL("../fixtures/synthetic", import.meta.url))])
  ok("tui: picker discovers runs with validated status", runs.length >= 3 && /CASES/.test(renderPicker(runs)))
  const { keyOf, reduce, initialState } = await import("../packages/caseforge-tui/dist/src/app.js")
  ok("tui: keyOf maps arrow/enter/quit", keyOf("\x1b[A") === "up" && keyOf("\r") === "enter" && keyOf("\x03") === "quit")
  ok("tui: reduce navigates picker<->case", reduce(reduce(initialState, "enter", 3), "back", 3).view === "picker")
}

console.log(`\n${pass} passed, ${fail} failed`)
process.exit(fail === 0 ? 0 : 1)
