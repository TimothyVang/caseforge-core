import { test } from "node:test"
import assert from "node:assert/strict"
import { fileURLToPath } from "node:url"
import { dirname, join } from "node:path"
import { loadCase } from "../dist/src/load.js"
import { renderHeader, renderFindings, renderCoverage, renderAudit, renderScreen } from "../dist/src/render.js"

const here = dirname(fileURLToPath(import.meta.url))
const FIX = join(here, "..", "..", "..", "fixtures", "synthetic", "sample-run")

test("fixture run validates complete + custody valid (live re-verify)", async () => {
  const v = await loadCase(FIX)
  assert.equal(v.validation.status, "complete")
  assert.equal(v.validation.custodyValid, true)
})
test("header renders verdict word + dual custody lights", async () => {
  const h = renderHeader(await loadCase(FIX))
  assert.match(h, /SUSPICIOUS/)
  assert.match(h, /recorded/)
  assert.match(h, /re-verified now/)
})
test("findings render with technique + custody (cited + tool_call_id)", async () => {
  const f = renderFindings(await loadCase(FIX))
  assert.match(f, /T1070\.001/)
  assert.match(f, /cited/)
  assert.match(f, /tc-1/)
})
test("coverage + audit render; chain linkage OK on the fixture", async () => {
  const v = await loadCase(FIX)
  assert.match(renderCoverage(v), /evtx/)
  assert.match(renderAudit(v), /chain linkage OK/)
})
test("full screen composes all panels", async () => {
  const s = renderScreen(await loadCase(FIX))
  assert.ok(s.length > 200)
})

import { renderTimeline } from "../dist/src/render.js"
const BROKEN = join(here, "..", "..", "..", "fixtures", "synthetic", "broken-chain-run")
const NOREPORT = join(here, "..", "..", "..", "fixtures", "synthetic", "no-report-run")

test("timeline panel renders events from normalized_timeline", async () => {
  const v = await loadCase(FIX)
  // sample-run has no normalized_timeline -> honest degrade
  assert.match(renderTimeline(v), /TIMELINE/)
  assert.match(renderTimeline(v), /not produced by this run/)
})
test("broken audit chain is caught by the structural check", async () => {
  const v = await loadCase(BROKEN)
  assert.equal(v.chainOk, false)
  assert.match(renderAudit(v), /chain linkage BROKEN/)
})
test("missing verdict.json degrades honestly (not fabricated)", async () => {
  const v = await loadCase(NOREPORT)
  assert.equal(v.verdict, undefined)
  assert.match(renderFindings(v), /not produced by this run/)
  // custody still holds (sealed run)
  assert.equal(v.validation.custodyValid, true)
})

import { listRuns as listRunsP } from "../dist/src/picker.js"
import { renderPicker } from "../dist/src/render.js"
const SYNTH_ROOT = join(here, "..", "..", "..", "fixtures", "synthetic")

test("picker discovers the synthetic run dirs with statuses", async () => {
  const runs = await listRunsP([SYNTH_ROOT])
  assert.ok(runs.length >= 3, `expected >=3 runs, got ${runs.length}`)
  assert.ok(runs.some((r) => r.status === "complete"))
  const p = renderPicker(runs)
  assert.match(p, /CASES/)
  assert.match(p, /sample-run/)
})
