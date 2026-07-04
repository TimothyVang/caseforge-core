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
  const t = renderTimeline(await loadCase(FIX))
  assert.match(t, /TIMELINE/)
  assert.match(t, /T1070\.001/)
  assert.match(t, /events/)
})
test("timeline degrades honestly when absent", async () => {
  assert.match(renderTimeline(await loadCase(NOREPORT)), /not produced by this run/)
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

test("picker highlights the cursor row", async () => {
  const runs = await listRunsP([SYNTH_ROOT])
  const p = renderPicker(runs, 1)
  const lines = p.split("\n")
  // the 2nd run row (index 1) carries the cursor arrow; row 0 does not
  const rowLines = lines.filter((l) => /fixtures\/synthetic/.test(l))
  assert.match(rowLines[1], /▶/)
  assert.doesNotMatch(rowLines[0], /▶/)
})

test("picker flags a run whose audit chain is structurally broken", async () => {
  const runs = await listRunsP([SYNTH_ROOT])
  const broken = runs.find((r) => /broken-chain-run/.test(r.dir))
  assert.ok(broken, "broken-chain-run present")
  assert.equal(broken.chainOk, false)
  const good = runs.find((r) => /sample-run/.test(r.dir))
  assert.equal(good.chainOk, true)
  const p = renderPicker(runs, 0)
  assert.match(p, /⚠ chain/) // the broken run is flagged even though status=complete
})

import { renderCustodyBanner } from "../dist/src/render.js"
const CINVALID = join(here, "..", "..", "..", "fixtures", "synthetic", "custody-invalid-run")

test("custody-invalid case shows a NOT VERIFIED banner over findings", async () => {
  const v = await loadCase(CINVALID)
  assert.match(renderCustodyBanner(v), /CUSTODY NOT VERIFIED/)
  assert.match(renderScreen(v), /CUSTODY NOT VERIFIED/)
})
test("valid custody shows no warning banner", async () => {
  assert.equal(renderCustodyBanner(await loadCase(FIX)), "")
})
