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
