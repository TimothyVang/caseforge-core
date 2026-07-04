export * from "./load.js"
export * from "./render.js"
export * from "./picker.js"
import { join } from "node:path"
import { loadCase } from "./load.js"
import { renderScreen, renderPicker } from "./render.js"
import { listRuns } from "./picker.js"

const DEFAULT_ROOTS = ["tmp/auto-runs", "tmp/fleet-runs", "docs/sample-run", "fixtures/synthetic"]

/** Launch the read-only workbench. With a run dir: view it. Without: list cases. */
export async function launchTui(runDir?: string): Promise<number> {
  if (!runDir) {
    const roots = [...DEFAULT_ROOTS]
    if (process.env.FINDEVIL_HOME) roots.push(join(process.env.FINDEVIL_HOME, "cases"))
    const entries = await listRuns(roots)
    process.stdout.write(renderPicker(entries) + "\n")
    if (entries.length === 0) process.stderr.write("\nno runs found — pass a run dir: caseforge tui <run-dir>\n")
    return 0
  }
  const view = await loadCase(runDir)
  process.stdout.write(renderScreen(view) + "\n")
  return 0
}
