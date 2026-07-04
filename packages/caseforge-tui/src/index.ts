export * from "./load.js"
export * from "./render.js"
import { loadCase } from "./load.js"
import { renderScreen } from "./render.js"

/** Launch the read-only workbench for a run dir. Returns a process exit code. */
export async function launchTui(runDir?: string): Promise<number> {
  if (!runDir) {
    process.stderr.write("usage: caseforge tui <run-dir>\n")
    return 2
  }
  const view = await loadCase(runDir)
  process.stdout.write(renderScreen(view) + "\n")
  return 0
}
