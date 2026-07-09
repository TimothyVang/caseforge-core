import { loadCase } from "./load.js"
import { renderScreen, renderPicker, renderFooter, renderFindingDetail } from "./render.js"
import { listRuns } from "./picker.js"
import type { RunEntry } from "./picker.js"
import { keyOf, reduce, initialState } from "./app.js"
import type { AppState } from "./app.js"

const CLEAR = "\x1b[2J\x1b[H"

/** Draw the current state. Returns the finding count of the loaded case (0 for
 * the picker) so the loop can bound the finding cursor in reduce(). */
async function draw(state: AppState, runs: RunEntry[]): Promise<number> {
  if (state.view === "picker") {
    const body = `${renderPicker(runs, state.cursor)}\n\n${renderFooter("picker")}`
    process.stdout.write(CLEAR + body + "\n")
    return 0
  }
  const entry = runs[state.cursor]
  const view = entry ? await loadCase(entry.dir) : undefined
  const findingCount = view?.verdict?.findings?.length ?? 0
  let panel: string
  if (!view) panel = "no case selected"
  else if (state.view === "detail") panel = renderFindingDetail(view, state.finding)
  else panel = renderScreen(view, state.finding)
  const body = `${panel}\n\n${renderFooter(state.view)}`
  process.stdout.write(CLEAR + body + "\n")
  return findingCount
}

/** Interactive picker->viewer loop. Thin I/O shell over the pure app.ts core;
 * all navigation logic lives in reduce()/keyOf() and is unit-tested. */
export async function runInteractive(roots: string[]): Promise<number> {
  const runs = await listRuns(roots)
  if (runs.length === 0) {
    process.stdout.write(`${renderPicker(runs)}\nno runs found — pass a run dir: caseforge tui <run-dir>\n`)
    return 0
  }
  const stdin = process.stdin
  if (stdin.isTTY) stdin.setRawMode(true)
  process.stdout.write("\x1b[?25l") // hide cursor
  stdin.resume()
  stdin.setEncoding("utf8")

  let state: AppState = initialState
  // Bound for the finding cursor; refreshed from the last drawn case so reduce()
  // clamps up/down within the selected case's findings.
  let findingCount = await draw(state, runs)

  return await new Promise<number>((resolve) => {
    const cleanup = (): void => {
      if (stdin.isTTY) stdin.setRawMode(false)
      stdin.pause()
      stdin.off("data", onData)
      process.stdout.write("\x1b[?25h" + CLEAR) // restore cursor
    }
    const onData = (seq: string): void => {
      state = reduce(state, keyOf(seq), runs.length, findingCount)
      if (state.quit) {
        cleanup()
        resolve(0)
        return
      }
      void draw(state, runs).then((n) => {
        findingCount = n
      })
    }
    stdin.on("data", onData)
  })
}
