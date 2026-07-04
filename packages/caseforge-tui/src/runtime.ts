import { loadCase } from "./load.js"
import { renderScreen, renderPicker, renderFooter } from "./render.js"
import { listRuns } from "./picker.js"
import type { RunEntry } from "./picker.js"
import { keyOf, reduce, initialState } from "./app.js"
import type { AppState } from "./app.js"

const CLEAR = "\x1b[2J\x1b[H"

async function draw(state: AppState, runs: RunEntry[]): Promise<void> {
  let body: string
  if (state.view === "picker") {
    body = `${renderPicker(runs, state.cursor)}\n\n${renderFooter("picker")}`
  } else {
    const entry = runs[state.cursor]
    const view = entry ? await loadCase(entry.dir) : undefined
    body = `${view ? renderScreen(view) : "no case selected"}\n\n${renderFooter("case")}`
  }
  process.stdout.write(CLEAR + body + "\n")
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
  stdin.resume()
  stdin.setEncoding("utf8")

  let state: AppState = initialState
  await draw(state, runs)

  return await new Promise<number>((resolve) => {
    const cleanup = (): void => {
      if (stdin.isTTY) stdin.setRawMode(false)
      stdin.pause()
      stdin.off("data", onData)
      process.stdout.write(CLEAR)
    }
    const onData = (seq: string): void => {
      state = reduce(state, keyOf(seq), runs.length)
      if (state.quit) {
        cleanup()
        resolve(0)
        return
      }
      void draw(state, runs)
    }
    stdin.on("data", onData)
  })
}
