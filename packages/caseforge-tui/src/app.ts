/** Pure interactivity core: raw key bytes -> intent, and (state, intent) -> state.
 * Kept free of any I/O so it is fully unit-testable; the TTY loop in runtime.ts
 * is the only untestable shell and stays as thin as possible. */

export type Key = "up" | "down" | "enter" | "back" | "quit" | "other"

export interface AppState {
  view: "picker" | "case"
  cursor: number
  quit: boolean
}

export const initialState: AppState = { view: "picker", cursor: 0, quit: false }

/** Map a raw stdin sequence to a navigation intent. */
export function keyOf(seq: string): Key {
  if (seq === "\x1b[A" || seq === "k") return "up"
  if (seq === "\x1b[B" || seq === "j") return "down"
  if (seq === "\r" || seq === "\n" || seq === " ") return "enter"
  if (seq === "q" || seq === "\x1b") return "back"
  if (seq === "\x03") return "quit" // ctrl-c
  return "other"
}

/** Advance the app state. Pure: no I/O, immutable (returns a new state). */
export function reduce(state: AppState, key: Key, runCount: number): AppState {
  if (state.quit) return state
  if (key === "quit") return { ...state, quit: true }
  const last = Math.max(0, runCount - 1)
  if (state.view === "picker") {
    if (key === "up") return { ...state, cursor: Math.max(0, state.cursor - 1) }
    if (key === "down") return { ...state, cursor: Math.min(last, state.cursor + 1) }
    if (key === "enter") return runCount > 0 ? { ...state, view: "case" } : state
    if (key === "back") return { ...state, quit: true }
    return state
  }
  // case view
  if (key === "back") return { ...state, view: "picker" }
  return state
}
